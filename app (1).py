#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Python-ws for Hugging Face Spaces
# Supports: VLESS + Trojan + Shadowsocks over WebSocket
# Author: eooce (Python port)

import os
import sys
import socket
import struct
import hashlib
import hmac
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
import platform
from aiohttp import web

# ============================================================
# 环境变量配置
# ============================================================
UUID         = os.environ.get('UUID', '5efabea4-f6d4-91fd-b8f0-17e004c89c60')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')   # v1: nz.abc.com:8008  v0: nz.abc.com
NEZHA_PORT   = os.environ.get('NEZHA_PORT', '')     # v0 agent 端口，v1 留空
NEZHA_KEY    = os.environ.get('NEZHA_KEY', '')      # v0/v1 密钥
DOMAIN       = os.environ.get('DOMAIN', '')         # 分配/反代域名，不含 https:// 前缀
SUB_PATH     = os.environ.get('SUB_PATH', 'sub')   # 订阅 token
NAME         = os.environ.get('NAME', '')           # 节点名称前缀，例如: HuggingFace
WSPATH       = os.environ.get('WSPATH', UUID[:8])   # WebSocket 路径
AUTO_ACCESS  = os.environ.get('AUTO_ACCESS', '').lower() == 'true'
DEBUG        = os.environ.get('DEBUG', '').lower() == 'true'

# Hugging Face Spaces 默认端口为 7860
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 7860)

# ============================================================
# 全局状态
# ============================================================
CurrentDomain = DOMAIN
CurrentPort   = 443
Tls           = 'tls'
ISP           = ''

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']

BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com',
    'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io',
    'librespeed.org', 'speedcheck.org',
]

# ============================================================
# 日志
# ============================================================
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
for _noisy in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client',
               'aiohttp.internal', 'aiohttp.websocket'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


# ============================================================
# 工具函数
# ============================================================
def is_port_available(port: int, host: str = '0.0.0.0') -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start: int, attempts: int = 100) -> int | None:
    for p in range(start, start + attempts):
        if is_port_available(p):
            return p
    return None


def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)


async def get_isp():
    global ISP
    for url in ('https://api.ip.sb/geoip', 'http://ip-api.com/json'):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=aiohttp.ClientTimeout(total=4)) as r:
                    if r.status == 200:
                        d = await r.json()
                        cc  = d.get('country_code') or d.get('countryCode', '')
                        org = d.get('isp') or d.get('org', '')
                        ISP = f"{cc}-{org}".replace(' ', '_')
                        return
        except Exception:
            pass
    ISP = 'Unknown'


async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get('https://api-ipv4.ip.sb/ip', timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        CurrentDomain = (await r.text()).strip()
                        Tls, CurrentPort = 'none', PORT
                        return
        except Exception as e:
            logger.error(f'Failed to get public IP: {e}')
        CurrentDomain = 'change-your-domain.com'
        Tls, CurrentPort = 'tls', 443
    else:
        CurrentDomain = DOMAIN
        Tls, CurrentPort = 'tls', 443


async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    for dns in DNS_SERVERS:
        try:
            url = f'https://dns.google/resolve?name={host}&type=A'
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        d = await r.json()
                        if d.get('Status') == 0:
                            for ans in d.get('Answer', []):
                                if ans.get('type') == 1:
                                    return ans['data']
        except Exception:
            continue
    return host


# ============================================================
# 双向转发（公共）
# ============================================================
async def relay(websocket, reader, writer, initial_data: bytes = b''):
    if initial_data:
        writer.write(initial_data)
        await writer.drain()

    async def ws_to_tcp():
        try:
            async for msg in websocket:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send_bytes(data)
        except Exception:
            pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())


# ============================================================
# 协议处理器
# ============================================================
class ProxyHandler:
    def __init__(self, uuid_str: str):
        self.uuid_str   = uuid_str                      # 无短横线
        self.uuid_bytes = bytes.fromhex(uuid_str)       # 16 bytes
        # Trojan 支持两种 UUID 格式的哈希
        std_uuid = (
            f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}"
            f"-{uuid_str[16:20]}-{uuid_str[20:]}"
        ) if '-' not in UUID else UUID
        self._trojan_hashes = {
            hashlib.sha224(uuid_str.encode()).hexdigest(),
            hashlib.sha224(std_uuid.encode()).hexdigest(),
            hashlib.sha224(UUID.encode()).hexdigest(),
        }

    # ----------------------------------------------------------
    # VLESS
    # ----------------------------------------------------------
    async def handle_vless(self, ws, data: bytes) -> bool:
        """
        VLESS over WebSocket (无加密版本):
        [1]ver [16]uuid [1]addon_len [addon] [1]cmd [2]port [1]atyp [addr] [payload]
        """
        try:
            if len(data) < 18 or data[0] != 0:
                return False
            if data[1:17] != self.uuid_bytes:
                return False

            i = 18 + data[17]          # 跳过 addon
            if i + 3 > len(data):
                return False

            cmd = data[i]; i += 1
            if cmd not in (1, 3):      # TCP / UDP（仅处理 TCP）
                return False

            port = struct.unpack('!H', data[i:i+2])[0]; i += 2
            atyp = data[i]; i += 1
            host, i = _parse_addr(data, i, atyp)
            if host is None:
                return False

            if is_blocked_domain(host):
                await ws.close(); return False

            # 回应客户端（version=0, addon_len=0）
            await ws.send_bytes(b'\x00\x00')

            resolved = await resolve_host(host)
            reader, writer = await asyncio.open_connection(resolved, port)
            await relay(ws, reader, writer, data[i:])
            return True

        except Exception as e:
            if DEBUG:
                logger.error(f'VLESS error: {e}')
            return False

    # ----------------------------------------------------------
    # Trojan
    # ----------------------------------------------------------
    async def handle_trojan(self, ws, data: bytes) -> bool:
        """
        Trojan over WebSocket:
        [56]sha224hex [CRLF] [1]cmd [1]atyp [addr] [2]port [CRLF] [payload]
        """
        try:
            if len(data) < 58:
                return False
            rcv_hash = data[:56].decode('ascii', errors='replace')
            if rcv_hash not in self._trojan_hashes:
                return False

            off = 56
            if data[off:off+2] == b'\r\n':
                off += 2
            if off >= len(data):
                return False

            cmd = data[off]; off += 1
            if cmd != 1:
                return False

            atyp = data[off]; off += 1
            host, off = _parse_addr(data, off, atyp)
            if host is None:
                return False

            port = struct.unpack('!H', data[off:off+2])[0]; off += 2
            if data[off:off+2] == b'\r\n':
                off += 2

            if is_blocked_domain(host):
                await ws.close(); return False

            resolved = await resolve_host(host)
            reader, writer = await asyncio.open_connection(resolved, port)
            await relay(ws, reader, writer, data[off:])
            return True

        except Exception as e:
            if DEBUG:
                logger.error(f'Trojan error: {e}')
            return False

    # ----------------------------------------------------------
    # Shadowsocks (none 加密，通过 v2ray-plugin WS 传输)
    # ----------------------------------------------------------
    async def handle_shadowsocks(self, ws, data: bytes) -> bool:
        """
        Shadowsocks SOCKS5 地址头 (atyp + addr + port + payload)
        加密方式：none（依赖外层 TLS 保护）
        """
        try:
            if len(data) < 7:
                return False

            off  = 0
            atyp = data[off]; off += 1
            host, off = _parse_addr(data, off, atyp)
            if host is None:
                return False

            if off + 2 > len(data):
                return False
            port = struct.unpack('!H', data[off:off+2])[0]; off += 2

            if is_blocked_domain(host):
                await ws.close(); return False

            resolved = await resolve_host(host)
            reader, writer = await asyncio.open_connection(resolved, port)
            await relay(ws, reader, writer, data[off:])
            return True

        except Exception as e:
            if DEBUG:
                logger.error(f'Shadowsocks error: {e}')
            return False


# ----------------------------------------------------------
# 地址解析公共函数
# ----------------------------------------------------------
def _parse_addr(data: bytes, i: int, atyp: int):
    """返回 (host_str, new_offset)，失败返回 (None, i)"""
    if atyp == 1:        # IPv4
        if i + 4 > len(data):
            return None, i
        host = '.'.join(str(b) for b in data[i:i+4])
        return host, i + 4
    elif atyp == 3:      # 域名 (SS/Trojan) 或 atyp==2 (VLESS)
        if i >= len(data):
            return None, i
        hl = data[i]; i += 1
        if i + hl > len(data):
            return None, i
        return data[i:i+hl].decode(), i + hl
    elif atyp == 2:      # VLESS 域名
        if i >= len(data):
            return None, i
        hl = data[i]; i += 1
        if i + hl > len(data):
            return None, i
        return data[i:i+hl].decode(), i + hl
    elif atyp == 4:      # IPv6
        if i + 16 > len(data):
            return None, i
        parts = [f'{(data[j] << 8) + data[j+1]:04x}' for j in range(i, i+16, 2)]
        return ':'.join(parts), i + 16
    return None, i


# ============================================================
# HTTP / WebSocket 路由
# ============================================================
async def websocket_handler(request: web.Request):
    ws = web.WebSocketResponse(max_msg_size=0)
    await ws.prepare(request)

    cuuid = UUID.replace('-', '')
    if f'/{WSPATH}' not in request.path:
        await ws.close()
        return ws

    proxy = ProxyHandler(cuuid)
    try:
        first = await asyncio.wait_for(ws.receive(), timeout=10)
        if first.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        msg = first.data

        # 按顺序尝试各协议
        # 1. VLESS  (首字节 == 0)
        if len(msg) > 17 and msg[0] == 0:
            if await proxy.handle_vless(ws, msg):
                return ws

        # 2. Trojan (前56字节为 sha224hex)
        if len(msg) >= 58:
            if await proxy.handle_trojan(ws, msg):
                return ws

        # 3. Shadowsocks (首字节为有效 atyp: 1/3/4)
        if len(msg) > 0 and msg[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg):
                return ws

        await ws.close()

    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f'WS handler error: {e}')
        await ws.close()

    return ws


async def http_handler(request: web.Request):
    path = request.path

    # 首页
    if path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                return web.Response(text=f.read(), content_type='text/html')
        except FileNotFoundError:
            return web.Response(text='<h2>Hello World!</h2>', content_type='text/html')

    # 订阅页
    if path == f'/{SUB_PATH}':
        await asyncio.gather(get_isp(), get_ip())

        name_part  = f"{NAME}-{ISP}" if NAME else ISP
        tls_sec    = 'tls' if Tls == 'tls' else 'none'
        ss_tls_seg = 'tls;' if Tls == 'tls' else ''

        vless_url = (
            f"vless://{UUID}@{CurrentDomain}:{CurrentPort}"
            f"?encryption=none&security={tls_sec}&sni={CurrentDomain}"
            f"&fp=chrome&type=ws&host={CurrentDomain}"
            f"&path=%2F{WSPATH}#{name_part}"
        )
        trojan_url = (
            f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}"
            f"?security={tls_sec}&sni={CurrentDomain}"
            f"&fp=chrome&type=ws&host={CurrentDomain}"
            f"&path=%2F{WSPATH}#{name_part}"
        )
        ss_pw  = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss_url = (
            f"ss://{ss_pw}@{CurrentDomain}:{CurrentPort}"
            f"?plugin=v2ray-plugin;mode%3Dwebsocket"
            f";host%3D{CurrentDomain};path%3D%2F{WSPATH}"
            f";{ss_tls_seg}sni%3D{CurrentDomain}"
            f";skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        )

        sub      = f"{vless_url}\n{trojan_url}\n{ss_url}"
        b64_sub  = base64.b64encode(sub.encode()).decode()
        return web.Response(text=b64_sub + '\n', content_type='text/plain')

    return web.Response(status=404, text='Not Found\n')


# ============================================================
# 哪吒探针
# ============================================================
def _nezha_binary_url() -> str:
    arch = platform.machine().lower()
    arm  = 'arm' in arch or 'aarch64' in arch
    if not NEZHA_PORT:   # v1
        return 'https://arm64.eooce.com/v1' if arm else 'https://amd64.eooce.com/v1'
    else:                # v0
        return 'https://arm64.eooce.com/agent' if arm else 'https://amd64.eooce.com/agent'


async def _download_nezha():
    if not NEZHA_SERVER or not NEZHA_KEY:
        return
    url = _nezha_binary_url()
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status == 200:
                    content = await r.read()
                    with open('npm', 'wb') as f:
                        f.write(content)
                    os.chmod('npm', 0o755)
                    logger.info('✅ Nezha agent downloaded')
    except Exception as e:
        logger.error(f'Nezha download failed: {e}')


async def run_nezha():
    if not NEZHA_SERVER or not NEZHA_KEY:
        return

    # 防止重复启动
    try:
        out = subprocess.check_output(['ps', 'aux'], text=True)
        if './npm' in out:
            logger.info('Nezha agent already running, skip.')
            return
    except Exception:
        pass

    await _download_nezha()

    tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
    cmd = ''

    if NEZHA_SERVER and NEZHA_PORT and NEZHA_KEY:
        # 哪吒 v0
        flag = '--tls' if NEZHA_PORT in tls_ports else ''
        cmd = (f'nohup ./npm -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} '
               f'{flag} --disable-auto-update --report-delay 4 '
               f'--skip-conn --skip-procs >/dev/null 2>&1 &')

    elif NEZHA_SERVER and NEZHA_KEY and not NEZHA_PORT:
        # 哪吒 v1
        port_str = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
        nz_tls   = 'true' if port_str in tls_ports else 'false'
        cfg = f"""client_secret: {NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: {NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {nz_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""
        with open('config.yaml', 'w') as f:
            f.write(cfg)
        cmd = 'nohup ./npm -c config.yaml >/dev/null 2>&1 &'

    if cmd:
        try:
            subprocess.Popen(cmd, shell=True, executable='/bin/bash')
            logger.info('✅ Nezha agent started')
        except Exception as e:
            logger.error(f'Nezha start failed: {e}')


# ============================================================
# 自动保活
# ============================================================
async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(
                "https://oooo.serv00.net/add-url",
                json={"url": full_url},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10),
            )
        logger.info('✅ Auto-access task registered')
    except Exception:
        pass


# ============================================================
# 清理临时文件
# ============================================================
def cleanup_files():
    for f in ('npm', 'config.yaml'):
        try:
            if os.path.exists(f):
                os.remove(f)
        except Exception:
            pass


# ============================================================
# 主入口
# ============================================================
async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f'Port {actual_port} in use, searching for free port...')
        actual_port = find_available_port(actual_port + 1)
        if actual_port is None:
            logger.error('No available ports found!')
            sys.exit(1)
        logger.info(f'Using port {actual_port}')

    app = web.Application()
    app.router.add_get('/',              http_handler)
    app.router.add_get(f'/{SUB_PATH}',  http_handler)
    # WebSocket 路由（支持带子路径）
    app.router.add_get(f'/{WSPATH}',           websocket_handler)
    app.router.add_get(f'/{WSPATH}/{{tail:.*}}', websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()

    logger.info(f'✅ python-ws-hug running on port {actual_port}')
    logger.info(f'   Sub URL : https://{DOMAIN or "your-domain"}:{actual_port}/{SUB_PATH}')
    logger.info(f'   WS Path : /{WSPATH}')

    # 后台任务
    asyncio.create_task(run_nezha())
    asyncio.create_task(add_access_task())

    async def delayed_cleanup():
        await asyncio.sleep(180)
        cleanup_files()
    asyncio.create_task(delayed_cleanup())

    try:
        await asyncio.Future()          # 永久运行
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nServer stopped.')
        cleanup_files()
