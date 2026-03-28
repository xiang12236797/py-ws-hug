# Python-WS (Hugging Face 版)

基于 Python asyncio / aiohttp 实现的 **VLESS + Trojan + Shadowsocks** 三协议代理，无需任何代理内核，专为 **Hugging Face Spaces** 部署优化。

---

> Telegram 交流群：<https://t.me/eooceu>  
> 对应 Node.js 版：[node-ws (hug 分支)](https://github.com/eooce/node-ws/tree/hug)

---

## 环境变量

| 变量名 | 是否必须 | 默认值 | 说明 |
|--------|---------|--------|------|
| `UUID` | 否 | `5efabea4-f6d4-91fd-b8f0-17e004c89c60` | 节点 UUID |
| `PORT` | 否 | `7860` | 监听端口，HuggingFace 固定 7860 |
| `DOMAIN` | **是** | — | 项目分配或反代后的域名，**不含** `https://` 前缀 |
| `SUB_PATH` | 否 | `sub` | 订阅 token，访问 `域名/sub` 获取节点 |
| `WSPATH` | 否 | UUID 前8位 | WebSocket 路径 |
| `NAME` | 否 | — | 节点名称前缀，如 `HuggingFace` |
| `NEZHA_SERVER` | 否 | — | 哪吒 v1：`nz.abc.com:8008`  v0：`nz.abc.com` |
| `NEZHA_PORT` | 否 | — | 哪吒 v0 agent 端口，v1 留空 |
| `NEZHA_KEY` | 否 | — | 哪吒密钥 |
| `AUTO_ACCESS` | 否 | `false` | 自动保活（需同时填写 `DOMAIN`） |
| `DEBUG` | 否 | `false` | 开启调试日志 |

---

## 部署到 Hugging Face Spaces

### 方法一：直接使用 Docker 镜像

1. 在 Hugging Face 新建一个 **Docker** 类型的 Space
2. 在 Space 的 `Settings → Secrets` 中添加上述环境变量
3. 在 `README.md`（Space 配置文件）写入：

```yaml
---
title: python-ws-hug
emoji: 🚀
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---
```

4. 将本仓库文件（`app.py`、`Dockerfile`、`requirements.txt`、`index.html`）上传到该 Space

### 方法二：通过 GitHub Actions 自动构建推送

1. Fork 本仓库
2. 在 GitHub 仓库 `Settings → Secrets` 中添加：
   - `DOCKER_USERNAME`：Docker Hub 用户名
   - `DOCKER_PASSWORD`：Docker Hub 密码或 Token
3. 修改 `.github/workflows/build-hug-image.yml` 中的镜像名称
4. Push 到 `main` 分支，Action 自动构建并推送镜像
5. 在 Hugging Face Space 中使用该镜像

---

## 订阅

部署成功后，访问以下地址获取节点订阅（Base64 编码）：

```
https://your-space-domain.hf.space/sub
```

订阅包含三个节点：

- `vless://...`
- `trojan://...`
- `ss://...`（v2ray-plugin / none 加密）

---

## 使用 Cloudflare Workers 反代加速（可选）

```js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    url.protocol = 'https:';
    url.hostname = 'your-space-domain.hf.space'; // 改为你的 HF 域名
    return fetch(new Request(url, request));
  },
};
```

---

## 技术栈

- Python 3.11+
- [aiohttp](https://docs.aiohttp.org/) — 异步 HTTP + WebSocket 服务器
- 无第三方代理内核，纯 Python 实现协议解析与 TCP 转发

---

版权所有 ©2025 `eooce`（Python 移植版）
