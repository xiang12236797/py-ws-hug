# Hugging Face Spaces — Python-WS
# Multi-arch build; HF Spaces 默认暴露 7860 端口

FROM python:3.11-slim

# 非 root 用户（HuggingFace 要求）
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR /app

# 安装依赖
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# 复制源文件
COPY --chown=user app.py      .
COPY --chown=user index.html  .

# Hugging Face Spaces 固定暴露 7860
EXPOSE 7860
ENV PORT=7860

CMD ["python", "app.py"]
