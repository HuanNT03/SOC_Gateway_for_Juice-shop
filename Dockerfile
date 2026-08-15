# ----------------------------------------------------------------------------
# PROJECT SENTINEL - AI SECURITY AGENT & STREAMLIT WEB UI DOCKERFILE
# ----------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# Cài đặt các gói hệ thống cần thiết
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Chép requirements và cài đặt python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chép toàn bộ mã nguồn ứng dụng
COPY config/ /app/config/
COPY tools/ /app/tools/
COPY agent/ /app/agent/

# Tạo sẵn thư mục logs cho Audit Logger
RUN mkdir -p /app/logs

# Biến môi trường mặc định trong Docker (kết nối tới container 'gateway:8000')
ENV PYTHONUNBUFFERED=1
ENV GATEWAY_HOST="http://gateway:8000"

EXPOSE 8501

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "agent/ui.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
