FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy_server.py /app/

ENV PROXY_HOST=0.0.0.0
ENV PROXY_PORT=8000
ENV WEB_PORT=8081
ENV CERT_DIR=/app/certs

EXPOSE 8000 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/healthz || exit 1

ENTRYPOINT ["python3", "proxy_server.py"]
