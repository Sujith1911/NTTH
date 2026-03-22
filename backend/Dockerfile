FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    nftables \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and the prebuilt Flutter web app
COPY backend/app/ ./app/
COPY flutter_app/build/web/ ./flutter_app/build/web/

# Create required directories
RUN mkdir -p /app/geoip /app/logs /app/models

# Non-root user for reduced privilege (except network ops)
RUN useradd -m ntth && chown -R ntth:ntth /app
# Note: CAP_NET_ADMIN and CAP_NET_RAW are granted via docker-compose

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
