# ────────────────────────────────────────────────────────────────
# NTTH — No Time To Hack
# Docker image for autonomous network defense with AR9271 support
# ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="NTTH Team"
LABEL description="Autonomous AI-Driven Honeypot Firewall with AR9271 Wireless Monitor"

# System dependencies for:
#   - scapy (packet capture)
#   - aircrack-ng (monitor mode)
#   - nftables (firewall)
#   - iw/wireless-tools (wireless config)
#   - usbutils (lsusb for adapter detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    iw \
    wireless-tools \
    nftables \
    iproute2 \
    net-tools \
    usbutils \
    tcpdump \
    libpcap-dev \
    gcc \
    python3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ /app/

# Copy Flutter web build (pre-built on host)
COPY flutter_app/build/web/ /app/flutter_app/build/web/

# Copy experiments framework
COPY experiments/ /app/experiments/

# Copy docs
COPY docs/ /app/docs/

# Copy startup script
COPY scripts/start_ntth.sh /app/start_ntth.sh
RUN chmod +x /app/start_ntth.sh

# Create data directories
RUN mkdir -p /app/logs /app/geoip /cowrie_logs

# Environment defaults (overridable via docker-compose or -e)
ENV ENVIRONMENT=production \
    DEBUG=false \
    DATABASE_URL=sqlite+aiosqlite:///./ntth.db \
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=NtthAdmin2026 \
    WIFI_ENABLED=true \
    WIFI_INTERFACE= \
    DEAUTH_THRESHOLD=10 \
    ROGUE_AP_DETECTION=true \
    PROBE_TRACKING=true \
    LOG_LEVEL=INFO

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -sf http://localhost:8000/api/v1/system/health || exit 1

# Entry point: auto-configure monitor mode → start backend
CMD ["/app/start_ntth.sh"]
