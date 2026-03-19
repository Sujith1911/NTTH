# NO TIME TO HACK — Backend

## Setup

### Development (SQLite)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The server will:
- Auto-create `ntth.db` SQLite database
- Seed `admin / changeme` user on first run
- Start packet sniffer (Linux only — skipped on Windows)
- Swagger UI at `http://localhost:8000/docs`

### Environment Variables (`.env`)

```
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/ntth
SECRET_KEY=your-256-bit-secret
ADMIN_PASSWORD=changeme
NETWORK_INTERFACE=eth0
GATEWAY_IP=192.168.1.1
GEOIP_DB_PATH=./geoip/GeoLite2-City.mmdb
GEOIP_ASN_DB_PATH=./geoip/GeoLite2-ASN.mmdb
```

### Production (Docker)

```bash
docker compose up -d
```

## GeoIP Database

1. Register at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
3. Place in `backend/geoip/`

## Firewall Notes

- Requires `nftables` and `CAP_NET_ADMIN` capability
- Emergency flush: `POST /api/v1/system/emergency-flush` (admin only)
- Gateway IP is never blocked (configured via `GATEWAY_IP`)

## ML Model

- Isolation Forest trains automatically after 500 clean-baseline packets
- Model saved to `./models/isolation_forest.joblib`
- Retrained every 6 hours via scheduler
