#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# NTTH Startup Script  — NO TIME TO HACK
# Usage: bash start.sh
# ──────────────────────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FLUTTER_DIR="$SCRIPT_DIR/flutter_app"
VENV="$BACKEND_DIR/venv"
BACKEND_PORT=8001
FLUTTER_PORT=44043

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║        NO TIME TO HACK — Startup             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Create venv if missing ─────────────────────────────────────────────────
if [ ! -f "$VENV/bin/activate" ]; then
  echo "📦 Creating virtual environment..."
  python3 -m venv "$VENV"
  echo "✅ Venv created"
fi

# ── 2. Install dependencies ───────────────────────────────────────────────────
echo "📦 Installing/checking Python dependencies..."
"$VENV/bin/pip" install -q -r "$BACKEND_DIR/requirements.txt" \
  && echo "✅ Dependencies OK" \
  || echo "⚠️  pip had warnings (continuing)"

# ── 3. Kill any process on BACKEND_PORT ───────────────────────────────────────
echo ""
echo "🔍 Checking port $BACKEND_PORT..."
if sudo fuser -k "${BACKEND_PORT}/tcp" 2>/dev/null; then
  echo "⚠️  Killed old process on :$BACKEND_PORT"
  sleep 1
else
  echo "✅ Port $BACKEND_PORT is free"
fi

# ── 4. Detect WiFi adapter ────────────────────────────────────────────────────
echo ""
echo "📡 Scanning for WiFi adapter..."
IFACES=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' || true)
if [ -z "$IFACES" ]; then
  echo "⚠️  No WiFi interfaces. Plug in AR9271 — auto-detected on start."
else
  echo "✅ WiFi interfaces: $IFACES"
fi

# ── 5. Start Flutter (background, as normal user) ─────────────────────────────
echo ""
if command -v flutter &>/dev/null; then
  # Kill existing flutter on that port
  fuser -k "${FLUTTER_PORT}/tcp" 2>/dev/null || true
  echo "🔨 Starting Flutter → http://localhost:$FLUTTER_PORT"
  (cd "$FLUTTER_DIR" && flutter run -d chrome \
    --web-port $FLUTTER_PORT \
    2>&1 | tee /tmp/ntth_flutter.log) &
  echo "✅ Flutter launched in background (log: /tmp/ntth_flutter.log)"
else
  echo "⚠️  flutter not in PATH — backend at :$BACKEND_PORT serves the built app."
fi

# ── 6. Start Backend ──────────────────────────────────────────────────────────
echo ""
echo "🚀 Starting backend on :$BACKEND_PORT (WiFi auto-detection active)..."
echo "   Dashboard → http://localhost:$BACKEND_PORT"
echo "   API Docs  → http://localhost:$BACKEND_PORT/docs"
echo ""

cd "$BACKEND_DIR"
exec sudo "$VENV/bin/uvicorn" app.main:app \
  --host 0.0.0.0 \
  --port $BACKEND_PORT \
  --reload \
  --log-level info
