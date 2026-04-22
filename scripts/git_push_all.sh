#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────
# NTTH — Git Push (for existing init + remote already set)
# 
# Current state: git init done, remote set, NO commits, NO fetch
# GitHub repo: has 9 commits on 'main' branch
# Local branch: 'master' (default from git init)
#
# Strategy: 
#   1. Fetch existing GitHub history
#   2. Create local 'main' branch tracking remote
#   3. Add all local changes on top
#   4. Commit and push
# ────────────────────────────────────────────────────────────────
set -euo pipefail
cd /home/ubuntu/NTTH

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  NTTH — Git Push All Changes                          ║"
echo "╚═══════════════════════════════════════════════════════╝"

# ── Step 1: Fetch remote history ──
echo ""
echo "1/5 → Fetching existing GitHub history..."
git fetch origin
echo "   ✅ Fetched remote/origin"

# ── Step 2: Switch to 'main' branch (matching GitHub) ──
echo ""
echo "2/5 → Setting up 'main' branch..."
# Create main from remote's main (preserves all 9 existing commits)
git checkout -b main origin/main
echo "   ✅ On branch 'main' with full GitHub history"

# ── Step 3: Update .gitignore FIRST ──
echo ""
echo "3/5 → Updating .gitignore..."
cat > .gitignore << 'GITIGNORE'
# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
.eggs/
dist/
*.egg
venv/
.venv/

# Environment
.env
*.env.local

# Database
*.db
*.db-journal

# IDE
.vscode/
.idea/
*.swp
*.swo

# Runtime
.runtime/
logs/
*.pid
*.log
server_crash_log.txt

# OS
.DS_Store
Thumbs.db

# ML models
backend/models/*.joblib

# GeoIP databases (too large for git)
backend/geoip/*.mmdb

# Persistent data (generated at runtime)
backend/data/known_attackers.json

# Flutter build artifacts
flutter_app/.dart_tool/
flutter_app/build/
flutter_app/.packages
flutter_app/.flutter-plugins
flutter_app/.flutter-plugins-dependencies

# Docker
*.tar

# Node
node_modules/
GITIGNORE

# ── Step 4: Stage ALL changes ──
echo ""
echo "4/5 → Staging all files..."
git add -A

echo ""
echo "═══════════════ CHANGES SUMMARY ═══════════════"
git diff --cached --stat | tail -10
echo ""
echo "   Total files changed: $(git diff --cached --numstat | wc -l)"
echo "═══════════════════════════════════════════════"

# ── Step 5: Commit ──
echo ""
echo "5/5 → Committing..."
git config user.name "Sujith1911" 2>/dev/null || true
git config user.email "sujith@ntth.dev" 2>/dev/null || true

git commit -m "feat: AR9271 wireless module, Docker deploy, audit fixes

### New Modules
- wireless/: auto_monitor, wifi_sniffer, deauth_detector,
  rogue_ap_detector, probe_tracker, channel_hopper
- agents/feedback_agent: FP tracking + honeypot engagement
- honeypot/multi_honeypot: auto-deploy on any attacked port
- monitor/persistent_tracker: MAC-based cross-session tracking
- experiments/run_experiments: automated research framework

### Infrastructure
- Dockerfile + docker-compose.yml: prod deploy with USB passthrough
- scripts/start_ntth.sh: bare-metal auto-start
- .dockerignore: optimized build context

### Audit Fixes
- rule_engine: bounded deques + stale key pruning (memory fix)
- decision_agent: TTL-based dedup pruning (memory fix)
- routes_auth: login rate limiting (5 attempts/5min → 429)
- persistent_tracker: JSON file persistence (survives restarts)

### Documentation
- 20+ doc files: HTML guides, thesis, research paper
- PROGRESS_TRACKER.md: updated with audit status
- README.md: expanded with full architecture"

# ── Push ──
echo ""
echo "→ Pushing to origin/main..."
git push origin main

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ✅ All changes pushed to GitHub!                     ║"
echo "║  https://github.com/Sujith1911/NTTH                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
