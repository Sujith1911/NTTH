# Walkthrough Docs

This section explains how the project is built and how the main pieces work together.

## Files

- `SYSTEM_OVERVIEW.md`
- `DOCKER_SETUP.md`
- `FRONTEND_BACKEND_FLOW.md`
- `UBUNTU_SETUP.md`
- `GATEWAY_LAB_FLOW.md`
- `LOCAL_RUN_GUIDE.md`
- `PACKET_SNIFFING_AND_ATTACK_DETECTION.md`
- `AGENTIC_AI_AND_RESPONSE_FLOW.md`
- `FIREWALL_AND_HONEYPOT_DETAILS.md`
- `MIGRATIONS_AND_FILE_MOVE.md`
- `DEPLOYMENT_AND_IMPROVEMENT_ROADMAP.md`
- `API_BY_API_WALKTHROUGH.md`
- `FRONTEND_SCREEN_BY_SCREEN.md`
- `DB_SCHEMA_EXPLANATION.md`
- `EXACT_UBUNTU_KALI_VICTIM_COMMANDS.md`
- `HOW_TO_PITCH_THE_SYSTEM.md`

## Best Reading Order

1. `SYSTEM_OVERVIEW.md`
2. `FRONTEND_BACKEND_FLOW.md`
3. `DOCKER_SETUP.md`
4. `LOCAL_RUN_GUIDE.md`
5. `PACKET_SNIFFING_AND_ATTACK_DETECTION.md`
6. `AGENTIC_AI_AND_RESPONSE_FLOW.md`
7. `FIREWALL_AND_HONEYPOT_DETAILS.md`
8. `UBUNTU_SETUP.md`
9. `GATEWAY_LAB_FLOW.md`
10. `MIGRATIONS_AND_FILE_MOVE.md`
11. `DEPLOYMENT_AND_IMPROVEMENT_ROADMAP.md`
12. `API_BY_API_WALKTHROUGH.md`
13. `FRONTEND_SCREEN_BY_SCREEN.md`
14. `DB_SCHEMA_EXPLANATION.md`
15. `EXACT_UBUNTU_KALI_VICTIM_COMMANDS.md`
16. `HOW_TO_PITCH_THE_SYSTEM.md`

## Main Working Paths

- Backend entry: `backend/app/main.py`
- Backend config: `backend/app/config.py`
- Docker stack: `backend/docker-compose.yml`
- Packet sniffer: `backend/app/monitor/packet_sniffer.py`
- Threat agent: `backend/app/agents/threat_agent.py`
- Decision agent: `backend/app/agents/decision_agent.py`
- Enforcement agent: `backend/app/agents/enforcement_agent.py`
- Honeypot watcher: `backend/app/honeypot/cowrie_watcher.py`
- DB models: `backend/app/database/models.py`
- Frontend API client: `flutter_app/lib/core/api_client.dart`
- Frontend WebSocket: `flutter_app/lib/core/websocket_service.dart`
