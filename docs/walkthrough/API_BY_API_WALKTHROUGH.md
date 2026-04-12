# API By API Walkthrough

This file explains the backend APIs screen by screen and function by function.

Base prefix:

- `/api/v1`

Authentication is required for most routes unless noted.

## 1. Auth APIs

File:

- `backend/app/api/routes_auth.py`

### `POST /api/v1/auth/login`

Purpose:

- authenticate a user
- return access and refresh tokens

Input:

- `username`
- `password`

Output:

- `access_token`
- `refresh_token`

Used by:

- login screen
- initial app session setup

### `POST /api/v1/auth/refresh`

Purpose:

- issue a new token pair when access token expires

Input:

- `refresh_token`

Used by:

- `flutter_app/lib/core/api_client.dart`

### `GET /api/v1/auth/me`

Purpose:

- return the current authenticated user

Used by:

- session and role-aware UI behavior

### `POST /api/v1/auth/register`

Purpose:

- admin-only user creation

### `GET /api/v1/auth/users`

Purpose:

- admin-only user listing

### `DELETE /api/v1/auth/users/{username}`

Purpose:

- admin-only user deactivation

## 2. Device APIs

File:

- `backend/app/api/routes_devices.py`

### `GET /api/v1/devices`

Purpose:

- paginated device inventory

Output includes:

- IP
- MAC
- hostname
- vendor
- trust flag
- risk score

Used by:

- Devices screen
- topology-related UI

### `GET /api/v1/devices/{device_id}`

Purpose:

- return one device record

### `PUT /api/v1/devices/{device_id}/trust`

Purpose:

- admin-only toggle for trusted/untrusted device state

Used by:

- device trust UI

### `GET /api/v1/devices/{device_id}/stats`

Purpose:

- paginated traffic stat history for one device

## 3. Threat APIs

File:

- `backend/app/api/routes_threats.py`

### `GET /api/v1/threats`

Purpose:

- paginated threat history

Supports:

- `page`
- `page_size`
- `unacknowledged_only`

Output includes:

- source IP
- destination IP
- victim IP
- threat type
- risk score
- action taken
- network origin
- location summary
- response mode

Used by:

- Threat Map screen

### `GET /api/v1/threats/stats`

Purpose:

- aggregate counts by type and action

Used by:

- dashboard summary and future analytics

### `GET /api/v1/threats/{threat_id}`

Purpose:

- fetch one threat event

### `POST /api/v1/threats/{threat_id}/acknowledge`

Purpose:

- mark a threat as acknowledged

## 4. Firewall APIs

File:

- `backend/app/api/routes_firewall.py`

### `GET /api/v1/firewall/status`

Purpose:

- show current runtime enforcement mode

Important fields:

- `mode`
- `runtime_supported`
- `active_rules`
- `containment`
- `rule_types`

Used by:

- Firewall screen
- dashboard posture view

### `GET /api/v1/firewall/rules`

Purpose:

- return active rules only

Used by:

- Firewall screen

### `GET /api/v1/firewall/rules/history`

Purpose:

- paginated history of active and expired rules

### `POST /api/v1/firewall/rules`

Purpose:

- admin-only manual rule creation

### `DELETE /api/v1/firewall/rules/{rule_id}`

Purpose:

- admin-only deactivate one rule and remove it from nftables if possible

### `POST /api/v1/firewall/flush`

Purpose:

- admin-only emergency rule flush

## 5. Honeypot APIs

File:

- `backend/app/api/routes_honeypot.py`

### `GET /api/v1/honeypot/sessions`

Purpose:

- paginated honeypot session history

Output includes:

- attacker IP
- observed attacker IP
- victim IP
- victim port
- credentials
- commands
- masking note

Used by:

- Honeypot screen

### `GET /api/v1/honeypot/sessions/{session_id}`

Purpose:

- fetch one honeypot session

### `POST /api/v1/honeypot/start`

Purpose:

- admin-only Cowrie start

### `POST /api/v1/honeypot/stop`

Purpose:

- admin-only Cowrie stop

### `GET /api/v1/honeypot/status`

Purpose:

- current honeypot runtime status

## 6. System APIs

File:

- `backend/app/api/routes_system.py`

### `GET /api/v1/system/health`

Purpose:

- overall health, runtime mode, capture status, scheduler, WebSocket, firewall, honeypot, and agents

Used by:

- System screen
- dashboard

### `GET /api/v1/system/stats`

Purpose:

- dashboard aggregate counts

### `GET /api/v1/system/agents`

Purpose:

- list current security agents and their status

### `GET /api/v1/system/logs`

Purpose:

- admin-only system logs

### `POST /api/v1/system/emergency-flush`

Purpose:

- flush all dynamic firewall rules

### `POST /api/v1/system/simulate-threat`

Purpose:

- publish synthetic attack events into the event bus

Note:

- only works when simulation routes are enabled

## 7. Network Topology APIs

File:

- `backend/app/api/routes_topology.py`

### `GET /api/v1/network/topology`

Purpose:

- return nodes, edges, live stats, gateway info, and scan metadata

Used by:

- topology screen
- dashboard

### `POST /api/v1/network/scan`

Purpose:

- trigger a background network scan

Used by:

- Dashboard
- Devices screen

### `GET /api/v1/network/scan/status`

Purpose:

- see whether a scan is running and when it last completed

## 8. WebSocket API

Route:

- `/ws/live?token=...`

Purpose:

- live feed for threat, device, honeypot, and topology updates

Main event types include:

- `threat`
- `honeypot_session`
- `device_seen`
- `device_updated`
- `topology_updated`
- `incident_response`
