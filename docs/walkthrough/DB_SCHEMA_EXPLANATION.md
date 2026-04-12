# DB Schema Explanation

This file explains the main database tables in plain language.

Main model file:

- `backend/app/database/models.py`

## 1. Schema Table Overview

| Table | Purpose | Important Keys | Used By |
|---|---|---|---|
| `users` | application accounts | `id`, `username` | auth and admin management |
| `devices` | discovered or protected assets | `id`, `ip_address` | devices page, topology, threat linking |
| `device_stats` | per-device traffic snapshots | `device_id`, `recorded_at` | device history |
| `threat_events` | persisted incidents | `id`, `src_ip`, `threat_type` | threat map, dashboard, reporting |
| `honeypot_sessions` | deception sessions | `session_id`, `attacker_ip`, `victim_ip` | honeypot page |
| `firewall_rules` | active and historic response rules | `rule_type`, `target_ip`, `match_dst_ip` | firewall page |
| `system_logs` | backend log entries | `component`, `level`, `logged_at` | system operations |

## 2. Users

Purpose:

- login and role control

Important columns:

- `username`
- `hashed_password`
- `role`
- `is_active`
- `last_login`

## 3. Devices

Purpose:

- represent machines found on the monitored network

Important columns:

- `ip_address`
- `mac_address`
- `hostname`
- `vendor`
- `is_trusted`
- `risk_score`
- `first_seen`
- `last_seen`

Relationships:

- one device can have many `device_stats`
- one device can have many `threat_events`

## 4. Device Stats

Purpose:

- store traffic snapshots for a device over time

Important columns:

- `packet_count`
- `byte_count`
- `unique_ports`
- `syn_count`
- `protocol`
- `recorded_at`

## 5. Threat Events

Purpose:

- represent suspicious activity that was scored and recorded

Important columns:

- `src_ip`
- `dst_ip`
- `dst_port`
- `protocol`
- `threat_type`
- `risk_score`
- `rule_score`
- `ml_score`
- `action_taken`
- `country`, `city`, `asn`, `org`
- `notes`

Special note:

`notes` is used to store incident context such as:

- victim IP
- response mode
- location summary
- network origin
- target hidden flag

## 6. Honeypot Sessions

Purpose:

- represent SSH or HTTP deception sessions

Important columns:

- `session_id`
- `attacker_ip`
- `observed_attacker_ip`
- `attacker_port`
- `victim_ip`
- `victim_port`
- `honeypot_type`
- `username_tried`
- `password_tried`
- `commands_run`
- `duration_seconds`
- `source_masked`
- `source_mask_reason`
- `started_at`
- `ended_at`

Why these fields matter:

- `attacker_ip` is the resolved or correlated attacker when possible
- `observed_attacker_ip` is what the honeypot actually saw
- `victim_ip` and `victim_port` preserve the attacked target context

## 7. Firewall Rules

Purpose:

- store containment actions and make them visible in the UI

Important columns:

- `rule_type`
- `target_ip`
- `target_port`
- `match_dst_ip`
- `match_dst_port`
- `protocol`
- `nft_handle`
- `is_active`
- `created_by`
- `expires_at`
- `reason`

Why `match_dst_ip` and `match_dst_port` matter:

- they make redirects victim-aware
- one attacker can target multiple victims
- the system can remember which exact flow was redirected

## 8. System Logs

Purpose:

- store backend operational logs in a queryable table

Important columns:

- `level`
- `component`
- `message`
- `extra`
- `logged_at`
