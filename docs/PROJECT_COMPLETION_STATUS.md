# NTTH Project Completion Status

Last updated: 2026-05-16

## Current State

NTTH is a functional gateway-mode security lab appliance. Devices connect to the `NTTH-Secure` hotspot, traffic is routed through the Ubuntu gateway, packets are captured, enriched, scored, and shown in the dashboard.

## Completed Since Last Baseline

- Removed wireless monitor mode from backend and dashboard.
- Removed fake simulation threat endpoint and added cleanup for stale demo data.
- Added richer packet metadata: MAC, direction, IP header fields, TCP/UDP/ICMP details, payload preview, HTTP request details, TLS SNI/ALPN hints, QUIC hint, and flow IDs.
- Added Packet Inspector service filters, payload/domain search, flow conversation endpoint, CSV/JSON/PCAP export, and hex plus ASCII payload display.
- Added plain HTTP form-field extraction for URL-encoded forms.
- Improved false-positive handling for common client ports and normal mobile/web app traffic.
- Raised automatic enforcement thresholds so medium risk logs/explains instead of immediately blocking or redirecting.
- Added risk detail data: winning rule, rule scores, ML score, action, and decision reason.
- Added topology risk detail view and separated blocked, throttled, and redirected states.
- Added manual firewall rule creation from the dashboard.
- Added honeypot session CSV export endpoint.
- Added packet retention cleanup and event-bus low-priority drop protection for heavy traffic bursts.
- Added focused backend tests for HTTP parsing, TLS SNI parsing, and rule detail scoring.

## Goal Coverage

- Gateway hotspot and routing: high
- Packet capture and inspection: high for metadata, medium for payload content
- HTTP inspection: good for plain HTTP, intentionally limited for HTTPS
- TLS metadata: partial, SNI/ALPN where visible
- IDS and scoring: improved, still not enterprise-grade
- Firewall containment: functional with safer thresholds
- Honeypot diversion: functional, session reporting improved
- Dashboard: stronger, still needs final UX polish
- Performance: improved with retention/backpressure, still needs long-run soak testing
- Production hardening: partial

## Remaining Work

- Add full PCAP storage if exact byte-for-byte export is required. Current PCAP export reconstructs packets from stored metadata and preview payload.
- Add deeper TLS parsing and certificate metadata where visible.
- Add full HTTP response parsing and request/response pairing.
- Add broader automated API and UI tests.
- Add HTTPS for the dashboard and a formal secret rotation procedure.
- Add database backup/restore commands.
- Run long-duration testing under real device traffic.

## Practical Completion Estimate

The project is now roughly 80-85% complete for a final-year/lab/demo security gateway.

It is still not a production security appliance. The remaining 15-20% is mostly hardening, long-run validation, broader tests, and deeper protocol analysis.
