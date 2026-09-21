<div align="center">
# LOGVAULT
**Universal Log Intelligence & Autonomous SOC Analytics — 100% Client-Side**
 
Smart India Hackathon 2026 — SIH26156
 
[![100% Client-Side](https://img.shields.io/badge/Architecture-100%25%20Client--Side-2ea44f)](#)
[![Zero Cloud Dependency](https://img.shields.io/badge/Cloud%20Dependency-Zero-blueviolet)](#)
[![Schema](https://img.shields.io/badge/Schema-ECS%20%2F%20OCSF-informational)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
 
[Overview](#overview) • [Features](#key-features) • [Architecture](#architecture) • [Quick Start](#quick-start) • [Screenshots](#screenshots) • [Structure](#project-structure)
 
**Current Status: ~30% prototype complete**
 
</div>
---
 
## Problem
 
SOCs ingest logs from firewalls, servers, cloud platforms, and custom IoT/SCADA devices — each in a different format. Analysts waste hours reconciling this by hand, and most tools only add cost by requiring a cloud-hosted SIEM backend.
 
## Overview
 
LOGVAULT is a browser-native platform that detects, parses, and normalizes logs from multiple formats into one unified schema (OCSF/ECS), then runs real-time anomaly detection — entirely client-side. No backend, no cloud, no data leaves the browser. Works in air-gapped environments.
 
**Pipeline:**
```
Raw logs → Format detection → Parsing → OCSF/ECS normalization
→ Anomaly detection (rules + entropy + MITRE ATT&CK mapping) → SOC dashboard
```
 
## Supported Formats
 
| Format | Standard | Example Sources |
|---|---|---|
| Syslog | RFC 5424 / 3164 | Linux, SSH, iptables |
| Web Access | W3C / Common Log | Nginx, Apache |
| JSON | RFC 8259 | CloudTrail, Kubernetes, Suricata |
| CEF | ArcSight | Palo Alto, CheckPoint |
| Windows Security | EventLog KV | Event IDs 4624, 4625, 4672, 7045 |
| Unknown/Custom | Zero-shot mapper | IoT, SCADA, FinTech |
 
## Key Features
 
- **Multi-Format Normalizer** — real-time OCSF/ECS mapping with tokenizer, hex view, and entropy analyzer
- **Anomaly Detection** — flags SQLi, XSS, path traversal, brute force, port scans; entropy scoring catches obfuscated payloads; auto-tags MITRE ATT&CK tactics/techniques
- **AI Schema Inference** — zero-shot mapper handles unfamiliar log formats
- **Visualizations** — 60 FPS Canvas charts, network topology mesh
- **Command Palette** — `Cmd/Ctrl+K` for keyboard-driven navigation
- **Zero Cloud Dependency** — fully client-side, safe for sensitive/air-gapped use
## Architecture
 
Modular vanilla-JS SPA; each pipeline stage is its own module.
 
| Layer | Role |
|---|---|
| Ingestion | Accepts log files/streams |
| Format Detection | Regex/structural fingerprinting |
| Parsing | Per-format parsers + AI fallback |
| Normalization | Maps fields to OCSF/ECS |
| Anomaly Detection | Rules, entropy, baselining |
| Presentation | Dashboards, charts, topology, alerts |
 
## Quick Start
 
**Option 1:** Open [`index.html`](index.html) directly in a browser — no build step.
 
**Option 2:**
```bash
npm install
npm start
```
 
## Project Structure
 
```
├── js/
│   ├── app.js              # App controller
│   ├── mock-data.js        # In-memory telemetry engine
│   ├── normalizer.js       # Normalization UI
│   ├── parsers.js          # Format parsers
│   ├── anomaly.js          # Detection engine
│   ├── ai-mapper.js        # Zero-shot schema mapping
│   ├── charts.js           # Canvas chart engine
│   ├── topology.js         # Network flow visualizer
│   ├── log-stream.js       # Live stream controller
│   ├── analytics.js        # SOC KPIs
│   ├── sources.js          # Ingestion source mgmt
│   ├── settings.js         # Config & RBAC
│   ├── auth.js             # Authentication
│   ├── navigation.js       # Screen routing
│   └── utils.js            # Helpers
├── ui-ux-screenshots/
│   ├── light-mode/
│   └── dark-mode/
├── index.html
├── styles.css
└── package.json
```
 
## Screenshots
 
24 captures across 11 SOC screens + login, in [`ui-ux-screenshots/`](ui-ux-screenshots):
 
| # | Screen | Light | Dark |
|:-:|---|---|---|
| 00 | Auth Portal | [light](ui-ux-screenshots/light-mode/00_login_portal.png) | [dark](ui-ux-screenshots/dark-mode/00_login_portal.png) |
| 01 | Dashboard | [light](ui-ux-screenshots/light-mode/01_dashboard.png) | [dark](ui-ux-screenshots/dark-mode/01_dashboard.png) |
| 02 | Live Log Stream | [light](ui-ux-screenshots/light-mode/02_live_logs.png) | [dark](ui-ux-screenshots/dark-mode/02_live_logs.png) |
| 03 | Normalizer & Hex Dump | [light](ui-ux-screenshots/light-mode/03_log_normalizer.png) | [dark](ui-ux-screenshots/dark-mode/03_log_normalizer.png) |
| 04 | AI Schema Mapper | [light](ui-ux-screenshots/light-mode/04_unknown_logs_ai.png) | [dark](ui-ux-screenshots/dark-mode/04_unknown_logs_ai.png) |
| 05 | 3D Threat Graph | [light](ui-ux-screenshots/light-mode/05_anomalies_3d.png) | [dark](ui-ux-screenshots/dark-mode/05_anomalies_3d.png) |
| 06 | Alert Center | [light](ui-ux-screenshots/light-mode/06_alert_center.png) | [dark](ui-ux-screenshots/dark-mode/06_alert_center.png) |
| 07 | Event Analytics | [light](ui-ux-screenshots/light-mode/07_event_analytics.png) | [dark](ui-ux-screenshots/dark-mode/07_event_analytics.png) |
| 08 | Sources Health | [light](ui-ux-screenshots/light-mode/08_sources_topology.png) | [dark](ui-ux-screenshots/dark-mode/08_sources_topology.png) |
| 09 | Parser Registry | [light](ui-ux-screenshots/light-mode/09_parser_registry.png) | [dark](ui-ux-screenshots/dark-mode/09_parser_registry.png) |
| 10 | Network Topology | [light](ui-ux-screenshots/light-mode/10_network_topology.png) | [dark](ui-ux-screenshots/dark-mode/10_network_topology.png) |
| 11 | Platform Settings | [light](ui-ux-screenshots/light-mode/11_platform_settings.png) | [dark](ui-ux-screenshots/dark-mode/11_platform_settings.png) |
 
## Roadmap
 
- WASM-accelerated parsing for high-throughput ingestion
- Pluggable community rule packs
- Exportable OCSF/ECS bundles for downstream SIEM
- Offline PWA support
## Contributing
 
Open an issue to discuss significant changes before submitting a PR.
 
## License
 
MIT — see `LICENSE`.
 
---
 
<div align="center">
Built for Smart India Hackathon (SIH26156) — Enterprise-Grade Universal Log SIEM.
</div>
 
