<div align="center">
 LOGVAULT
 Universal Log Intelligence, Multi-Format Normalization & Autonomous SOC Analytics Platform
 
**Smart India Hackathon 2026 — Problem Statement ID: SIH26156**
 
[![100% Client-Side](https://img.shields.io/badge/Architecture-100%25%20Client--Side-2ea44f)](#)
[![Zero Cloud Dependency](https://img.shields.io/badge/Cloud%20Dependency-Zero-blueviolet)](#)
[![Schema](https://img.shields.io/badge/Schema-ECS%20%2F%20OCSF-informational)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#-license)
 
*In-Browser Log Normalization · Real-Time Anomaly Detection · MITRE ATT&CK Mapping*
 
[Overview](#-overview) • [Features](#️-key-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Screenshots](#-uiux-screenshots-gallery) • [Project Structure](#-project-structure)
 
</div>
---
 
##  Problem Statement
 
Modern Security Operations Centers ingest logs from a sprawl of heterogeneous sources — firewalls, web servers, cloud platforms, operating systems, and custom IoT/SCADA telemetry — each speaking a different, often proprietary format. Before any meaningful threat-hunting can begin, analysts burn hours reconciling this data by hand, and most existing tooling only makes it worse by locking that work behind expensive, cloud-hosted SIEM backends.
 
**LOGVAULT** closes that gap. It is a fully client-side, browser-native platform that automatically fingerprints, parses, and normalizes logs from multiple formats into a single unified schema (OCSF/ECS), then runs real-time anomaly detection and threat analytics — all without a single byte leaving the browser.
 
---
 
##  Overview
 
**LOGVAULT** is a high-performance cybersecurity command center and log-normalization engine built for **Smart India Hackathon (SIH26156)**. It runs entirely client-side, with no backend server and no cloud service in the loop — making it lightweight, portable, deployable in air-gapped environments, and inherently resistant to data exfiltration.
 
### How it works
 
```text
 3–5 Distinct Log Formats (Syslog, Nginx/Apache, JSON, CEF, Windows KV)
                         │
                         ▼
             Automatic Format Detection
           (Structural & Regex Fingerprinting)
                         │
                         ▼
                  Dedicated Parsing
        (or AI Heuristic Schema Mapping for Unknowns)
                         │
                         ▼
              Common Unified Schema (OCSF / ECS)
                         │
                         ▼
             Client-Side Anomaly Detection Engine
     (Threat Rules + Shannon Entropy ML + Statistical
              Baseline + MITRE ATT&CK Mapping)
                         │
                         ▼
           Interactive Real-Time SOC Command Center
```
 
---
 
##  Supported Log Formats
 
| Format | Specification / Standard | Sample Sources |
| :--- | :--- | :--- |
| **Syslog** | RFC 5424 / RFC 3164 (BSD) | Linux hosts, SSH daemons, iptables, kernels |
| **Web Access** | W3C Combined / Common Log Format | Nginx, Apache HTTP Server |
| **Structured JSON** | RFC 8259 JSON payloads | AWS CloudTrail, Kubernetes, Suricata EVE |
| **ArcSight CEF** | Common Event Format (severity 0–10) | CheckPoint, Palo Alto, firewalls |
| **Windows Security** | EventLog KV subsystem | Windows Event IDs 4624 / 4625 / 4672 / 7045 |
| **Unknown / Custom** | Zero-shot semantic mapper | IoT devices, SCADA, FinTech telemetry |
 
---
 
##  Key Features
 
### 1. Multi-Format Normalizer
A real-time pipeline that maps raw, heterogeneous logs onto the OCSF/ECS schema as they arrive. An interactive tokenizer, hex-stream view, and Shannon entropy analyzer make it easy to inspect exactly what each payload contains before and after normalization.
 
### 2. Autonomous Anomaly Detection
Flags SQL injection, XSS, path traversal, brute-force attempts, and ingress port scans out of the box. Shannon entropy scoring surfaces encoded or obfuscated attack vectors that pattern matching alone would miss, and every detected event is automatically tagged with its corresponding MITRE ATT&CK tactic and technique.
 
### 3. AI-Assisted Schema Inference
A zero-shot heuristic mapper infers a working schema for log formats the platform has never seen before, so unfamiliar or custom sources are normalized alongside everything else instead of being discarded.
 
### 4. High-DPI Visualizations & Topology
60 FPS HTML5 Canvas rendering powers velocity splines, sweep donut charts, and sparklines throughout the dashboard, alongside an interactive network topology mesh that visualizes live traffic between ingestion sources.
 
### 5. Omnibox Command Palette
A `Cmd+K` / `Ctrl+K` command palette gives operators keyboard-driven navigation across every screen in the platform, cutting down on mouse-heavy workflows during live incident response.
 
### 6. Zero Cloud Dependency
Everything runs client-side — no backend server, no external API calls, and no log data ever leaves the browser — making LOGVAULT a natural fit for air-gapped or otherwise sensitive deployments.
 
---
 
##  Architecture
 
LOGVAULT is built as a modular, vanilla-JS single-page application. Each pipeline stage — ingestion, format detection, parsing, normalization, anomaly detection, and visualization — is isolated into its own module for maintainability and easy extension with new log formats or detection rules.
 
| Layer | Responsibility |
| :--- | :--- |
| **Ingestion** | Accepts log streams/files and routes them into the detection pipeline |
| **Format Detection** | Structural & regex fingerprinting to classify incoming log format |
| **Parsing** | Dedicated parsers per format, or AI heuristic mapping for unknowns |
| **Normalization** | Maps parsed fields into a common OCSF/ECS schema |
| **Anomaly Detection** | Applies threat rules, entropy analysis, and statistical baselining |
| **Presentation** | Renders SOC dashboards, charts, topology, and alerting UI |
 
---
 
##  Quick Start
 
### Option 1 — Open Directly in Browser
Simply open [`index.html`](index.html) in any modern web browser. No build step, no install required.
 
### Option 2 — Run with a Local Static Server
```bash
npm install
npm start
```
 
Then navigate to the local server address printed in your terminal.
 
---
 
##  Project Structure
 
```text
├── js/
│   ├── app.js                  # Master application controller & lifecycle
│   ├── mock-data.js            # In-memory telemetry engine & LogVault API service
│   ├── normalizer.js           # Multi-format normalization pipeline UI
│   ├── parsers.js              # Dedicated log format parsers & test harness
│   ├── anomaly.js              # Anomaly detection & threat rules engine
│   ├── ai-mapper.js            # Zero-shot schema mapping for custom logs
│   ├── charts.js               # High-DPI canvas chart engine
│   ├── topology.js             # 60 FPS network flow topology visualizer
│   ├── log-stream.js           # Real-time telemetry stream controller
│   ├── analytics.js            # SOC analytics & KPI metric cards
│   ├── sources.js              # Ingestion sources & flow management
│   ├── settings.js             # Configuration & RBAC management
│   ├── auth.js                 # Authentication & security gateway
│   ├── navigation.js           # Screen router & history management
│   └── utils.js                # String, canvas & formatting helpers
├── ui-ux-screenshots/
│   ├── light-mode/             # 12 high-DPI light/cream theme captures
│   └── dark-mode/               # 12 high-DPI obsidian dark theme captures
├── index.html                  # SOC Command Center web UI
├── styles.css                  # Custom theme & CSS design system
└── package.json                # Project manifest
```
 
---
 
##  UI/UX Screenshots Gallery
 
All 24 high-resolution UI/UX captures covering all 11 SOC platform screens plus the Operator Authentication Portal are cataloged in [`ui-ux-screenshots/`](ui-ux-screenshots):
 
| # | Screen / Module | Light Mode (Warm Cream) | Dark Mode (Obsidian) |
| :-: | :--- | :--- | :--- |
| `00` | **Operator Authentication Portal** | [light](ui-ux-screenshots/light-mode/00_login_portal.png) | [dark](ui-ux-screenshots/dark-mode/00_login_portal.png) |
| `01` | **SOC Dashboard Home** | [light](ui-ux-screenshots/light-mode/01_dashboard.png) | [dark](ui-ux-screenshots/dark-mode/01_dashboard.png) |
| `02` | **Live Log Stream** | [light](ui-ux-screenshots/light-mode/02_live_logs.png) | [dark](ui-ux-screenshots/dark-mode/02_live_logs.png) |
| `03` | **Log Normalizer & Hex Dump** | [light](ui-ux-screenshots/light-mode/03_log_normalizer.png) | [dark](ui-ux-screenshots/dark-mode/03_log_normalizer.png) |
| `04` | **AI Schema Inference Mapper** | [light](ui-ux-screenshots/light-mode/04_unknown_logs_ai.png) | [dark](ui-ux-screenshots/dark-mode/04_unknown_logs_ai.png) |
| `05` | **3D Anomaly Threat Graph** | [light](ui-ux-screenshots/light-mode/05_anomalies_3d.png) | [dark](ui-ux-screenshots/dark-mode/05_anomalies_3d.png) |
| `06` | **Alert Center & Kanban Board** | [light](ui-ux-screenshots/light-mode/06_alert_center.png) | [dark](ui-ux-screenshots/dark-mode/06_alert_center.png) |
| `07` | **SOC Event Analytics** | [light](ui-ux-screenshots/light-mode/07_event_analytics.png) | [dark](ui-ux-screenshots/dark-mode/07_event_analytics.png) |
| `08` | **Sources Health & Collector Fleet** | [light](ui-ux-screenshots/light-mode/08_sources_topology.png) | [dark](ui-ux-screenshots/dark-mode/08_sources_topology.png) |
| `09` | **Parser Registry & WASM Chamber** | [light](ui-ux-screenshots/light-mode/09_parser_registry.png) | [dark](ui-ux-screenshots/dark-mode/09_parser_registry.png) |
| `10` | **Network Conduits Topology** | [light](ui-ux-screenshots/light-mode/10_network_topology.png) | [dark](ui-ux-screenshots/dark-mode/10_network_topology.png) |
| `11` | **Platform Settings & Storage** | [light](ui-ux-screenshots/light-mode/11_platform_settings.png) | [dark](ui-ux-screenshots/dark-mode/11_platform_settings.png) |
 
---
 
##  Roadmap
 
- [ ] WASM-accelerated parsing for very high-throughput log ingestion
- [ ] Pluggable rule packs for community-contributed detection signatures
- [ ] Exportable OCSF/ECS-normalized log bundles for downstream SIEM ingestion
- [ ] Offline PWA support for fully air-gapped deployments
---
 
##  Contributing
 
Contributions, issue reports, and feature requests are welcome. Please open an issue to discuss significant changes before submitting a pull request.
 
##  License
 
This project is licensed under the MIT License — see the `LICENSE` file for details.
 
---
 
<div align="center">
*Developed for Smart India Hackathon (SIH26156) — Enterprise-Grade Universal Log SIEM.*
 
</div>
