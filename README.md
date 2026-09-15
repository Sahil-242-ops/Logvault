# LOGVAULT (SIH26156)
### Universal Log Intelligence, Multi-Format Normalization & Autonomous SOC Analytics Platform

> **100% Client-Side Web Application | Zero Cloud Dependency | In-Browser Normalization & Anomaly Detection | ECS/OCSF Common Schema**

---

## 🚀 Overview

**LOGVAULT** is a high-performance, modern cybersecurity Command Center and Log Normalization engine built for Smart India Hackathon (SIH26156). It runs entirely in the browser without requiring external backend servers or cloud services.

```text
3–5 Distinct Log Formats (Syslog, Nginx/Apache, JSON, CEF, Windows KV)
                        ↓
            Automatic Format Detection
          (Structural & Regex Fingerprinting)
                        ↓
                 Dedicated Parsing
          (or AI Heuristic Schema Mapping for Unknowns)
                        ↓
             Common Unified Schema (OCSF/ECS)
                        ↓
            Client-Side Anomaly Detection Engine
    (Threat Rules + Shannon Entropy ML + Statistical Baseline + MITRE ATT&CK)
                        ↓
          Interactive Real-Time SOC Command Center
```

---

## 📂 Supported Log Formats

| Format | Specification / Standard | Sample Sources |
| :--- | :--- | :--- |
| **Syslog** | RFC 5424 / RFC 3164 (BSD) | Linux hosts, SSH Daemons, iptables, Kernels |
| **Web Access** | W3C Combined / Common Log Format | Nginx, Apache HTTP Server |
| **Structured JSON** | RFC 8259 JSON Payloads | AWS CloudTrail, Kubernetes, Suricata EVE |
| **ArcSight CEF** | Common Event Format (0–10 Severity) | CheckPoint, Palo Alto, Firewalls |
| **Windows Security** | EventLog KV Subsystem | Windows EventID 4624/4625/4672/7045 |
| **Unknown / Custom** | Zero-Shot Semantic Mapper | IoT Devices, SCADA, FinTech Telemetry |

---

## ⚡ Quick Start

### 1. Open Directly in Browser
Simply open [`index.html`](file:///c:/Users/malik/Desktop/Sih/index.html) in any modern web browser.

### 2. Or Run with a Local Static Server
```bash
npm start
```

---

## 🛡️ Key Features

1. **Multi-Format Normalizer:**
   - Real-time normalization pipeline to OCSF/ECS standards.
   - Interactive Tokenizer, Hex stream view, and Shannon Entropy analyzer.

2. **Autonomous Anomaly Detection:**
   - Detects SQLi, XSS, Path Traversal, Brute Force, and Ingress Port Scans.
   - Shannon entropy score for encoded/obfuscated attack vectors.
   - MITRE ATT&CK tactic tagging.

3. **High-DPI Visualizations & Topology:**
   - 60 FPS HTML5 Canvas Charts (Velocity Splines, Sweep Donut charts, Sparklines).
   - Interactive Network Topology Flow Mesh.

4. **Omnibox Command Palette:**
   - `Cmd+K` / `Ctrl+K` keyboard-driven command navigation.

---

## 📁 Project Structure

```text
├── js/
│   ├── app.js                  # Master Application Controller & Lifecycle
│   ├── mock-data.js            # In-Memory Telemetry Engine & LogVault API Service
│   ├── normalizer.js           # Multi-Format Normalization Pipeline UI
│   ├── parsers.js              # Dedicated Log Format Parsers & Test Harness
│   ├── anomaly.js              # Anomaly Detection & Threat Rules Engine
│   ├── ai-mapper.js            # Zero-Shot Schema Mapping for Custom Logs
│   ├── charts.js               # High-DPI Canvas Chart Engine
│   ├── topology.js             # 60 FPS Network Flow Topology Visualizer
│   ├── log-stream.js           # Real-Time Telemetry Stream Controller
│   ├── analytics.js            # SOC Analytics & KPI Metric Cards
│   ├── sources.js              # Ingestion Sources & Flow Management
│   ├── settings.js             # Configuration & RBAC Management
│   ├── auth.js                 # Authentication & Security Gateway
│   ├── navigation.js           # Screen Router & History Management
│   └── utils.js                # String, Canvas & Formatting Helpers
├── ui-ux-screenshots/
│   ├── light-mode/             # 12 High-DPI Light/Cream Theme Captures
│   └── dark-mode/              # 12 High-DPI Obsidian Dark Theme Captures
├── index.html                  # SOC Command Center Web UI
├── styles.css                  # Custom Theme & CSS Design System
└── package.json                # Project Manifest
```

---

## 📸 UI/UX Screenshots Gallery

All 24 high-resolution UI/UX captures covering all 11 SOC platform screens plus the Operator Authentication Portal are cataloged in [`ui-ux-screenshots/`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots):

| # | Screen / Module | Light Mode (Warm Cream) | Dark Mode (Obsidian) |
| :-: | :--- | :--- | :--- |
| `00` | **Operator Authentication Portal** | [`light-mode/00_login_portal.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/00_login_portal.png) | [`dark-mode/00_login_portal.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/00_login_portal.png) |
| `01` | **SOC Dashboard Home** | [`light-mode/01_dashboard.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/01_dashboard.png) | [`dark-mode/01_dashboard.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/01_dashboard.png) |
| `02` | **Live Log Stream** | [`light-mode/02_live_logs.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/02_live_logs.png) | [`dark-mode/02_live_logs.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/02_live_logs.png) |
| `03` | **Log Normalizer & Hex Dump** | [`light-mode/03_log_normalizer.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/03_log_normalizer.png) | [`dark-mode/03_log_normalizer.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/03_log_normalizer.png) |
| `04` | **AI Schema Inference Mapper** | [`light-mode/04_unknown_logs_ai.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/04_unknown_logs_ai.png) | [`dark-mode/04_unknown_logs_ai.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/04_unknown_logs_ai.png) |
| `05` | **3D Anomaly Threat Graph** | [`light-mode/05_anomalies_3d.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/05_anomalies_3d.png) | [`dark-mode/05_anomalies_3d.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/05_anomalies_3d.png) |
| `06` | **Alert Center & Kanban Board** | [`light-mode/06_alert_center.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/06_alert_center.png) | [`dark-mode/06_alert_center.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/06_alert_center.png) |
| `07` | **SOC Event Analytics** | [`light-mode/07_event_analytics.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/07_event_analytics.png) | [`dark-mode/07_event_analytics.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/07_event_analytics.png) |
| `08` | **Sources Health & Collector Fleet** | [`light-mode/08_sources_topology.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/08_sources_topology.png) | [`dark-mode/08_sources_topology.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/08_sources_topology.png) |
| `09` | **Parser Registry & WASM Chamber** | [`light-mode/09_parser_registry.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/09_parser_registry.png) | [`dark-mode/09_parser_registry.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/09_parser_registry.png) |
| `10` | **Network Conduits Topology** | [`light-mode/10_network_topology.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/10_network_topology.png) | [`dark-mode/10_network_topology.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/10_network_topology.png) |
| `11` | **Platform Settings & Storage** | [`light-mode/11_platform_settings.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/light-mode/11_platform_settings.png) | [`dark-mode/11_platform_settings.png`](file:///c:/Users/malik/Desktop/Sih/ui-ux-screenshots/dark-mode/11_platform_settings.png) |

---

*Developed for Smart India Hackathon (SIH26156) — Enterprise-Grade Universal Log SIEM.*

