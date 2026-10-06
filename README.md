# LOGVAULT

Universal log pre-processing framework built for Smart India Hackathon 2026.

Problem statement SIH26156 (Blockchain and Cyber Security), team BetterCallCode, team ID 165723.

LOGVAULT takes log files in different formats, works out what each one is, and converts every record into one common structure based on OCSF 1.1. It then checks the events against detection rules, keeps the original line next to the normalized one, and gives analysts a web interface to review and act on what it found. Everything runs on one machine and the server makes no internet calls, so it can be used on networks that are not allowed to send logs outside.

## Why we built it

A security team usually receives logs from firewalls, web servers, Linux and Windows machines, cloud services and in-house applications, and each of them writes logs differently. Someone has to write and maintain a parser for every new source before the data is useful, and fields with the same meaning end up with different names in different tools. On top of that, many government, defence and banking networks cannot use cloud-based log tools at all.

We wanted something that accepts these logs as they are, turns them into a single format that other tools can consume, and runs fully offline.

## What it does

1. Accepts a log file upload or a single record through the REST API.
2. Detects the format of each record and splits files into records (JSON arrays, JSON Lines, CSV with a header, one line per record, XML documents with many events).
3. Parses the record with the matching parser and maps its fields to common names.
4. Builds an OCSF 1.1 event (class, category, activity, severity, endpoints, user) and validates it.
5. Runs detection rules and tags findings with the MITRE ATT&CK technique.
6. Stores the raw log and the normalized event together in SQLite.
7. Optionally asks a local AI model (Ollama) for a second opinion on alerts. An analyst always makes the final decision.

Parsing one record takes about 0.1 ms on a normal laptop. The included demo file (14 records in 4 formats) is processed in roughly 30 ms.

## Supported formats

| Format | Notes |
|---|---|
| Syslog RFC 5424 | Including structured data and the PRI header |
| Syslog RFC 3164 | With or without PRI; SSH, PAM, sudo and iptables messages are read in detail |
| JSON and JSON Lines | Common field names from CloudTrail, ECS and application logs are mapped |
| Logs wrapped in JSON | e.g. `{"timestamp": ..., "log": "<original line>"}` from Filebeat, Docker or Fluentd; the inner line is parsed with its own parser |
| CEF | ArcSight Common Event Format, header and extension fields |
| XML | Windows Event XML and generic XML; DOCTYPE and ENTITY are refused |
| CSV | With or without a header row |
| Apache / Nginx access logs | Common and combined formats |
| Windows key=value exports | Event IDs are classified |
| Generic key=value | Any `key=value` record |
| Free text | IPs, ports, users, timestamps and HTTP requests are picked out by pattern |

For a format that none of these cover, the Schema Mapper screen proposes a field mapping from one sample record. Once saved, the mapping is used for every later record of that format.

## Getting started

You need Docker Desktop.

```bash
docker compose up -d --build
```

Then open http://localhost:8000/?auth=demo, which signs you in with the evaluation account.

To try it, open the Log Normalizer screen and upload `samples/demo-attack.log`. It contains SSH brute-force attempts, SQL injection, XSS and path traversal mixed with normal traffic. You should get 14 records in 4 formats with 10 flagged events. The Alert Center then shows each alert with the AI's proposed verdict, waiting for approval. `samples/cloud-audit.json` is a second example in JSON.

### Evaluation accounts

These are created the first time the server starts. Passwords are stored as PBKDF2 hashes and the role decides what each account can do.

| Email | Password | Role |
|---|---|---|
| sahil.soc@logvault.sih | CyberSecurity2026! | Tier-3 SOC Lead |
| rajesh.cmd@logvault.sih | Command2026! | Incident Commander |
| vikram.hunt@logvault.sih | ThreatHunter2026! | Tier-2 Analyst |
| sneha.triage@logvault.sih | TriageAnalyst2026! | Tier-1 Analyst |

For a real installation, set `LOGVAULT_SEED_OPERATORS=false` and `LOGVAULT_DEMO_LOGIN=false` and change the passwords from the Settings screen.

### Running without Docker

```bash
pip install -r backend/requirements.txt
python -m backend.serve
```

Tested with Python 3.13.

### Optional parts

Local AI: install [Ollama](https://ollama.com), then run `ollama pull llama3.2` and `ollama serve`. LOGVAULT works without it; the rules still detect and explain alerts.

IP locations on the map: run `python scripts/download_geoip.py` once on a machine with internet access and rebuild the image. The database is about 120 MB and is not kept in git.

OpenSearch: start with `OPENSEARCH_URL=http://opensearch:9200 docker compose --profile opensearch up -d --build`. Stored events are then also indexed in OpenSearch and the log search uses it. SQLite remains the main store.

## Features

Ingestion and normalization
- Automatic format detection for the formats listed above
- OCSF 1.1 events with validation results shown for each record
- Original log kept and linked to every normalized event
- Masking of emails, ID numbers and card numbers
- Schema Mapper for new formats without writing code

Detection and investigation
- Rules for SQL injection, XSS, path traversal, brute force, command execution, privilege escalation, data exfiltration and obfuscated content
- MITRE ATT&CK technique on each finding
- Optional AI investigation with verdict, root cause and suggested actions
- Alerts are only closed after an analyst approves; the decision and the analyst's name are recorded
- Threat graph, world map of sources, activity heatmap and per-source statistics

Response and export
- Block an IP or isolate a host. New activity from it is raised as critical, and the list can be exported as iptables, Cisco ACL or Windows Firewall rules
- Export to SIEM and data lake formats: OCSF JSON Lines (plain or gzip), CSV, CEF, Splunk HEC, Elasticsearch/OpenSearch bulk
- Evidence bundles with a SHA-256 manifest, optionally encrypted with AES-256

Security
- Sign-in with hashed passwords and four roles
- Audit log of sign-ins, changes and exports, stored as a SHA-256 hash chain so edits can be detected
- Optional HTTPS
- Storage size limit and retention period

## Offline use

The server does not contact the internet. The AI model, the IP location database and the map data are local. The web page loads its fonts from Google Fonts when it can and falls back to system fonts when offline.

To move LOGVAULT to an isolated network, build the image on a connected machine, save it with `docker save logvault:latest -o logvault.tar`, copy it across and load it with `docker load -i logvault.tar`. If you use the AI, copy the Ollama model files as well.

## Configuration

Settings are read from environment variables or a `.env` file (see `.env.example`).

| Variable | Default | Meaning |
|---|---|---|
| LOGVAULT_PORT | 8000 | Port on the host |
| OLLAMA_HOST | http://host.docker.internal:11434 | Ollama address |
| OLLAMA_DEFAULT_MODEL | llama3.2 | Model to use |
| AUTO_INVESTIGATE | true | Let the AI look at new alerts automatically |
| STORAGE_LIMIT_GB | 0 | Size limit, 0 means none |
| RETENTION_DAYS | 0 | Days to keep events, 0 means forever |
| LOGVAULT_AUTH | true | Require sign-in for API calls |
| LOGVAULT_SEED_OPERATORS | true | Create the evaluation accounts |
| LOGVAULT_DEMO_LOGIN | true | Allow the one-click demo sign-in |
| LOGVAULT_TLS | false | Serve HTTPS using data/tls/cert.pem and key.pem (self-signed if missing) |
| OPENSEARCH_URL | empty | OpenSearch address; empty turns it off |

## API

Interactive documentation is available at http://localhost:8000/docs. All endpoints except health and sign-in need the token returned by `POST /api/auth/login`.

Main endpoints:

- `POST /api/normalize` normalizes one record, `POST /api/upload` processes a file
- `GET /api/events`, `/api/anomalies`, `/api/alerts` return stored data
- `POST /api/alerts/{id}/investigate`, `/approve`, `/reject` for the alert workflow
- `POST /api/mapper/infer` and `/api/mapper/rules` for the Schema Mapper
- `GET /api/export/siem?format=ocsf-jsonl` (also `ocsf-jsonl-gz`, `csv`, `cef`, `splunk-hec`, `elastic-bulk`)
- `POST /api/export/bundle` for an evidence bundle
- `GET /api/audit` and `/api/audit/verify` for the audit log

## Project layout

```
backend/            FastAPI application
  parsers/          one parser per format, plus format detection
  schema/ocsf.py    OCSF conversion and validation
  mitre/            detection rules
  ai/               Ollama client and alert investigation
  tests/            pytest suite (70 tests)
frontend/           web interface, plain HTML/CSS/JavaScript
samples/            demo log files
scripts/            GeoIP download, map data, bundle decryption
```

Run the tests with `python -m pytest backend/tests`.

## Limitations

- Logs come in through upload or the API. There is no syslog listener or collector agent yet.
- Containment produces firewall rules but does not apply them; that is left to the network team.
- The SQLite database is not encrypted on disk. Use disk encryption on the host if that matters.
- Small local AI models can be wrong, which is why rules keep the verdict on the cautious side and a person approves every alert.

Planned next: a UDP/TCP 514 syslog listener, correlation across records (brute-force bursts, impossible travel), and database encryption at rest.

## Credits

- IP geolocation data by [DB-IP](https://db-ip.com), CC BY 4.0
- Map outlines from [Natural Earth](https://www.naturalearthdata.com)
- Icons by [Lucide](https://lucide.dev)
- Local AI through [Ollama](https://ollama.com) with Meta Llama 3.2
- Event schema from the [Open Cybersecurity Schema Framework](https://ocsf.io)

## Team

Sahil ([Sahil-242-ops](https://github.com/Sahil-242-ops)) and Aman Gupta ([amanguptawork124-collab](https://github.com/amanguptawork124-collab)).

Released under the [MIT License](LICENSE).
