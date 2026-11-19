# Omnisight SIEM

**Local-first, modular security platform** for shared lab environments and enterprise operations.

- **Edge Agent (Python)** — multi-vector telemetry, historical backfill (`.gz` / rotated logs), HMAC-signed remote control
- **Central Backend (FastAPI + Async SQLAlchemy/SQLite)** — dual-channel ingestion, hybrid detection (rules + Ollama), WebSocket control gateway, PDF forensic reports
- **Analyst Dashboard (Vite + React + Vanilla CSS)** — Datadog/Splunk-style high-density UI

**Strict constraint: no Docker.** All execution is bare-metal.

---

## Architecture

```
┌─────────────────┐     JSON batches      ┌──────────────────────────┐
│  Edge Agent(s)  │ ────────────────────► │  FastAPI Backend :8000   │
│  collector.py   │                       │  • Ingestion             │
│  transport.py   │ ◄── signed commands ──│  • Rules + Ollama AI     │
│  backfill.py    │      (WebSocket)      │  • Orchestration (WS)    │
└─────────────────┘                       │  • Reporting (PDF)       │
                                          └────────────┬─────────────┘
                                                       │ REST
                                          ┌────────────▼─────────────┐
                                          │  React Dashboard :5173   │
                                          │  Live Stream · Incidents │
                                          │  Node Manager · Reports  │
                                          └──────────────────────────┘
```

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- (Optional) [Ollama](https://ollama.com) running locally with a model such as `llama3.2` for AI risk scoring

---

## 1. Backend Setup

```bash
cd omnisight-siem

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Populate 48h synthetic multi-vector dataset + demo alerts
python scripts/seed_demo.py

# Start API
uvicorn backend.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

---

## 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Dashboard: http://127.0.0.1:5173

The Vite dev server proxies `/api` and `/ws` to the backend.

---

## 3. Edge Agent Setup

In a separate terminal (venv activated, from project root):

```bash
python -m agent.collector
```

Options:

```bash
python -m agent.collector \
  --node-id lab-node-01 \
  --backend http://127.0.0.1:8000 \
  --ws ws://127.0.0.1:8000/ws/agent \
  --secret omnisight-lab-secret-change-me
```

The agent will:

1. Perform historical backfill (`seek(0)` + `.gz` parsing)
2. Live-tail auth / DB / application logs
3. Run lightweight FIM scans
4. Maintain an authenticated WebSocket for signed remediation commands

---

## Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/ingest/events` | Real-time JSON telemetry from agents |
| POST | `/api/v1/ingest/csv` | Bulk CSV upload |
| GET | `/api/v1/events` | Query stored events |
| GET | `/api/v1/alerts` | Incident triage queue |
| GET | `/api/v1/nodes` | Lab node inventory |
| POST | `/api/v1/nodes/command` | Dispatch signed command to one node |
| POST | `/api/v1/nodes/broadcast` | Broadcast command |
| WS | `/ws/agent?node_id=…` | Agent control channel |
| GET | `/api/v1/reports/incident/{alert_id}/pdf` | Forensic PDF report |
| GET | `/api/v1/reports/incident/{alert_id}/json` | JSON incident package |

---

## Hybrid Detection Engine

**Tier-1 (deterministic sliding-window)**

- Brute-force auth (≥5 failures / 5 min)
- FIM burst (≥3 integrity events / 5 min)
- Off-hours successful logins
- Privilege-escalation signals

**Tier-2 (local Ollama)**

- Calls `http://localhost:11434/api/generate`
- Returns 0–100 risk score + threat brief
- Graceful fallback when Ollama is offline

---

## Remote Control Commands (whitelist)

`whoami`, `uptime`, `hostname`, `df`, `free`, `ps_top`, `netstat`, `echo_test`, `lock_session`, `kill_process`, `block_ip`, `disable_user`

Destructive actions are **demo-safe** (logged, not applied to the host firewall/accounts unless you intentionally harden them).

All commands are HMAC-SHA256 signed; the agent verifies the signature before execution and returns a signed receipt.

---

## Project Layout

```
omnisight-siem/
├── agent/
│   ├── collector.py      # Multi-vector live tailing
│   ├── backfill.py       # Historical parser (.gz, seek(0))
│   └── transport.py      # Shipper + WebSocket control listener
├── backend/
│   ├── main.py           # FastAPI entry
│   ├── database.py       # Async SQLAlchemy / SQLite
│   ├── ingestion.py      # Dual-channel intake
│   ├── rules.py          # Hybrid detection engine
│   ├── orchestration.py  # Node control gateway
│   └── reporting.py      # PDF/JSON forensic reports
├── frontend/             # Vite + React dashboard
├── scripts/seed_demo.py  # 48-hour synthetic dataset
└── requirements.txt
```

---

## Security Notes (Lab Use)

- Default shared secret: `omnisight-lab-secret-change-me` — change it for any non-lab deployment.
- SQLite file `omnisight.db` is created in the working directory.
- Agent command whitelist prevents arbitrary shell execution.
- No containerization; run under a dedicated OS user when possible.

---

## License

Provided as an educational / lab reference implementation.
