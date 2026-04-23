venv\Scripts\activate---python app.py --remove cache of backend and remove the files under flow folder then run
# 🛡 Smart Alert v4.0 — AI-Powered Intrusion Detection & Prevention System

A real-time network intrusion detection and prevention system powered by XGBoost machine learning and Ollama AI decision-making, with automated cross-platform IP blocking, email/Telegram alerting, and AI-powered remediation recommendations.

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SOC Dashboard (Browser)                        │
│   Dashboard │ Threats │ Blocked │ AI Advisor │ Model │ Settings  │
│         HTML + CSS + Vanilla JS + Chart.js                       │
└────────────────────────────┬─────────────────────────────────────┘
                             │ REST API (JSON)
┌────────────────────────────┼─────────────────────────────────────┐
│                      Flask Backend (app.py)                       │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │ ml_engine.py │   │ ip_blocker.py│   │recommendation_engine │  │
│  │  XGBoost     │   │  iptables    │   │    Ollama LLM        │  │
│  │  15 classes  │   │  netsh       │   │    (phi3:mini)       │  │
│  │  30 features │   │  cross-plat  │   │    SOC advice        │  │
│  └──────┬───────┘   └──────▲───────┘   └──────────────────────┘  │
│         │                  │                                      │
│         ▼                  │                                      │
│  ┌─────────────────────────┴──────────────────────────────────┐  │
│  │              AI Decision Layer (app.py)                     │  │
│  │   ai_decide() → Ollama → "block" / "monitor" / "ignore"   │  │
│  │   safe_execute() → validate → block_ip()                   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────┐   ┌──────────────┐                             │
│  │ notifier.py  │   │  config.py   │                             │
│  │ Email + TG   │   │  .env loader │                             │
│  └──────────────┘   └──────────────┘                             │
└──────────────────────────────────────────────────────────────────┘
         │                    │                    │
    ┌────┴────┐         ┌────┴────┐          ┌────┴────┐
    │ XGBoost │         │ Local   │          │ Ollama  │
    │ Model   │         │Firewall │          │ LLM     │
    │ .pkl    │         │iptables │          │phi3:mini│
    └─────────┘         │ netsh   │          └─────────┘
                        └─────────┘
```

### Data Flow

```
Network Traffic / CSV Dataset
        │
        ▼
  ┌─────────────┐
  │ ML Engine   │  XGBoost predicts attack type + confidence
  │ (30 features)│
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ 3-Tier      │  HIGH (≥75%) → auto-block
  │ Alert System│  MEDIUM (50-75%) → alert only
  │             │  LOW (<50%) → log only
  └──────┬──────┘
         │ HIGH alerts only
         ▼
  ┌─────────────┐
  │ AI Decision │  Ollama LLM decides: block / monitor / ignore
  │ (ai_decide) │  Fallback: block if Ollama offline
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ Safety Layer│  Validates IP (no private/loopback)
  │(safe_execute)│  Checks confidence > 0.7
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐     ┌──────────┐     ┌──────────┐
  │ IP Blocker  │     │  Email   │     │ Telegram │
  │ iptables/   │     │  Alert   │     │  Alert   │
  │ netsh       │     └──────────┘     └──────────┘
  └─────────────┘
```

---

## Project Structure

```
smart_alert_v4/
├── app.py                          ← Flask entry point + AI decision layer
├── attack_injector.py              ← Demo attack simulator (no CICFlowMeter needed)
├── run.sh                          ← Quick start script (Linux)
├── requirements.txt                ← Pinned Python dependencies
├── .env.example                    ← Config template (copy to .env)
├── .gitignore
├── Backend/
│   ├── __init__.py
│   ├── config.py                   ← Centralized config (hot-reloadable)
│   ├── ml_engine.py                ← XGBoost prediction + live CSV reader
│   ├── ip_blocker.py               ← Cross-platform firewall (iptables/netsh)
│   ├── notifier.py                 ← Email (Gmail SMTP) + Telegram Bot
│   └── recommendation_engine.py    ← Ollama LLM SOC recommendations
├── Artifacts/
│   ├── saved_model.pkl             ← Trained XGBoost model
│   ├── scaler.pkl                  ← StandardScaler (scikit-learn 1.6.1)
│   ├── label_encoder.pkl           ← LabelEncoder (15 classes)
│   └── merged_test_data.csv        ← Test dataset (5,170 rows)
├── templates/
│   └── index.html                  ← SOC Dashboard (single-file SPA)
└── logs/
    ├── predictions.log             ← JSON prediction log
    ├── blocker.log                 ← Block/unblock event log
    └── blocked_ips.json            ← Active blocked IPs database
```

---

## Quick Start

### Linux

```bash
cd smart_alert_v4
chmod +x run.sh
./run.sh
```

### Windows

```cmd
cd smart_alert_v4
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
mkdir logs
copy .env.example .env
python app.py
```

Then open **http://localhost:5000** and click **▶ Run Static**.

---

## Full Setup Guide

### Step 1 — Python Environment

**Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Create .env

```bash
cp .env.example .env
```

Fill in your credentials (see Credential Setup below).

### Step 3 — Create Logs Directory

**Linux:**
```bash
mkdir -p logs/flows
```

**Windows:**
```cmd
mkdir logs\flows
```

### Step 4 — Install Ollama (free, local)

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull phi3:mini
```

**Windows:**
Download from https://ollama.com/download — install, then:
```cmd
ollama serve
ollama pull phi3:mini
```

### Step 5 — Run

```bash
python app.py
```

Open **http://localhost:5000**

---

## Credential Setup (All Free)

### Gmail (Email Alerts)

1. Go to https://myaccount.google.com/security
2. Enable **2-Step Verification**
3. Go to https://myaccount.google.com/apppasswords
4. Select **Mail** → Generate
5. Copy the 16-character password

```
EMAIL_SENDER=your.email@gmail.com
EMAIL_PASSWORD=abcdefghijklmnop
EMAIL_RECEIVER=your.email@gmail.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
```

Sender and receiver can be the same account.

### Telegram Bot

1. Open Telegram → search **@BotFather** → send `/newbot`
2. Name: `Smart Alert IDS`
3. Username: `smart_alert_yourname_bot` (must end in `bot`)
4. BotFather gives you a token — copy it
5. Send any message to your new bot (just type "hi")
6. Open in browser: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
7. Find `"chat":{"id":123456789}` in the JSON

```
TELEGRAM_BOT_TOKEN=7845123456:AAF-abcdefghijk123456
TELEGRAM_CHAT_ID=123456789
```

### Ollama LLM

No account needed. Runs locally.

```bash
ollama pull phi3:mini     # 2.3 GB, works on 4 GB RAM
```

```
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini
OLLAMA_TIMEOUT=30
```

Other model options:

| Model | Size | RAM Needed | Quality |
|-------|------|-----------|---------|
| phi3:mini | 2.3 GB | 4 GB | Good (default) |
| llama3.2 | 2 GB | 4 GB | Good |
| llama3.2:1b | 1 GB | 2 GB | Basic (fastest) |
| mistral | 4.1 GB | 8 GB | Best |

### IP Blocker

Leave `ROUTER_IP` empty for demo mode — IPs get tracked in the dashboard with countdown timers but no actual firewall rules are applied:

```
ROUTER_IP=
```

On Linux with sudo access, the system automatically uses `iptables`. On Windows with admin access, it uses `netsh`. If neither is available, it runs in demo mode silently.

---

## Complete .env File

```
# ML Model Paths (DO NOT CHANGE)
MODEL_PATH=Artifacts/saved_model.pkl
SCALER_PATH=Artifacts/scaler.pkl
ENCODER_PATH=Artifacts/label_encoder.pkl
DATA_PATH=Artifacts/merged_test_data.csv
LIVE_CSV=live_capture.csv
LOG_PATH=logs/predictions.log
FLOWS_DIR=logs/flows

# ML Threshold
CONFIDENCE_THRESHOLD=0.75

# Network (for CICFlowMeter live capture)
NETWORK_INTERFACE=eth0
CAPTURE_SECS=60

# Ollama LLM (free, local)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini
OLLAMA_TIMEOUT=30

# IP Blocker (empty = demo mode)
ROUTER_IP=
ROUTER_USER=root
SSH_KEY=~/.ssh/smart_alert_key
BLOCK_DURATION=300
BLOCKED_DB=logs/blocked_ips.json
BLOCKER_LOG=logs/blocker.log

# Email (fill with your Gmail credentials)
EMAIL_SENDER=
EMAIL_PASSWORD=
EMAIL_RECEIVER=
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465

# Telegram Bot (fill with your bot credentials)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# API Security (empty = no auth, dev mode)
API_KEY=
```

---

## Running Modes

### Static Mode (Quick Test)

Click **▶ Run Static** in the dashboard. Processes 5,170 flows from `merged_test_data.csv` instantly.

### Demo Live Mode (No CICFlowMeter Needed)

**Terminal 1:**
```bash
python app.py
```



### Real Live Mode (With CICFlowMeter)

Install CICFlowMeter:



**Windows:**
Install Npcap from https://npcap.com, then:
```cmd
pip install cicflowmeter
```

Set your network interface in `.env`:
```
NETWORK_INTERFACE=eth0     # Linux (use: ip link show)
NETWORK_INTERFACE=Ethernet # Windows (use: ipconfig)
```

Click **◉ Start Live** (green button) in the dashboard.

---

## 3-Tier Alert System

| Level | Condition | Automated Action |
|-------|-----------|-----------------|
| **HIGH** | Attack + confidence ≥ 75% | AI decision → auto-block + email + Telegram |
| **MEDIUM** | Attack + confidence 50–75% | Alert only (manual review) |
| **LOW** | BENIGN or confidence < 50% | Log only |

---

## AI-Assisted Blocking Pipeline

The system uses a two-stage AI pipeline:

**Stage 1 — ML Detection:** XGBoost classifies each network flow into one of 15 classes with a confidence score.

**Stage 2 — AI Decision:** For HIGH alerts, Ollama LLM receives the attack details and decides:
- **block** → IP gets blocked via local firewall
- **monitor** → logged for SOC review, no block
- **ignore** → dismissed

**Safety layer:** Private IPs (192.168.x, 10.x, 127.x) are never blocked. Confidence must exceed 0.7. If Ollama is offline, the system falls back to blocking directly (fail-safe).

---

## Cross-Platform IP Blocking

| OS | Firewall Tool | Block Command | Unblock Command |
|----|--------------|---------------|-----------------|
| Linux | iptables | `sudo iptables -A INPUT -s <IP> -j DROP` | `sudo iptables -D INPUT -s <IP> -j DROP` |
| Windows | netsh | `netsh advfirewall firewall add rule name="SmartAlert_Block_<IP>" dir=in action=block remoteip=<IP>` | `netsh advfirewall firewall delete rule name="SmartAlert_Block_<IP>"` |
| Other / No permission | Demo mode | Stored in DB only | Removed from DB only |

The OS is detected automatically. If the firewall command fails (no sudo, no admin), the system continues in demo mode — IPs are tracked in the dashboard with countdown timers, but no actual firewall rules are applied.

---

## Security Features

- **IP Validation** — All IPs validated with Python `ipaddress` module before any command execution (prevents command injection)
- **XSS Protection** — All dynamic content escaped via `esc()` before DOM insertion
- **API Authentication** — Settings endpoint protected with Bearer token
- **AI Safety Layer** — Never blocks private/loopback/reserved IPs regardless of AI decision
- **SHA-256 Deduplication** — Alert dedup uses SHA-256 (not MD5)
- **Bounded Memory** — Alert hash set limited to 10,000 entries with FIFO eviction
- **Fail-Safe AI** — If Ollama is offline, system falls back to direct blocking
- **Graceful Firewall** — If iptables/netsh fails, system continues in demo mode without crashing
- **Private IP Protection** — RFC1918, loopback, reserved, and multicast addresses are never blocked

---

## Dashboard Screens

| Screen | Description |
|--------|-------------|
| **Dashboard** | 5 stat cards, pipeline controls, 3 charts (doughnut/line/bars), recent events table, event log timeline |
| **Threat Log** | Full paginated table (50/page), filter by attack type, export CSV, per-row block/AI actions |
| **Blocked IPs** | Active blocks with live countdown timers, per-IP unblock button, bulk unblock |
| **AI Advisor** | Select any attack → Ollama returns 3–4 SOC remediation steps, static fallback if offline |
| **Model Insight** | XGBoost feature importance bars (top 20), model metadata, alert tier explanation |
| **Settings** | Email, Telegram, IP Blocker, Ollama, and ML threshold config — writes to .env with hot-reload |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/health` | Health check (uptime, mode, counts) |
| GET | `/api/results` | Predictions with pagination + filter |
| GET | `/api/blocked` | Currently blocked IPs |
| GET | `/api/pipeline_status` | System component status |
| GET | `/api/feature_importance` | XGBoost feature importance |
| GET | `/api/injector_status` | Demo CSV file status |
| POST | `/api/run_static` | Run static prediction on dataset |
| POST | `/api/start_live` | Start CICFlowMeter live capture |
| POST | `/api/start_live_csv` | Start demo live mode (CSV watcher) |
| POST | `/api/stop_live` | Stop any live pipeline |
| POST | `/api/set_mode` | Switch static/live mode |
| POST | `/api/reset_live_csv` | Delete live_capture.csv + reset reader |
| POST | `/api/block` | Block an IP (manual) |
| POST | `/api/block_local` | Block via local iptables (no SSH) |
| POST | `/api/unblock` | Unblock an IP |
| POST | `/api/recommend` | Get AI SOC recommendation |
| POST | `/api/send_email` | Send email threat report |
| POST | `/api/send_telegram` | Send Telegram alert |
| GET/POST | `/api/settings` | Read/write configuration |

---

## Credits

- **Dataset:** CIC-IDS-2017 (Canadian Institute for Cybersecurity)
- **ML:** XGBoost + scikit-learn
- **AI/LLM:** Ollama (phi3:mini)
- **Frontend:** Chart.js, JetBrains Mono, DM Sans
- **Blocking:** iptables (Linux) / netsh (Windows)
