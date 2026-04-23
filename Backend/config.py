"""
Smart Alert — Centralized Configuration
All env vars read from one place; supports hot-reload via Config.reload().
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Single source of truth for all configuration."""

    # ── ML Paths ──────────────────────────────────────────────
    MODEL_PATH = os.getenv("MODEL_PATH", "Artifacts/saved_model.pkl")
    SCALER_PATH = os.getenv("SCALER_PATH", "Artifacts/scaler.pkl")
    ENCODER_PATH = os.getenv("ENCODER_PATH", "Artifacts/label_encoder.pkl")
    DATA_PATH = os.getenv("DATA_PATH", "Artifacts/merged_test_data.csv")
    LIVE_CSV = os.getenv("LIVE_CSV", "live_capture.csv")
    LOG_PATH = os.getenv("LOG_PATH", "logs/predictions.log")
    FLOWS_DIR = os.getenv("FLOWS_DIR", "logs/flows")

    # ── ML Thresholds ─────────────────────────────────────────
    CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))

    # ── Network ───────────────────────────────────────────────
    NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
    CAPTURE_SECS = int(os.getenv("CAPTURE_SECS", "120"))

    # ── Ollama ────────────────────────────────────────────────
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3")
    OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "10"))

    # ── IP Blocker ────────────────────────────────────────────
    ROUTER_IP = os.getenv("ROUTER_IP", "")
    ROUTER_USER = os.getenv("ROUTER_USER", "root")
    SSH_KEY = os.getenv("SSH_KEY", os.path.expanduser("~/.ssh/smart_alert_key"))
    BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "300"))
    BLOCKED_DB = os.getenv("BLOCKED_DB", "logs/blocked_ips.json")
    BLOCKER_LOG = os.getenv("BLOCKER_LOG", "logs/blocker.log")

    # ── Email ─────────────────────────────────────────────────
    EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
    EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))

    # ── Telegram ──────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

    # ── Security ──────────────────────────────────────────────
    API_KEY = os.getenv("API_KEY", "")

    @classmethod
    def reload(cls):
        """Re-read all values from environment after .env change."""
        load_dotenv(override=True)
        for attr in dir(cls):
            if attr.startswith("_") or attr == "reload":
                continue
            env_key = attr
            default = getattr(cls, attr)
            raw = os.getenv(env_key, "")
            if not raw:
                continue
            if isinstance(default, int):
                try:
                    setattr(cls, attr, int(raw))
                except ValueError:
                    pass
            elif isinstance(default, float):
                try:
                    setattr(cls, attr, float(raw))
                except ValueError:
                    pass
            else:
                setattr(cls, attr, raw)
