"""
Smart Alert v4.0 — Notification Module
Handles Email (SMTP/Gmail) + Telegram Bot alerts.
Reads config at call time so settings changes take effect without restart.
"""

import smtplib
import requests
import logging
from email.message import EmailMessage
from datetime import datetime

from Backend.config import Config

logger = logging.getLogger("smart_alert.notifier")


# ══════════════════════════════════════════════════════════════════
#  EMAIL
# ══════════════════════════════════════════════════════════════════
def send_email_alert(attack_rows: list[dict]) -> bool:
    """Send an HTML email report for attack rows. Returns True on success."""
    # Read config at call time (supports hot-reload)
    sender = Config.EMAIL_SENDER
    password = Config.EMAIL_PASSWORD
    receiver = Config.EMAIL_RECEIVER

    if not sender or not password or not receiver:
        logger.warning("[EMAIL] Credentials not configured — skipping")
        return False

    if not attack_rows:
        return False

    msg = EmailMessage()
    msg["Subject"] = (
        f"🚨 Smart Alert — {len(attack_rows)} Threats Detected "
        f"[{datetime.now().strftime('%H:%M:%S')}]"
    )
    msg["From"] = sender
    msg["To"] = receiver

    html = _build_email_html(attack_rows)
    msg.set_content("Smart Alert detected threats. Open in HTML-enabled email client.")
    msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP_SSL(Config.SMTP_HOST, Config.SMTP_PORT, timeout=15) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
        logger.info(f"[EMAIL] Sent alert for {len(attack_rows)} attacks to {receiver}")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("[EMAIL] Authentication failed — check Gmail App Password")
        return False
    except Exception as e:
        logger.error(f"[EMAIL] Failed: {e}")
        return False


def _build_email_html(rows: list[dict]) -> str:
    critical_rows = [r for r in rows if r.get("alert_level") in ("high", "medium")]
    attack_count = len(critical_rows)

    type_counts: dict[str, int] = {}
    for r in critical_rows:
        p = r.get("prediction", "Unknown")
        type_counts[p] = type_counts.get(p, 0) + 1

    summary_rows = "".join(
        f"<tr><td style='padding:6px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;color:#ff4d4d'>{k}</td>"
        f"<td style='padding:6px 12px;border-bottom:1px solid #2a2a2a;"
        f"text-align:center;font-family:monospace;color:#ffaa00'>{v}</td></tr>"
        for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
    )

    detail_rows = "".join(
        f"<tr>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;font-size:12px;color:#8899aa'>{r.get('timestamp', '')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;font-size:12px;color:#00e5ff'>{r.get('src_ip', '?')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;font-size:12px;color:#e0e0e0'>{r.get('dst_port', '?')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;font-size:12px;color:#ff4d4d;font-weight:bold'>"
        f"{r.get('prediction', '?')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #2a2a2a;"
        f"font-family:monospace;font-size:12px;color:#00e676'>{r.get('confidence', '?')}</td>"
        f"</tr>"
        for r in critical_rows[:50]
    )

    return f"""<!DOCTYPE html><html><body style="background:#0d1117;color:#e0e0e0;
    font-family:'Segoe UI',Arial,sans-serif;padding:24px;margin:0">
    <div style="max-width:700px;margin:0 auto">
      <div style="border-left:4px solid #ff3b5c;padding-left:16px;margin-bottom:24px">
        <h1 style="color:#ff3b5c;font-size:22px;margin:0 0 4px">
          🚨 Smart Alert — Threat Report</h1>
        <p style="color:#8899aa;margin:0;font-size:13px">
          Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · XGBoost IDS v4.0</p>
      </div>
      <div style="display:flex;gap:16px;margin-bottom:24px">
        <div style="background:#161e28;border:1px solid #1e2d3d;border-radius:8px;
            padding:16px;flex:1;text-align:center">
          <div style="font-size:28px;font-weight:700;color:#ff3b5c;
              font-family:monospace">{attack_count}</div>
          <div style="font-size:12px;color:#8899aa;margin-top:4px">ATTACKS</div>
        </div>
        <div style="background:#161e28;border:1px solid #1e2d3d;border-radius:8px;
            padding:16px;flex:1;text-align:center">
          <div style="font-size:28px;font-weight:700;color:#ffaa00;
              font-family:monospace">{len(type_counts)}</div>
          <div style="font-size:12px;color:#8899aa;margin-top:4px">TYPES</div>
        </div>
        <div style="background:#161e28;border:1px solid #1e2d3d;border-radius:8px;
            padding:16px;flex:1;text-align:center">
          <div style="font-size:28px;font-weight:700;color:#00e5ff;
              font-family:monospace">{len(rows)}</div>
          <div style="font-size:12px;color:#8899aa;margin-top:4px">TOTAL FLOWS</div>
        </div>
      </div>
      <h3 style="color:#e0e0e0;font-size:14px;margin-bottom:10px;font-family:monospace;
          text-transform:uppercase">Attack Summary</h3>
      <table style="width:100%;border-collapse:collapse;background:#161e28;
          border-radius:8px;overflow:hidden;margin-bottom:24px">
        <thead><tr>
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Attack Type</th>
          <th style="padding:10px 12px;text-align:center;font-size:11px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Count</th>
        </tr></thead>
        <tbody>{summary_rows}</tbody>
      </table>
      <h3 style="color:#e0e0e0;font-size:14px;margin-bottom:10px;font-family:monospace;
          text-transform:uppercase">Event Details (first 50)</h3>
      <table style="width:100%;border-collapse:collapse;background:#161e28;
          border-radius:8px;overflow:hidden;margin-bottom:24px">
        <thead><tr>
          <th style="padding:8px 12px;text-align:left;font-size:10px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Timestamp</th>
          <th style="padding:8px 12px;text-align:left;font-size:10px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Source IP</th>
          <th style="padding:8px 12px;text-align:left;font-size:10px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Port</th>
          <th style="padding:8px 12px;text-align:left;font-size:10px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Prediction</th>
          <th style="padding:8px 12px;text-align:left;font-size:10px;color:#8899aa;
              font-family:monospace;border-bottom:1px solid #1e2d3d">Confidence</th>
        </tr></thead>
        <tbody>{detail_rows}</tbody>
      </table>
      <p style="color:#4a5f72;font-size:12px;text-align:center;font-family:monospace">
        Smart Alert v4.0 · XGBoost IDS · CIC-IDS-2017</p>
    </div></body></html>"""


# ══════════════════════════════════════════════════════════════════
#  TELEGRAM
# ══════════════════════════════════════════════════════════════════
def send_telegram_alert(message: str) -> bool:
    import requests

    try:
        # 🔒 Force safe message
        if not message or not str(message).strip():
            message = "🚨 SMART_ALERT: Test message"

        message = str(message)

        url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"

        payload = {
            "chat_id": str(Config.TELEGRAM_CHAT_ID),
            "text": message
        }

        response = requests.post(url, data=payload, timeout=10)

        print("Telegram response:", response.text)  # 🔥 DEBUG

        response.raise_for_status()
        return True

    except Exception as e:
        print("[TELEGRAM ERROR]:", e)
        return False

# ── CLI test ─────────────────────────────────────────────────────
if __name__ == "__main__":
    test_rows = [
        {
            "timestamp": "2026-03-26 10:30:00",
            "src_ip": "45.33.32.156",
            "dst_port": 80,
            "prediction": "DDoS",
            "confidence": 0.97,
            "alert_level": "high",
        },
    ]
    print("Email result:", send_email_alert(test_rows))
    print("Telegram result:", send_telegram_alert("🧪 Smart Alert test"))
