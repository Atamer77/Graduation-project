

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import hashlib
import threading
from datetime import datetime
from functools import wraps
from collections import OrderedDict
from dotenv import load_dotenv

load_dotenv()

from Backend.ml_engine import (
    run_static_prediction, run_live_prediction,
    stop_live, get_latest_results, is_live_running
)
from Backend.recommendation_engine import get_recommendation, check_ollama_status
from Backend.ip_blocker import block_ip, unblock_ip, get_blocked_ips
from Backend.notifier import send_email_alert, send_telegram_alert
from Backend.config import Config

import logging
logger = logging.getLogger("smart_alert")

app = Flask(__name__)
CORS(app)

class BoundedSet:
    def __init__(self, maxsize=10000):
        self._data = OrderedDict()
        self._maxsize = maxsize

    def add(self, item):
        if item in self._data:
            return
        if len(self._data) >= self._maxsize:
            self._data.popitem(last=False)
        self._data[item] = True

    def __contains__(self, item):
        return item in self._data

sent_hashes = BoundedSet(maxsize=10000)
pipeline_mode = "static"
pipeline_lock = threading.Lock()
START_TIME = datetime.now()



def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = Config.API_KEY
        if not api_key:
            return f(*args, **kwargs)
        token = request.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token[7:]
        if token != api_key:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated



@app.route("/")
def index():
    return render_template("index.html")



@app.route("/health")
def health():
    rows, counts = get_latest_results()
    return jsonify({
        "status": "ok",
        "uptime_seconds": int((datetime.now() - START_TIME).total_seconds()),
        "mode": pipeline_mode,
        "rows_loaded": len(rows),
        "blocked_ips": len(get_blocked_ips()),
        "ollama": _check_ollama(),
    })



@app.route("/api/results")
def api_results():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    filter_type = request.args.get("filter", "all")

    rows, counts = get_latest_results()

    if filter_type and filter_type != "all":
        rows = [r for r in rows if r.get("prediction") == filter_type]

    total = len(rows)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_rows = rows[start:start + per_page]

    return jsonify({
        "rows": page_rows,
        "all_rows": rows[:500],  
        "counts": counts,
        "mode": pipeline_mode,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        }
    })


@app.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_ips())


@app.route("/api/pipeline_status")
def api_pipeline_status():
    return jsonify({
        "mode": pipeline_mode,
        "ollama": _check_ollama(),
        "blocker": True,
        "email": bool(Config.EMAIL_SENDER),
        "telegram": bool(Config.TELEGRAM_BOT_TOKEN),
    })


@app.route("/api/feature_importance")
def api_feature_importance():
    """Expose XGBoost feature importances for explainability."""
    try:
        from Backend.ml_engine import get_feature_importance
        return jsonify(get_feature_importance())
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/run_static", methods=["POST"])
def api_run_static():
    global pipeline_mode
    pipeline_mode = "static"
    try:
        rows, counts = run_static_prediction()
        _process_alerts(rows)
        return jsonify({"ok": True, "total": len(rows), "counts": counts})
    except Exception as e:
        logger.error(f"Static run failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/start_live", methods=["POST"])
def api_start_live():
    global pipeline_mode
    with pipeline_lock:
        if pipeline_mode == "live" and is_live_running():
            return jsonify({"ok": False, "error": "Live pipeline already running"})
        pipeline_mode = "live"
    t = threading.Thread(target=_live_loop, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": "Live pipeline started"})


@app.route("/api/stop_live", methods=["POST"])
def api_stop_live():
    global pipeline_mode
    pipeline_mode = "static"
    stop_live()
    return jsonify({"ok": True})


def _live_loop():
    for rows in run_live_prediction():
        _process_alerts(rows)



@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    attack = data.get("attack", "Manual")
    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"}), 400
    ok, msg = block_ip(ip, attack)
    return jsonify({"ok": ok, "ip": ip, "message": msg})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"}), 400
    ok = unblock_ip(ip)
    return jsonify({"ok": ok, "ip": ip})



@app.route("/api/recommend", methods=["POST"])
def api_recommend():
    data = request.get_json()
    attack = data.get("attack", "Unknown")
    src_ip = data.get("src_ip", "unknown")
    dst_port = data.get("dst_port", 0)
    confidence = data.get("confidence", 0.9)
    rec = get_recommendation(attack, src_ip, dst_port, confidence)
    return jsonify({"recommendation": rec})



@app.route("/api/send_email", methods=["POST"])
def api_send_email():
    rows, _ = get_latest_results()
    attacks = [r for r in rows if r.get("prediction", "").upper() != "BENIGN"]
    if not attacks:
        return jsonify({"ok": False, "message": "No attacks to report"})
    ok = send_email_alert(attacks)
    return jsonify({"ok": ok})


@app.route("/api/send_telegram", methods=["POST"])
def api_send_telegram():
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        rows, counts = get_latest_results()
        attacks = [r for r in rows if r.get("prediction", "").upper() != "BENIGN"]
        message = _build_telegram_summary(attacks, counts)
    ok = send_telegram_alert(message)
    return jsonify({"ok": ok})



@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    """Return non-secret settings for the UI."""
    return jsonify({
        "router_ip": Config.ROUTER_IP,
        "router_user": Config.ROUTER_USER,
        "block_duration": Config.BLOCK_DURATION,
        "email_sender": Config.EMAIL_SENDER,
        "email_receiver": Config.EMAIL_RECEIVER,
        "interface": Config.NETWORK_INTERFACE,
        "ollama_model": Config.OLLAMA_MODEL,
        "ollama_url": Config.OLLAMA_URL,
        "confidence_threshold": Config.CONFIDENCE_THRESHOLD,
    })


@app.route("/api/settings", methods=["POST"])
@require_auth
def api_save_settings():
    """Write settings to .env file (auth required)."""
    data = request.get_json()
    env_path = ".env"
    lines = []
    if os.path.exists(env_path):
        with open(env_path) as f:
            lines = f.readlines()

    def _set(key, val):
        for i, line in enumerate(lines):
            if line.startswith(key + "="):
                lines[i] = f"{key}={val}\n"
                return
        lines.append(f"{key}={val}\n")

    mapping = {
        "router_ip": "ROUTER_IP",
        "router_user": "ROUTER_USER",
        "block_duration": "BLOCK_DURATION",
        "email_sender": "EMAIL_SENDER",
        "email_receiver": "EMAIL_RECEIVER",
        "interface": "NETWORK_INTERFACE",
        "ollama_model": "OLLAMA_MODEL",
        "ollama_url": "OLLAMA_URL",
        "confidence_threshold": "CONFIDENCE_THRESHOLD",
    }
    for field, env_key in mapping.items():
        if field in data:
            _set(env_key, data[field])

    with open(env_path, "w") as f:
        f.writelines(lines)

    load_dotenv(override=True)
    Config.reload()
    return jsonify({"ok": True})


def ai_decide(ip: str, attack_type: str, confidence: float) -> str:
    
    prompt = f"""You are a cybersecurity analyst in a Security Operations Center.

Attack detected:
IP: {ip}
Type: {attack_type}
Confidence: {confidence}

Decide ONE action:
- block
- monitor
- ignore

Return ONLY one word."""

    try:
        import requests as req
        response = req.post(
            f"{Config.OLLAMA_URL}/api/generate",
            json={
                "model": Config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 5, "num_ctx": 256},
            },
            timeout=Config.OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        raw = response.json().get("response", "").strip().lower()

        for word in ["block", "monitor", "ignore"]:
            if word in raw:
                logger.info(f"AI decision: {word} for IP {ip} ({attack_type}, conf={confidence})")
                return word

        logger.warning(f"AI returned unclear response '{raw}' for {ip} — defaulting to block")
        return "block"

    except Exception as e:
        logger.warning(f"AI decision failed for {ip}: {e} — fallback to block")
        return "block"


def safe_execute(ip: str, decision: str, confidence: float, attack_type: str = "Unknown"):
   
    import ipaddress as _ipa

    try:
        addr = _ipa.ip_address(ip.strip())
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            logger.info(f"Safe-execute: skipped private/loopback IP {ip} (decision={decision})")
            return
    except ValueError:
        logger.warning(f"Safe-execute: invalid IP '{ip}' — skipping")
        return

    if decision == "block" and confidence > 0.7:
        logger.info(f"Safe-execute: BLOCKING {ip} (AI={decision}, conf={confidence:.3f})")
        block_ip(ip, attack_type)
    elif decision == "monitor":
        logger.info(f"Safe-execute: MONITORING {ip} — AI said monitor (conf={confidence:.3f})")
    elif decision == "ignore":
        logger.info(f"Safe-execute: IGNORED {ip} — AI said ignore (conf={confidence:.3f})")
    else:
        logger.info(f"Safe-execute: skipped {ip} — AI={decision} but conf={confidence:.3f} < 0.7")


def _process_alerts(rows):
    attack_rows = [r for r in rows if r.get("alert_level") == "high"]

    new_attacks = []
    for r in attack_rows:
        fp = f"{r.get('src_ip', '')}-{r.get('prediction', '')}"
        hid = hashlib.sha256(fp.encode()).hexdigest()
        if hid not in sent_hashes:
            sent_hashes.add(hid)
            new_attacks.append(r)
            src = r.get("src_ip", "")
            if src and src != "unknown":
                conf = r.get("confidence", 0.9)
                if conf >= 0.95:
                    logger.info(f"Auto-block (conf={conf:.3f}): {src} ({r['prediction']})")
                    safe_execute(src, "block", conf, r["prediction"])
                else:
                    decision = ai_decide(src, r["prediction"], conf)
                    safe_execute(src, decision, conf, r["prediction"])

    if new_attacks:
        threading.Thread(
            target=send_email_alert, args=(new_attacks,), daemon=True
        ).start()
        for r in new_attacks[:5]:
            msg = (
                f" {r['prediction']}\n"
                f"Src: {r.get('src_ip', '?')}  Port: {r.get('dst_port', '?')}\n"
                f"Confidence: {r.get('confidence', '?')}"
            )
            threading.Thread(
                target=send_telegram_alert, args=(msg,), daemon=True
            ).start()


def _build_telegram_summary(attacks, counts):
    total = sum(counts.values())
    lines = [
        f"📊 Smart Alert Summary — {datetime.now().strftime('%H:%M:%S')}",
        f"Total flows: {total}",
    ]
    for k, v in sorted(counts.items(), key=lambda x: -x[1])[:5]:
        lines.append(f"  • {k}: {v}")
    return "\n".join(lines)


def _check_ollama():
    try:
        import requests as req
        r = req.get(Config.OLLAMA_URL, timeout=2)
        return r.status_code == 200
    except Exception:
        return False



if __name__ == "__main__":
    print("=" * 55)
    print("  Smart Alert v4.0 — ML-Based IDS Dashboard")
    print("  http://localhost:5000")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=5000)
