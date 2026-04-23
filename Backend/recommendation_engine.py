


import requests
import logging

from Backend.config import Config

logger = logging.getLogger("smart_alert.ollama")

OLLAMA_MODEL = "phi3:mini"

STATIC_RECS = {
    "DDoS": (
        "• Enable rate limiting on the upstream firewall (max 1000 req/s per source IP)\n"
        "• Null-route the source IP at the border router for 15 minutes\n"
        "• Contact ISP scrubbing center if traffic exceeds 1 Gbps\n"
        "• Enable SYN cookies on target servers to absorb the SYN flood"
    ),
    "PortScan": (
        "• Add a DROP rule in iptables for this source IP immediately\n"
        "• Review exposed service ports — disable any non-essential services\n"
        "• Check authentication logs for follow-up exploitation attempts\n"
        "• Enable connection-rate limiting (max 20 new connections/min per IP)"
    ),
    "DoS Hulk": (
        "• Enable mod_evasive or ModSecurity on your web server\n"
        "• Rate-limit HTTP connections to 50 per IP per minute\n"
        "• Enable CAPTCHA challenge for high-frequency requestors\n"
        "• Consider activating Cloudflare Under Attack Mode if using CDN"
    ),
    "FTP-Patator": (
        "• Immediately block this source IP in iptables\n"
        "• Disable FTP if not required — migrate to SFTP\n"
        "• Enforce account lockout after 5 failed login attempts\n"
        "• Rotate all FTP credentials as a precaution"
    ),
    "SSH-Patator": (
        "• Block this IP immediately with iptables or fail2ban\n"
        "• Disable SSH password authentication — enforce key-based auth\n"
        "• Move SSH daemon to a non-standard port\n"
        "• Enable 2FA for all SSH logins"
    ),
    "DoS slowloris": (
        "• Configure server connection timeout (RequestReadTimeout in Apache)\n"
        "• Limit max simultaneous connections per IP to 10\n"
        "• Switch to nginx which handles slowloris better than Apache\n"
        "• Enable fail2ban with apache-badbots filter"
    ),
    "DoS Slowhttptest": (
        "• Set server timeout values to 30 seconds for headers and body\n"
        "• Limit request body size and header size in web server config\n"
        "• Deploy a WAF rule to detect incomplete HTTP requests\n"
        "• Rate-limit POST requests to 5 per second per IP"
    ),
    "DoS GoldenEye": (
        "• Enable HTTP connection limits at the load balancer level\n"
        "• Deploy mod_reqtimeout with aggressive timeout values\n"
        "• Blacklist the source IP range at the firewall\n"
        "• Enable DDoS protection at the CDN/cloud layer"
    ),
    "Bot": (
        "• Block this IP — likely part of a botnet C2 network\n"
        "• Scan all endpoints for malware and C2 beaconing activity\n"
        "• Review outbound traffic for unusual DNS/HTTP patterns\n"
        "• Submit the IP to threat intelligence feeds (AbuseIPDB, VirusTotal)"
    ),
    "Web Attack": (
        "• Block this IP and review all web server access logs\n"
        "• Patch the targeted web application immediately\n"
        "• Enable WAF rules for SQLi, XSS, and path traversal\n"
        "• Review input validation in all form-handling code"
    ),
    "Infiltration": (
        "• CRITICAL: Isolate the affected network segment immediately\n"
        "• Capture full packet traces (tcpdump) for forensic analysis\n"
        "• Review all lateral movement in internal logs\n"
        "• Escalate to senior SOC analyst — likely APT activity"
    ),
    "Heartbleed": (
        "• CRITICAL: Patch OpenSSL to version 1.0.1g or later immediately\n"
        "• Revoke and reissue ALL SSL certificates on affected servers\n"
        "• Force password resets for all users — credentials may be exposed\n"
        "• Scan all services for CVE-2014-0160 with nmap ssl-heartbleed script"
    ),
}

DEFAULT_REC = (
    "• Isolate the affected network segment for analysis\n"
    "• Capture packet traces (tcpdump) for forensic review\n"
    "• Review firewall and authentication logs for lateral movement\n"
    "• Escalate to senior SOC analyst if activity persists"
)

SYSTEM_PROMPT = (
    "You are a senior SOC analyst working in a real Security Operations Center.\n"
    "\n"
    "STRICT RULES:\n"
    "- Output ONLY 3 to 4 bullet points.\n"
    "- Each bullet must be a REAL, actionable step (command, config, or concrete action).\n"
    "- Do NOT explain concepts.\n"
    "- Do NOT include definitions or descriptions.\n"
    "- Do NOT invent tools, commands, or technologies.\n"
    "- Only use well-known tools (iptables, ufw, fail2ban, netstat, tcpdump, systemctl, etc).\n"
    "- If unsure, give a safe generic security action (block IP, check logs, limit traffic).\n"
    "- Never hallucinate unknown commands or fake CVEs.\n"
    "\n"
    "STYLE:\n"
    "- Start each line with '•'\n"
    "- Keep each bullet under 15 words\n"
    "- Be direct and imperative (e.g., 'Block IP using iptables')\n"
    "\n"
    "GOAL:\n"
    "Give immediate defensive actions a SOC analyst would execute right now."
)

def get_recommendation(
    attack_type: str,
    src_ip: str = "unknown",
    dst_port: int = 0,
    confidence: float = 0.9,
) -> str:

    if attack_type.upper() == "BENIGN":
        return "• Normal traffic — no action required."

    try:
        print("[DEBUG] Trying Ollama with model:", OLLAMA_MODEL)

        rec = _query_ollama(attack_type, src_ip, dst_port, confidence)

        if rec:
            print("[DEBUG] USING OLLAMA ✅")
            return rec

    except Exception as e:
        print("[DEBUG] Ollama FAILED ❌:", e)
        logger.warning(f"[OLLAMA] Failed: {e}")

    # fallback
    if attack_type in STATIC_RECS:
        return STATIC_RECS[attack_type]

    return DEFAULT_REC

def _query_ollama(attack_type, src_ip, dst_port, confidence):

    prompt = (
    f"Alert detected:\n"
    f"Attack: {attack_type}\n"
    f"Source IP: {src_ip}\n"
    f"Port: {dst_port}\n"
    f"Confidence: {confidence * 100:.1f}%\n\n"
    f"Give only short mitigation actions."
    )

    payload = {
    "model": "phi3:mini",
    "prompt": prompt,
    "stream":False}
  

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=200,
        )

        print("[DEBUG] STATUS:", response.status_code)
        print("[DEBUG] RESPONSE:", response.text[:200])  

        response.raise_for_status()

        data = response.json()
        return data.get("response", "").strip()

    except Exception as e:
        print("[DEBUG] OLLAMA ERROR:", e)
        return None



def check_ollama_status():

    try:
        r = requests.get(Config.OLLAMA_URL, timeout=3)

        models_r = requests.get(f"{Config.OLLAMA_URL}/api/tags", timeout=3)
        models = [m["name"] for m in models_r.json().get("models", [])]

        return {
            "ok": True,
            "forced_model": OLLAMA_MODEL,
            "available_models": models,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    print(check_ollama_status())
    print(get_recommendation("PortScan", "172.16.0.1", 80, 0.99))
