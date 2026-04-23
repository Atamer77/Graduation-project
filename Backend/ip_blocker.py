"""
Smart Alert v4.0 — IP Blocker
Cross-platform local firewall blocking:
  • Linux  → iptables (via sudo)
  • Windows → netsh advfirewall
HARDENED: IP validation prevents command injection.
Falls back to demo mode (DB-only) if firewall commands fail.
"""

import subprocess
import platform
import ipaddress
import json
import os
import threading
import logging
from datetime import datetime

from Backend.config import Config

# ── OS Detection (done once at import) ───────────────────────────
OS_TYPE = platform.system()  # "Linux", "Windows", "Darwin", etc.

# ── Logging ───────────────────────────────────────────────────────
os.makedirs(os.path.dirname(Config.BLOCKER_LOG) if os.path.dirname(Config.BLOCKER_LOG) else "logs", exist_ok=True)

logger = logging.getLogger("smart_alert.blocker")
handler = logging.FileHandler(Config.BLOCKER_LOG)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logger.info(f"IP Blocker initialized | OS: {OS_TYPE}")
print(f"[BLOCKER] OS detected: {OS_TYPE}")

# ── Thread-safe DB lock ───────────────────────────────────────────
_db_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════
#  IP VALIDATION (prevents command injection)
# ══════════════════════════════════════════════════════════════════
def validate_ip(ip: str) -> tuple[bool, str]:
    """
    Strictly validate an IP address string.
    Returns (is_valid, reason).
    """
    ip = ip.strip()
    if not ip:
        return False, "Empty IP address"

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP format: {ip}"

    if addr.is_private:
        return False, f"Private IP not blocked: {ip}"
    if addr.is_loopback:
        return False, f"Loopback IP not blocked: {ip}"
    if addr.is_reserved:
        return False, f"Reserved IP not blocked: {ip}"
    if addr.is_multicast:
        return False, f"Multicast IP not blocked: {ip}"
    if addr.is_unspecified:
        return False, f"Unspecified IP not blocked: {ip}"

    return True, "valid"


# ══════════════════════════════════════════════════════════════════
#  DATABASE (unchanged)
# ══════════════════════════════════════════════════════════════════
def _load_db() -> dict:
    try:
        with open(Config.BLOCKED_DB) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_db(db: dict):
    db_dir = os.path.dirname(Config.BLOCKED_DB)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    with open(Config.BLOCKED_DB, "w") as f:
        json.dump(db, f, indent=2)


# ══════════════════════════════════════════════════════════════════
#  SSH HELPER (legacy — kept for reference, NO LONGER CALLED)
# ══════════════════════════════════════════════════════════════════
def _ssh(command: str) -> bool:
    """
    [LEGACY] Run a shell command on a remote router via SSH.
    Replaced by _firewall_block / _firewall_unblock.
    Kept in file for backward compatibility — not called anywhere.
    """
    logger.warning("_ssh() called but SSH blocking is disabled — use local firewall instead")
    return False


# ══════════════════════════════════════════════════════════════════
#  LOCAL FIREWALL — CROSS-PLATFORM
# ══════════════════════════════════════════════════════════════════
def _firewall_block(ip: str) -> bool:
    """
    Block an IP using the local OS firewall.
    Linux   → sudo iptables -A INPUT -s <IP> -j DROP
    Windows → netsh advfirewall firewall add rule ...
    Returns True on success, False on failure (demo mode continues).
    """
    try:
        if OS_TYPE == "Linux":
            # Check if rule already exists (avoid duplicates)
            check = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            if check.returncode == 0:
                logger.info(f"iptables rule already exists for {ip} — skipping")
                return True

            # Add INPUT rule
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, check=True, timeout=10
            )
            # Add FORWARD rule (for gateway setups)
            subprocess.run(
                ["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            logger.info(f"iptables BLOCK success: {ip}")
            return True

        elif OS_TYPE == "Windows":
            rule_name = f"SmartAlert_Block_{ip}"
            # Add inbound block rule
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in", "action=block", f"remoteip={ip}",
                    "enable=yes"
                ],
                capture_output=True, text=True, check=True, timeout=10
            )
            logger.info(f"netsh BLOCK success: {ip} (rule: {rule_name})")
            return True

        else:
            # macOS / other — no native firewall CLI support
            logger.warning(f"Unsupported OS '{OS_TYPE}' — demo mode (no firewall rule applied)")
            return False

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.warning(f"Firewall BLOCK failed for {ip} — {stderr} (continuing in demo mode)")
        return False
    except FileNotFoundError:
        logger.warning(
            f"Firewall binary not found on {OS_TYPE} — "
            f"running in demo mode (IP stored in DB only)"
        )
        return False
    except subprocess.TimeoutExpired:
        logger.warning(f"Firewall command timed out for {ip} — demo mode")
        return False
    except PermissionError:
        logger.warning(
            f"Permission denied for firewall command ({ip}) — "
            f"run with sudo/admin. Continuing in demo mode."
        )
        return False
    except Exception as e:
        logger.warning(f"Firewall BLOCK unexpected error: {e} — demo mode")
        return False


def _firewall_unblock(ip: str) -> bool:
    """
    Remove firewall block for an IP using the local OS firewall.
    Linux   → sudo iptables -D INPUT -s <IP> -j DROP
    Windows → netsh advfirewall firewall delete rule name="SmartAlert_Block_<IP>"
    Returns True on success.
    """
    try:
        if OS_TYPE == "Linux":
            # Remove INPUT rule
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            # Remove FORWARD rule (ignore error if it doesn't exist)
            subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            logger.info(f"iptables UNBLOCK success: {ip}")
            return True

        elif OS_TYPE == "Windows":
            rule_name = f"SmartAlert_Block_{ip}"
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ],
                capture_output=True, text=True, check=True, timeout=10
            )
            logger.info(f"netsh UNBLOCK success: {ip} (rule: {rule_name})")
            return True

        else:
            logger.warning(f"Unsupported OS '{OS_TYPE}' — cannot remove firewall rule")
            return False

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.warning(f"Firewall UNBLOCK failed for {ip} — {stderr}")
        return False
    except FileNotFoundError:
        logger.warning(f"Firewall binary not found — unblock skipped for {ip}")
        return False
    except subprocess.TimeoutExpired:
        logger.warning(f"Firewall unblock timed out for {ip}")
        return False
    except Exception as e:
        logger.warning(f"Firewall UNBLOCK unexpected error: {e}")
        return False


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API (same signatures as before)
# ══════════════════════════════════════════════════════════════════
def block_ip(ip: str, attack_type: str = "Unknown") -> tuple[bool, str]:
    """
    Block an IP using local firewall and schedule auto-unblock.
    Returns (success: bool, message: str).
    If the firewall command fails, the IP is still stored in the DB
    (demo mode) so the dashboard and auto-unblock still work.
    """
    ip = ip.strip()

    # VALIDATE — prevents command injection
    valid, reason = validate_ip(ip)
    if not valid:
        logger.info(f"Block rejected: {reason}")
        return False, reason

    with _db_lock:
        db = _load_db()
        if ip in db:
            logger.info(f"Already blocked: {ip}")
            return True, "Already blocked"

        # Apply local firewall rule (graceful — never crashes)
        fw_ok = _firewall_block(ip)

        # Persist to DB regardless of firewall result (demo-safe)
        unblock_at = datetime.now().timestamp() + Config.BLOCK_DURATION
        db[ip] = {
            "attack_type": attack_type,
            "blocked_at": datetime.now().isoformat(),
            "unblock_at": unblock_at,
            "remaining": Config.BLOCK_DURATION,
        }
        _save_db(db)

    if fw_ok:
        msg = f"Blocked for {Config.BLOCK_DURATION // 60} minutes"
        logger.info(f"BLOCKED {ip} | reason={attack_type} | duration={Config.BLOCK_DURATION}s | firewall=applied")
    else:
        msg = f"Blocked for {Config.BLOCK_DURATION // 60} minutes (demo mode — no firewall)"
        logger.info(f"BLOCKED {ip} | reason={attack_type} | duration={Config.BLOCK_DURATION}s | firewall=demo")

    print(f"[BLOCKER] Blocked {ip} ({attack_type}) — auto-unblock in {Config.BLOCK_DURATION // 60}m"
          f"{'' if fw_ok else ' [demo]'}")

    # Schedule auto-unblock
    timer = threading.Timer(Config.BLOCK_DURATION, unblock_ip, args=[ip])
    timer.daemon = True
    timer.start()

    return True, msg


def unblock_ip(ip: str) -> bool:
    """Remove the block for an IP from the firewall and DB."""
    ip = ip.strip()

    with _db_lock:
        db = _load_db()
        if ip not in db:
            logger.warning(f"Unblock requested for unknown IP: {ip}")
            return False

        # Remove firewall rule (graceful — DB is cleaned regardless)
        _firewall_unblock(ip)

        db.pop(ip, None)
        _save_db(db)

    logger.info(f"UNBLOCKED {ip}")
    print(f"[BLOCKER] Unblocked {ip}")
    return True


def get_blocked_ips() -> list[dict]:
    """Return current blocked IPs with live remaining seconds."""
    now = datetime.now().timestamp()
    with _db_lock:
        db = _load_db()

    result = []
    for ip, info in db.items():
        remaining = max(0, int(info.get("unblock_at", now) - now))
        result.append({
            "ip": ip,
            "attack_type": info.get("attack_type", "Unknown"),
            "blocked_at": info.get("blocked_at", ""),
            "remaining": remaining,
        })
    return result


def _restore_blocks_on_startup():
    """Re-schedules unblock timers for IPs blocked before restart."""
    now = datetime.now().timestamp()
    with _db_lock:
        db = _load_db()

    for ip, info in list(db.items()):
        remaining = info.get("unblock_at", now) - now
        if remaining > 0:
            logger.info(f"Restoring block timer for {ip} — {int(remaining)}s remaining")
            timer = threading.Timer(remaining, unblock_ip, args=[ip])
            timer.daemon = True
            timer.start()
        else:
            unblock_ip(ip)


# ── Run at import ────────────────────────────────────────────────
_restore_blocks_on_startup()
