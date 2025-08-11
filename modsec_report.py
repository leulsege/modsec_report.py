#!/usr/bin/env python3
import re
import smtplib
import requests
from functools import lru_cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from collections import defaultdict
import datetime as dt
from datetime import datetime, timedelta
import os
import sys
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional

# ==============================
# Config (customize as needed)
# ==============================
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"
CACHE_DIR = "/tmp/modsec_analyzer_cache"
LOG_CACHE_FILE = os.path.join(CACHE_DIR, "log_cache.json")

# Toggle incremental reads: 0 = full file scan for the date window (recommended)
INCREMENTAL = int(os.environ.get("INCREMENTAL", "0"))
LOG_POSITION_FILE = os.path.join(CACHE_DIR, "log_position.txt")

# Single-domain mode (leave DOMAIN set to use this mode)
DOMAIN = os.environ.get("DOMAIN", "zpanel.site")  # e.g., "abc.com"

# Multi-domain recipients map (domain -> email). If empty, falls back to single-domain mode.
RECIPIENTS = {
    # "zpanel.site": "security@zpanel.site",
    # "abc.com": "ops@abc.com",
}

SMTP_SERVER = os.environ.get("SMTP_SERVER", "cloud.zergaw.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "security.update@zergaw.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "YOUR_PASSWORD")
DEFAULT_TO_EMAIL = os.environ.get("TO_EMAIL", "recipient@example.com")

EMAIL_WORKERS = int(os.environ.get("EMAIL_WORKERS", "10"))

# Limits (0 = unlimited)
RECENT_LIMIT = int(os.environ.get("RECENT_LIMIT", "50"))
TOP_ATTACKERS_LIMIT = int(os.environ.get("TOP_ATTACKERS_LIMIT", "20"))

# Logo: expects logo.png in same folder as this script by default
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.environ.get("LOGO_PATH") or os.path.join(SCRIPT_DIR, "logo.png")

# GeoIP2
GEOIP_DB = os.environ.get("GEOIP_DB")  # /path/to/GeoLite2-Country.mmdb
IP_CACHE_PATH = os.path.join(CACHE_DIR, "ip_country_cache.json")

# Date Range (default: last 7 days)
END_DATE = dt.date.today()
START_DATE = END_DATE - dt.timedelta(days=7)

# Toggle country enrichment quickly
ENABLE_COUNTRY = os.environ.get("ENABLE_COUNTRY", "1") == "1"

# Cache settings
LOG_CACHE_TTL = 3600  # seconds
# ==============================

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# ---------- Utilities ----------
def fmt_num(n):
    """Format integer with thousands separator."""
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)

def pct(part, total):
    if not total:
        return "0.0%"
    return f"{(part / total) * 100:.1f}%"

def get_file_hash(filepath: str) -> str:
    """Get MD5 hash of file contents for change detection."""
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_file_position(filepath: str) -> int:
    """Get last read position from cache."""
    try:
        with open(LOG_POSITION_FILE, "r") as f:
            data = json.load(f)
            if data.get('file') == filepath:
                return data.get('position', 0)
    except Exception:
        pass
    return 0

def _atomic_write_json(path: str, obj: dict) -> None:
    """Write JSON atomically to avoid partial/corrupt files."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(obj, f)
    os.replace(tmp_path, path)

def save_file_position(filepath: str, position: int) -> None:
    """Save last read position to cache."""
    try:
        _atomic_write_json(LOG_POSITION_FILE, {'file': filepath, 'position': position})
    except Exception:
        pass

# ---------- GeoIP ----------
GEOIP_READER = None
def _init_geoip():
    global GEOIP_READER
    if not ENABLE_COUNTRY:
        return
    if GEOIP_DB and os.path.isfile(GEOIP_DB):
        try:
            import geoip2.database
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB)
        except Exception as e:
            print(f"[WARN] GeoIP init failed: {e}", file=sys.stderr)

# Persistent IP cache with automatic saving
class IPCache:
    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self.cache = self._load_cache()
        
    def _load_cache(self) -> Dict[str, str]:
        try:
            with open(self.cache_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}
            
    def get(self, ip: str) -> Optional[str]:
        return self.cache.get(ip)
        
    def set(self, ip: str, country: str) -> None:
        self.cache[ip] = country
        
    def save(self) -> None:
        try:
            _atomic_write_json(self.cache_path, self.cache)
        except Exception:
            pass

IP_CACHE = IPCache(IP_CACHE_PATH)

@lru_cache(maxsize=100000)
def _country_from_geoip(ip: str) -> Optional[str]:
    if GEOIP_READER is None:
        return None
    try:
        resp = GEOIP_READER.country(ip)
        return resp.country.name or "Unknown"
    except Exception:
        return None

def get_ip_country(ip: str) -> str:
    """Return country name for given IP (local/private handled)."""
    if not ENABLE_COUNTRY:
        return "Unknown"

    if ip == "N/A":
        return "Local Network"

    def _is_private(ip_):
        try:
            a, b, *_ = [int(x) for x in ip_.split(".")]
        except Exception:
            return False
        if a == 10:
            return True
        if a == 192 and b == 168:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 127:
            return True
        return False

    if _is_private(ip):
        return "Local Network"

    cached = IP_CACHE.get(ip)
    if cached is not None:
        return cached

    country = _country_from_geoip(ip)
    if country:
        IP_CACHE.set(ip, country)
        return country

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country", timeout=1.0)
        data = resp.json()
        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            IP_CACHE.set(ip, country)
            return country
    except Exception:
        pass

    IP_CACHE.set(ip, "Unknown")
    return "Unknown"

# ---------- Parsing ----------
def _iter_blocks(content: str) -> List[str]:
    """Split log content into transaction blocks."""
    return re.split(r"\n--[a-f0-9]+-A--", content)

def _extract_attack_entries(block: str) -> List[Tuple[str, str, str]]:
    """Extract attack entries from a single ModSecurity block."""
    ip_match = (
        re.search(r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE) or
        re.search(r"X-Real-IP:\s*([\d\.]+)", block)
    )
    attacker_ip = ip_match.group(1) if ip_match else "N/A"

    req_match = re.search(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS) ([^\s]+) HTTP", block)
    request_line = f"{req_match.group(1)} {req_match.group(2)}" if req_match else "N/A"

    messages = re.findall(r'\[msg "(.+?)"\]', block)
    return [(attacker_ip, request_line, msg) for msg in messages]

def _parse_time(block: str) -> Optional[datetime]:
    ts_match = re.search(r"\[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2})", block)
    if not ts_match:
        return None
    date_str, time_str = ts_match.groups()
    try:
        return datetime.strptime(f"{date_str}:{time_str}", "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None

def _parse_log_content(content: str) -> Dict[str, List[dict]]:
    by_domain: Dict[str, List[dict]] = defaultdict(list)
    for block in _iter_blocks(content):
        if "Host:" not in block:
            continue

        host_m = re.search(r"Host:\s*([^\s]+)", block)
        if not host_m:
            continue
        dom = host_m.group(1).strip().lower().split(":")[0]

        dt_obj = _parse_time(block)
        if not dt_obj or not (START_DATE <= dt_obj.date() <= END_DATE):
            continue

        for ip, request_line, msg in _extract_attack_entries(block):
            by_domain[dom].append({
                "date": dt_obj.strftime("%d/%b/%Y"),
                "time": dt_obj.strftime("%H:%M:%S"),
                "ip": ip,
                "request": request_line,
                "message": msg,
                "_datetime": dt_obj,
            })

    return by_domain

def _read_log_content() -> str:
    if not INCREMENTAL:
        with open(LOG_FILE, "r", errors="ignore") as f:
            return f.read()

    file_size = os.path.getsize(LOG_FILE)
    last_position = get_file_position(LOG_FILE)
    with open(LOG_FILE, "r", errors="ignore") as f:
        if 0 < last_position < file_size:
            f.seek(last_position)
            content = f.read()
        else:
            content = f.read()
        try:
            save_file_position(LOG_FILE, file_size)
        except Exception:
            pass
        return content

def parse_all_domains() -> Dict[str, List[dict]]:
    current_hash = ""
    try:
        current_hash = get_file_hash(LOG_FILE)
    except Exception:
        pass

    try:
        if os.path.exists(LOG_CACHE_FILE):
            with open(LOG_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
            ts = cache_data.get("timestamp")
            start_ok = cache_data.get("start_date") == START_DATE.isoformat()
            end_ok = cache_data.get("end_date") == END_DATE.isoformat()
            hash_ok = (not current_hash) or (cache_data.get("hash") == current_hash)
            if ts and start_ok and end_ok and hash_ok:
                ts_dt = datetime.fromisoformat(ts)
                if (datetime.now() - ts_dt).total_seconds() <= LOG_CACHE_TTL:
                    return cache_data["data"]
    except Exception as e:
        print(f"[WARN] Cache load failed: {e}", file=sys.stderr)

    try:
        content = _read_log_content()
        by_domain = _parse_log_content(content)
    except Exception as e:
        print(f"[ERROR] cannot read/parse log file {LOG_FILE}: {e}", file=sys.stderr)
        return {}

    if ENABLE_COUNTRY:
        all_ips = {a["ip"] for lst in by_domain.values() for a in lst if a["ip"] != "N/A"}
        ip2country = {ip: get_ip_country(ip) for ip in all_ips}
    else:
        ip2country = {}

    for dom, lst in by_domain.items():
        for a in lst:
            a["country"] = ip2country.get(a["ip"], "Unknown")
        lst.sort(key=lambda a: a["_datetime"], reverse=True)

    try:
        safe_by_domain: Dict[str, List[dict]] = {}
        for dom, lst in by_domain.items():
            safe_by_domain[dom] = [
                {k: v for k, v in a.items() if k != "_datetime"} for a in lst
            ]
        payload = {
            'hash': current_hash,
            'start_date': START_DATE.isoformat(),
            'end_date': END_DATE.isoformat(),
            'data': safe_by_domain,
            'timestamp': datetime.now().isoformat()
        }
        _atomic_write_json(LOG_CACHE_FILE, payload)
    except Exception as e:
        print(f"[WARN] Cache save failed: {e}", file=sys.stderr)

    return by_domain

def parse_single_domain(target_domain: str) -> List[dict]:
    by_domain = parse_all_domains()
    return by_domain.get(target_domain.lower(), [])

# ---------- Stats ----------
def generate_stats(attacks: List[dict]) -> dict:
    stats = {
        "total_attacks": len(attacks),
        "attack_types": defaultdict(int),
        "top_attackers": defaultdict(int),
        "hourly_distribution": defaultdict(int),
        "methods": defaultdict(int),
        "by_severity": defaultdict(int),
    }

    for attack in attacks:
        stats["attack_types"][attack["message"]] += 1
        stats["top_attackers"][(attack["ip"], attack.get("country", "Unknown"))] += 1

        try:
            dtp = datetime.strptime(f"{attack['date']} {attack['time']}", "%d/%b/%Y %H:%M:%S")
            stats["hourly_distribution"][dtp.hour] += 1
        except Exception:
            pass

        if attack["request"] != "N/A":
            method = attack["request"].split()[0]
            stats["methods"][method] += 1

        msg_lower = attack["message"].lower()
        if any(k in msg_lower for k in ("sql injection", "rce", "remote code execution")):
            stats["by_severity"]["Critical"] += 1
        elif any(k in msg_lower for k in ("xss", "cross-site scripting")):
            stats["by_severity"]["High"] += 1
        elif any(k in msg_lower for k in ("injection", "traversal", "file inclusion")):
            stats["by_severity"]["Medium"] += 1
        else:
            stats["by_severity"]["Low"] += 1

    top_types = sorted(stats["attack_types"].items(), key=lambda x: x[1], reverse=True)
    top_attackers = sorted(stats["top_attackers"].items(), key=lambda x: x[1], reverse=True)

    stats["top_5_attack_types"] = top_types[:5]
    stats["_all_attackers_sorted"] = top_attackers
    return stats

# ---------- EMAIL HTML HELPERS ----------
def _logo_block_html() -> str:
    """Logo with fixed width using table and inline styles (email-safe)."""
    return """
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
  <tr>
    <td align="left" valign="middle" style="padding:0; margin:0;">
      <img src="cid:logo" alt="Logo" width="120" height="auto"
           style="display:block; max-width:120px; height:auto; border:0; outline:none; text-decoration:none; -ms-interpolation-mode:bicubic;" />
    </td>
  </tr>
</table>
""".strip()

def _header_table_html(domain: str, subtitle: str, start_date: dt.date, end_date: dt.date) -> str:
    """Table-based header with logo and titles."""
    logo_html = _logo_block_html()
    return f"""
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;">
  <tr>
    <td style="padding: 20px; border:1px solid #eee; border-radius:8px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
        <tr>
          <td width="140" valign="middle" style="padding-right:20px;">
            {logo_html}
          </td>
          <td valign="middle">
            <div style="font-family: Arial, sans-serif; font-size:16px; color:#444; margin:0; padding:0;">
              Weekly security update for your site:
            </div>
            <div style="font-family: Arial, sans-serif; font-size:22px; font-weight:bold; color:#222; margin:4px 0 6px 0;">
              {domain}
            </div>
            <div style="font-family: Arial, sans-serif; font-size:14px; color:#444; margin:0 0 6px 0;">
              {subtitle}
            </div>
            <div style="font-family: Arial, sans-serif; font-size:12px; color:#666; margin:0;">
              Report from <strong>{start_date}</strong> to <strong>{end_date}</strong>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
""".strip()

def _severity_cards_html(counts: dict, total: int) -> str:
    """Gradient severity cards using tables + inline styles (as per your original look)."""
    def card(title, count, gradient_css):
        return f"""
<td valign="top" width="25%" style="padding:6px;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:separate; border-radius:8px;">
    <tr>
      <td align="center" style="padding:12px; border-radius:8px; color:#ffffff; {gradient_css}">
        <div style="font-family:Arial, sans-serif; font-size:12px; opacity:0.9;">{title}</div>
        <div style="font-family:Arial, sans-serif; font-size:24px; font-weight:bold; line-height:28px;">{fmt_num(count)}</div>
        <div style="font-family:Arial, sans-serif; font-size:11px; opacity:0.9;">{pct(count, total)}</div>
      </td>
    </tr>
  </table>
</td>
"""
    # same gradients as you used before
    gradients = {
        "CRITICAL": "background: linear-gradient(135deg, #ff4d4d, #ff1a1a);",
        "HIGH":     "background: linear-gradient(135deg, #ff9966, #ff5e62);",
        "MEDIUM":   "background: linear-gradient(135deg, #ffcc00, #ffaa00);",
        "LOW":      "background: linear-gradient(135deg, #66cc66, #2eb82e);",
    }
    return f"""
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin-top:8px;">
  <tr>
    {card("CRITICAL", counts.get("Critical", 0), gradients["CRITICAL"])}
    {card("HIGH",     counts.get("High", 0),     gradients["HIGH"])}
    {card("MEDIUM",   counts.get("Medium", 0),   gradients["MEDIUM"])}
    {card("LOW",      counts.get("Low", 0),      gradients["LOW"])}
  </tr>
</table>
""".strip()

# ---------- HTML BUILDER ----------
def build_html_report(domain: str, attacks: List[dict], stats: dict) -> str:
    subtitle = "Zergaw Cloud WAF Security Update"
    header_html = _header_table_html(domain, subtitle, START_DATE, END_DATE)

    if not attacks:
        return f"""
        <html>
        <head>
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0; padding:0; background:#f5f5f5;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr>
              <td align="center" style="padding:24px;">
                <table role="presentation" width="900" cellspacing="0" cellpadding="0" border="0" style="background:#ffffff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.05);">
                  <tr><td style="padding:0 20px 20px 20px;">{header_html}</td></tr>
                  <tr>
                    <td style="padding:20px; font-family:Arial, sans-serif; font-size:14px; color:#333;">
                      <h2 style="margin:0 0 12px 0; font-size:18px; font-weight:bold; color:#333;">{subtitle}</h2>
                      <p style="margin:0;">This is a weekly security update for <strong>{domain}</strong>. There were no recorded security events from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong>.</p>
                    </td>
                  </tr>
                  <tr>
                    <td align="right" style="padding:16px 20px; font-family:Arial, sans-serif; font-size:11px; color:#666; border-top:1px solid #eee;">
                      <div>Generated on {datetime.now().strftime("%d/%b/%Y")}</div>
                      <div style="margin-top:4px;">Time: {datetime.now().strftime("%H:%M:%S")}</div>
                      <div style="margin-top:6px; font-weight:bold;">Zergaw Cloud</div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

    # Severity cards
    severity_counts = {
        "Critical": stats["by_severity"].get("Critical", 0),
        "High":     stats["by_severity"].get("High", 0),
        "Medium":   stats["by_severity"].get("Medium", 0),
        "Low":      stats["by_severity"].get("Low", 0),
    }
    total = stats["total_attacks"]
    severity_cards_html = _severity_cards_html(severity_counts, total)

    # Top attack types chart rows (table-based)
    def bar_row(msg, count):
        percentage = (count / total) * 100 if total else 0
        return f"""
        <tr>
          <td style="padding:6px 0; font-family:Arial, sans-serif; font-size:13px; color:#333;">{msg}</td>
          <td align="right" style="padding:6px 0; font-family:Arial, sans-serif; font-size:13px; color:#333; white-space:nowrap;">{fmt_num(count)} ({percentage:.1f}%)</td>
        </tr>
        <tr>
          <td colspan="2" style="padding:0 0 10px 0;">
            <div style="height:8px; background-color:#ddd; border-radius:4px; overflow:hidden;">
              <div style="height:8px; width:{percentage}%; background-color:#e74c3c;"></div>
            </div>
          </td>
        </tr>
        """

    attack_types_chart = "".join(bar_row(msg, count) for msg, count in stats["top_5_attack_types"])

    # Top attackers
    attackers_sorted = stats.get("_all_attackers_sorted", [])
    if TOP_ATTACKERS_LIMIT > 0:
        attackers_sorted = attackers_sorted[:TOP_ATTACKERS_LIMIT]

    top_attackers_rows = "".join(
        f"<tr>"
        f"<td style='padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;'>{ip}<br><span style='font-size:11px; color:#777;'>{country}</span></td>"
        f"<td style='padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;'>{fmt_num(count)}</td>"
        f"<td style='padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;'>{pct(count, total)}</td>"
        f"</tr>"
        for (ip, country), count in attackers_sorted
    )

    # Recent attacks
    recent_attacks = attacks if RECENT_LIMIT == 0 else attacks[:RECENT_LIMIT]
    recent_attacks_rows = "".join(
        f"""
        <tr>
          <td style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;">
            <div>{atk['date']}</div>
            <div style="font-size:11px; color:#777;">{atk['time']}</div>
          </td>
          <td style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;">
            {atk['ip']}<br><span style="font-size:11px; color:#777;">{atk.get('country','Unknown')}</span>
          </td>
          <td style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd; word-break:break-word;">{atk['request']}</td>
          <td style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd; word-break:break-word;">{atk['message']}</td>
          <td style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; border:1px solid #ddd;">
            <span style="background-color:#e74c3c;color:#fff;padding:2px 8px;border-radius:12px; display:inline-block;">BLOCKED</span>
          </td>
        </tr>
        """
        for atk in recent_attacks
    )

    # Full HTML (table-based layout)
    return f"""
    <html>
    <head>
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin:0; padding:0; background:#f5f5f5;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
        <tr>
          <td align="center" style="padding:24px;">
            <table role="presentation" width="900" cellspacing="0" cellpadding="0" border="0" style="background:#ffffff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.05);">
              <tr><td style="padding:0 20px 20px 20px;">{header_html}</td></tr>

              <!-- Overview -->
              <tr>
                <td style="padding:20px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;">
                    <tr>
                      <td colspan="2" style="font-family:Arial, sans-serif; font-size:18px; font-weight:bold; color:#333; padding-bottom:8px; border-bottom:2px solid #eee;">Security Overview</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 0; font-family:Arial, sans-serif; font-size:14px; color:#333;">
                        <strong>Total Attacks:</strong> {fmt_num(stats["total_attacks"])}
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <strong>Unique Attack Types:</strong> {fmt_num(len(stats["attack_types"]))}
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <strong>Unique Attackers:</strong> {fmt_num(len(stats["top_attackers"]))}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding-top:8px;">
                        {severity_cards_html}
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Top Attack Types -->
              <tr>
                <td style="padding:0 20px 20px 20px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="font-family:Arial, sans-serif; font-size:18px; font-weight:bold; color:#333; padding:0 0 8px 0; border-bottom:2px solid #eee;">Top Attack Types</td>
                    </tr>
                    {attack_types_chart}
                  </table>
                </td>
              </tr>

              <!-- Top Attackers -->
              <tr>
                <td style="padding:0 20px 20px 20px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="font-family:Arial, sans-serif; font-size:18px; font-weight:bold; color:#333; padding:0 0 8px 0; border-bottom:2px solid #eee;">Top Attackers</td>
                    </tr>
                    <tr>
                      <td>
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;">
                          <tr>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">IP Address</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Requests</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Percentage</th>
                          </tr>
                          {top_attackers_rows}
                        </table>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Recent Attacks -->
              <tr>
                <td style="padding:0 20px 20px 20px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="font-family:Arial, sans-serif; font-size:18px; font-weight:bold; color:#333; padding:0 0 8px 0; border-bottom:2px solid #eee;">Recent Attacks</td>
                    </tr>
                    <tr>
                      <td>
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;">
                          <tr>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Date / Time</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">IP</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Request</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Message</th>
                            <th align="left" style="padding:10px; font-family:Arial, sans-serif; font-size:13px; color:#333; background:#f4f4f4; border:1px solid #ddd;">Status</th>
                          </tr>
                          {recent_attacks_rows}
                        </table>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td align="right" style="padding:16px 20px; font-family:Arial, sans-serif; font-size:11px; color:#666; border-top:1px solid #eee;">
                  <div>Generated on {datetime.now().strftime("%d/%b/%Y")}</div>
                  <div style="margin-top:4px;">Time: {datetime.now().strftime("%H:%M:%S")}</div>
                  <div style="margin-top:6px; font-weight:bold;">Zergaw Cloud</div>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

# ---------- Email ----------
def send_email(subject: str, html_content: str, to_email: str, logo_path: str = LOGO_PATH) -> None:
    related = MIMEMultipart("related")
    related["From"] = SMTP_USER
    related["To"] = to_email
    related["Subject"] = subject

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText("Please view this email in HTML format.", "plain"))
    alt.attach(MIMEText(html_content, "html"))
    related.attach(alt)

    if os.path.isfile(logo_path):
        try:
            with open(logo_path, "rb") as imgf:
                mime_image = MIMEImage(imgf.read())
                mime_image.add_header("Content-ID", "<logo>")
                mime_image.add_header("Content-Disposition", "inline", filename=os.path.basename(logo_path))
                related.attach(mime_image)
        except Exception as e:
            print(f"[WARN] failed to attach logo image: {e}", file=sys.stderr)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_email, related.as_string())

# ---------- Driver ----------
def send_many(reports: List[dict]) -> None:
    with ThreadPoolExecutor(max_workers=EMAIL_WORKERS) as ex:
        futures = []
        for r in reports:
            stats = generate_stats(r["attacks"])
            html = build_html_report(r["domain"], r["attacks"], stats)
            subj = f"Weekly Security Update for your site: {r['domain']} - {datetime.now().strftime('%b %d, %Y')}"
            futures.append(ex.submit(send_email, subj, html, r["to_email"], LOGO_PATH))
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[ERROR] Failed to send email: {e}", file=sys.stderr)

def main():
    _init_geoip()
    try:
        if RECIPIENTS:
            by_domain = parse_all_domains()
            reports = []
            for dom, to_email in RECIPIENTS.items():
                attacks = by_domain.get(dom.lower(), [])
                reports.append({"domain": dom, "to_email": to_email, "attacks": attacks})
            send_many(reports)
            print(f"Sent {len(reports)} reports for configured domains: {', '.join(RECIPIENTS.keys())}")
        else:
            attacks = parse_single_domain(DOMAIN)
            stats = generate_stats(attacks)
            html_report = build_html_report(DOMAIN, attacks, stats)
            subject = f"Weekly Security Update for your site: {DOMAIN} - {datetime.now().strftime('%b %d, %Y')}"
            send_email(subject, html_report, DEFAULT_TO_EMAIL, LOGO_PATH)
            print(f"Report sent to {DEFAULT_TO_EMAIL} with {len(attacks)} attack entries for {DOMAIN}.")
    finally:
        IP_CACHE.save()

if __name__ == "__main__":
    main()
