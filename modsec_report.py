#!/usr/bin/env python3
import re
import smtplib
import requests
from functools import lru_cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from collections import defaultdict
import datetime
import os
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================
# Config (customize as needed)
# ==============================
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"

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

# Logo: expects logo.png in same folder as this script by default
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.environ.get("LOGO_PATH") or os.path.join(SCRIPT_DIR, "logo.png")

# GeoIP2
GEOIP_DB = os.environ.get("GEOIP_DB")  # /path/to/GeoLite2-Country.mmdb
IP_CACHE_PATH = os.environ.get("IP_CACHE_PATH", "/tmp/ip_country_cache.json")

# Date Range (default: last 7 days)
END_DATE = datetime.date.today()
START_DATE = END_DATE - datetime.timedelta(days=7)

# Toggle country enrichment quickly
ENABLE_COUNTRY = os.environ.get("ENABLE_COUNTRY", "1") == "1"
# ==============================

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

# tiny persistent cache across runs
try:
    with open(IP_CACHE_PATH, "r") as _f:
        IP_CACHE = json.load(_f)
except Exception:
    IP_CACHE = {}

def _save_ip_cache():
    try:
        with open(IP_CACHE_PATH, "w") as _f:
            json.dump(IP_CACHE, _f)
    except Exception:
        pass

@lru_cache(maxsize=50000)
def _country_from_geoip(ip):
    if GEOIP_READER is None:
        return None
    try:
        resp = GEOIP_READER.country(ip)
        return resp.country.name or "Unknown"
    except Exception:
        return None

def get_ip_country(ip):
    """Return country name for given IP (local/private handled)."""
    if not ENABLE_COUNTRY:
        return "Unknown"

    if (
        ip == "N/A"
        or ip.startswith("10.")
        or ip.startswith("192.168")
        or ip.startswith("172.")
        or ip.startswith("127.")
    ):
        return "Local Network"

    # fast cache
    if ip in IP_CACHE:
        return IP_CACHE[ip]

    # local db
    country = _country_from_geoip(ip)
    if country:
        IP_CACHE[ip] = country
        _save_ip_cache()
        return country

    # tiny-timeout fallback (HTTP)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country", timeout=1.5)
        data = resp.json()
        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            IP_CACHE[ip] = country
            _save_ip_cache()
            return country
    except Exception:
        pass

    IP_CACHE[ip] = "Unknown"
    _save_ip_cache()
    return "Unknown"

# ---------- Parsing ----------
def _iter_blocks(content):
    # Split by audit part A boundaries
    return re.split(r"\n--[a-f0-9]+-A--", content)

def _extract_attack_entries(block):
    """Yield attack dicts from a single ModSecurity block (already filtered by date)."""
    # IP
    attacker_ip = "N/A"
    ip_match = re.search(r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE) \
               or re.search(r"X-Real-IP:\s*([\d\.]+)", block)
    if ip_match:
        attacker_ip = ip_match.group(1)

    # Method + path
    req_match = re.search(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS) ([^\s]+) HTTP", block)
    request_line = f"{req_match.group(1)} {req_match.group(2)}" if req_match else "N/A"

    # Messages
    messages = re.findall(r'\[msg "(.+?)"\]', block)
    for msg in messages:
        yield attacker_ip, request_line, msg

def _parse_time(block):
    ts_match = re.search(r"\[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2})", block)
    if not ts_match:
        return None
    date_str, time_str = ts_match.groups()
    try:
        dt = datetime.datetime.strptime(f"{date_str}:{time_str}", "%d/%b/%Y:%H:%M:%S")
        return dt
    except ValueError:
        return None

def parse_all_domains():
    """Parse entire log once; return dict[domain] = [attacks]."""
    try:
        with open(LOG_FILE, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] cannot read log file {LOG_FILE}: {e}", file=sys.stderr)
        return {}

    by_domain = defaultdict(list)
    for block in _iter_blocks(content):
        if "Host:" not in block:
            continue

        # domain
        host_m = re.search(r"Host:\s*([^\s]+)", block)
        if not host_m:
            continue
        dom = host_m.group(1).strip().lower()

        # timestamp filter
        dt = _parse_time(block)
        if not dt or not (START_DATE <= dt.date() <= END_DATE):
            continue

        for ip, request_line, msg in _extract_attack_entries(block):
            by_domain[dom].append({
                "date": dt.strftime("%d/%b/%Y"),
                "time": dt.strftime("%H:%M:%S"),
                "ip": ip,
                "request": request_line,
                "message": msg,
                "_datetime": dt,
            })

    # Country enrichment (bulk unique IPs)
    if ENABLE_COUNTRY:
        all_ips = {a["ip"] for lst in by_domain.values() for a in lst if a["ip"] != "N/A"}
        ip2country = {ip: get_ip_country(ip) for ip in all_ips}
    else:
        ip2country = {}

    for dom, lst in by_domain.items():
        for a in lst:
            a["country"] = ip2country.get(a["ip"], "Unknown")
        lst.sort(key=lambda a: a["_datetime"], reverse=True)

    return by_domain

def parse_single_domain(target_domain):
    """Compatibility: parse only one domain (legacy behavior)."""
    by_domain = parse_all_domains()
    return by_domain.get(target_domain.lower(), [])

# ---------- Stats ----------
def generate_stats(attacks):
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

        # hour
        try:
            dt = datetime.datetime.strptime(f"{attack['date']} {attack['time']}", "%d/%b/%Y %H:%M:%S")
            stats["hourly_distribution"][dt.hour] += 1
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

    stats["top_5_attack_types"] = sorted(
        stats["attack_types"].items(), key=lambda x: x[1], reverse=True
    )[:5]
    stats["top_5_attackers"] = sorted(
        stats["top_attackers"].items(), key=lambda x: x[1], reverse=True
    )[:5]
    return stats

# ---------- HTML ----------
def build_html_report(domain, attacks, stats):
    subtitle = "Zergaw Cloud WAF Security Update"

    # logo referenced by CID in the email; fallback text if missing
    logo_html = f'<div style="font-size:20px;font-weight:bold;">{domain}</div>'
    if os.path.isfile(LOGO_PATH):
        # Reduced from 70px to 35px (~50%)
        logo_html = '<img src="cid:logo" alt="Logo" style="height:35px; object-fit:contain;">'
    else:
        print(f"[WARN] logo file not found at {LOGO_PATH}", file=sys.stderr)

    # Split title styles: prefix vs domain
    title_text_html = (
        '<span style="font-size:18px; font-weight:normal;">Weekly security update for your site:</span> '
        f'<span style="font-size:22px; font-weight:bold; color:#222;">{domain}</span>'
    )

    if not attacks:
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background:#f5f5f5; }}
                .container {{ max-width: 900px; margin: auto; padding: 20px; }}
                .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
                h2 {{ margin-top:0; }}
                .header {{ display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }}
                .title-block {{ flex:1; min-width:220px; }}
                .small {{ font-size:12px; color:#666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header -->
                <div class="card">
                    <div class="header">
                        <div style="flex:0 0 auto;">
                            {logo_html}
                        </div>
                        <div class="title-block">
                            <div style="margin-bottom:4px;">{title_text_html}</div>
                            <div style="font-size:16px; color:#444; margin-bottom:6px;">{subtitle}</div>
                            <div class="small">Report from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong></div>
                        </div>
                    </div>
                </div>

                <!-- No events -->
                <div class="card">
                    <h2>{subtitle}</h2>
                    <p>This is a weekly security update for <strong>{domain}</strong>. There were no recorded security events from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong>.</p>
                </div>

                <!-- Footer -->
                <div class="card" style="text-align:right; font-size:11px; color:#666;">
                    <div>Generated on {datetime.datetime.now().strftime("%d/%b/%Y")}</div>
                    <div style="margin-top:4px;">Time: {datetime.datetime.now().strftime("%H:%M:%S")}</div>
                    <div style="margin-top:6px; font-weight:bold;">Zergaw Cloud</div>
                </div>
            </div>
        </body>
        </html>
        """

    severity_counts = {
        "Critical": stats["by_severity"].get("Critical", 0),
        "High": stats["by_severity"].get("High", 0),
        "Medium": stats["by_severity"].get("Medium", 0),
        "Low": stats["by_severity"].get("Low", 0),
    }
    total = stats["total_attacks"]

    severity_cards = f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0;">
        <div style="background: linear-gradient(135deg, #ff4d4d, #ff1a1a); padding: 15px; border-radius: 8px; color: white; text-align: center;">
            <div style="font-size: 12px; opacity: 0.9;">CRITICAL</div>
            <div style="font-size: 24px; font-weight: bold;">{fmt_num(severity_counts['Critical'])}</div>
            <div style="font-size: 11px;">{pct(severity_counts['Critical'], total)}</div>
        </div>
        <div style="background: linear-gradient(135deg, #ff9966, #ff5e62); padding: 15px; border-radius: 8px; color: white; text-align: center;">
            <div style="font-size: 12px; opacity: 0.9;">HIGH</div>
            <div style="font-size: 24px; font-weight: bold;">{fmt_num(severity_counts['High'])}</div>
            <div style="font-size: 11px;">{pct(severity_counts['High'], total)}</div>
        </div>
        <div style="background: linear-gradient(135deg, #ffcc00, #ffaa00); padding: 15px; border-radius: 8px; color: white; text-align: center;">
            <div style="font-size: 12px; opacity: 0.9;">MEDIUM</div>
            <div style="font-size: 24px; font-weight: bold;">{fmt_num(severity_counts['Medium'])}</div>
            <div style="font-size: 11px;">{pct(severity_counts['Medium'], total)}</div>
        </div>
        <div style="background: linear-gradient(135deg, #66cc66, #2eb82e); padding: 15px; border-radius: 8px; color: white; text-align: center;">
            <div style="font-size: 12px; opacity: 0.9;">LOW</div>
            <div style="font-size: 24px; font-weight: bold;">{fmt_num(severity_counts['Low'])}</div>
            <div style="font-size: 11px;">{pct(severity_counts['Low'], total)}</div>
        </div>
    </div>
    """

    attack_types_chart = ""
    for msg, count in stats["top_5_attack_types"]:
        percentage = (count / total) * 100 if total else 0
        attack_types_chart += f"""
        <div style="margin-bottom: 15px;">
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
                <span>{msg}</span>
                <span>{fmt_num(count)} ({percentage:.1f}%)</span>
            </div>
            <div style="height: 8px; background-color: #ddd; border-radius: 4px; overflow: hidden;">
                <div style="height: 100%; width: {percentage}%; background-color: #e74c3c;"></div>
            </div>
        </div>
        """

    top_attackers_rows = "".join(
        f"<tr><td>{ip}<br><small>{country}</small></td>"
        f"<td>{fmt_num(count)}</td>"
        f"<td>{pct(count, total)}</td></tr>"
        for (ip, country), count in stats["top_5_attackers"]
    )

    recent_attacks_rows = "".join(
        f"""
        <tr>
            <td>
                <div>{atk['date']}</div>
                <div style="font-size:11px; color:#777;">{atk['time']}</div>
            </td>
            <td>{atk['ip']}<br><small>{atk.get('country','Unknown')}</small></td>
            <td style="word-break:break-word;">{atk['request']}</td>
            <td style="word-break:break-word;">{atk['message']}</td>
            <td><span style="background-color:#e74c3c;color:white;padding:2px 8px;border-radius:12px;">BLOCKED</span></td>
        </tr>
        """
        for atk in attacks[:10]
    )

    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background:#f5f5f5; }}
            .container {{ max-width: 900px; margin: auto; padding: 20px; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
            h2 {{ border-bottom: 2px solid #eee; padding-bottom: 8px; color:#333; }}
            table {{ width:100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; vertical-align: top; }}
            th {{ background-color: #f4f4f4; font-size: 13px; }}
            tr:nth-child(even) {{ background-color: #fafafa; }}
            td {{ font-size: 13px; }}
            .header {{ display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }}
            .title-block {{ flex:1; min-width:220px; }}
            .small {{ font-size:12px; color:#666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Header -->
            <div class="card">
                <div class="header">
                    <div style="flex:0 0 auto;">
                        {logo_html}
                    </div>
                    <div class="title-block">
                        <div style="margin-bottom:4px;">{title_text_html}</div>
                        <div style="font-size:16px; color:#444; margin-bottom:6px;">{subtitle}</div>
                        <div class="small">Report from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong></div>
                    </div>
                </div>
            </div>

            <!-- Overview -->
            <div class="card">
                <h2>Security Overview</h2>
                <p><strong>Total Attacks:</strong> {fmt_num(stats["total_attacks"])}</p>
                <p><strong>Unique Attack Types:</strong> {fmt_num(len(stats["attack_types"]))}</p>
                <p><strong>Unique Attackers:</strong> {fmt_num(len(stats["top_attackers"]))}</p>
                {severity_cards}
            </div>

            <!-- Top Attack Types -->
            <div class="card">
                <h2>Top Attack Types</h2>
                {attack_types_chart}
            </div>

            <!-- Top Attackers -->
            <div class="card">
                <h2>Top Attackers</h2>
                <table>
                    <thead><tr><th>IP Address</th><th>Requests</th><th>Percentage</th></tr></thead>
                    <tbody>{top_attackers_rows}</tbody>
                </table>
            </div>

            <!-- Recent Attacks -->
            <div class="card">
                <h2>Recent Attacks</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Date / Time</th><th>IP</th><th>Request</th><th>Message</th><th>Status</th>
                        </tr>
                    </thead>
                    <tbody>{recent_attacks_rows}</tbody>
                </table>
            </div>

            <!-- Footer -->
            <div class="card" style="text-align:right; font-size:11px; color:#666;">
                <div>Generated on {datetime.datetime.now().strftime("%d/%b/%Y")}</div>
                <div style="margin-top:4px;">Time: {datetime.datetime.now().strftime("%H:%M:%S")}</div>
                <div style="margin-top:6px; font-weight:bold;">Zergaw Cloud</div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ---------- Email ----------
def send_email(subject, html_content, to_email, logo_path=LOGO_PATH):
    related = MIMEMultipart("related")
    related["From"] = SMTP_USER
    related["To"] = to_email
    related["Subject"] = subject

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText("Please view this email in HTML format.", "plain"))
    alt.attach(MIMEText(html_content, "html"))
    related.attach(alt)

    # Attach logo inline if available
    if os.path.isfile(logo_path):
        try:
            with open(logo_path, "rb") as imgf:
                img_data = imgf.read()
            mime_image = MIMEImage(img_data)
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
def send_many(reports):
    """reports: list of dicts {domain, to_email, attacks}"""
    with ThreadPoolExecutor(max_workers=EMAIL_WORKERS) as ex:
        futs = []
        for r in reports:
            stats = generate_stats(r["attacks"])
            html = build_html_report(r["domain"], r["attacks"], stats)
            subj = f"Weekly Security Update for your site: {r['domain']} - {datetime.datetime.now().strftime('%b %d, %Y')}"
            futs.append(ex.submit(send_email, subj, html, r["to_email"], LOGO_PATH))
        for f in as_completed(futs):
            f.result()  # propagate errors

def main():
    _init_geoip()

    # Multi-domain mode if RECIPIENTS provided; else single domain
    if RECIPIENTS:
        by_domain = parse_all_domains()
        reports = []
        for dom, attacks in by_domain.items():
            to_email = RECIPIENTS.get(dom, DEFAULT_TO_EMAIL)
            reports.append({"domain": dom, "to_email": to_email, "attacks": attacks})
        if not reports:
            # If no domains found, you might still want a "no events" mail per known recipient
            for dom, to_email in RECIPIENTS.items():
                reports.append({"domain": dom, "to_email": to_email, "attacks": []})
        send_many(reports)
        print(f"Sent {len(reports)} reports.")
    else:
        # single-domain fallback (compatible with your original flow)
        attacks = parse_single_domain(DOMAIN)
        stats = generate_stats(attacks)
        html_report = build_html_report(DOMAIN, attacks, stats)
        subject = f"Weekly Security Update for your site: {DOMAIN} - {datetime.datetime.now().strftime('%b %d, %Y')}"
        send_email(subject, html_report, DEFAULT_TO_EMAIL, LOGO_PATH)
        print(f"Report sent to {DEFAULT_TO_EMAIL} with {len(attacks)} attack entries for {DOMAIN}.")

if __name__ == "__main__":
    main()
