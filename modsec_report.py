#!/usr/bin/env python3
import re
import smtplib
import requests
import json
import datetime
import os
import sys
import argparse
import io
from functools import lru_cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import optional visualization library
try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    VIZ_ENABLED = True
except ImportError:
    VIZ_ENABLED = False
    print("[WARN] matplotlib not found. Charts will be disabled. Run: pip install matplotlib", file=sys.stderr)

# ==============================
# --- Configuration ---
# ==============================
# Can be overridden by command-line args
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"
# Default date range: last 7 days
END_DATE = datetime.date.today()
START_DATE = END_DATE - datetime.timedelta(days=7)

# Multi-domain recipients map (domain -> email). If empty, falls back to single-domain mode.
RECIPIENTS = {
    # "zpanel.site": "security@zpanel.site",
    # "abc.com": "ops@abc.com",
}
# Fallback for single-domain mode if RECIPIENTS is empty
DEFAULT_DOMAIN = os.environ.get("DOMAIN", "zpanel.site")

# SMTP Credentials (using environment variables is recommended)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "cloud.zergaw.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "security.update@zergaw.com")
SMTP_PASS = os.environ.get("SMTP_PASS") # IMPORTANT: No default password
DEFAULT_TO_EMAIL = os.environ.get("TO_EMAIL", "recipient@example.com")

# Performance & Behavior
EMAIL_WORKERS = int(os.environ.get("EMAIL_WORKERS", "10"))
ENABLE_COUNTRY = os.environ.get("ENABLE_COUNTRY", "1") == "1"
SEND_EMPTY_REPORTS = os.environ.get("SEND_EMPTY_REPORTS", "1") == "1"

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.environ.get("LOGO_PATH") or os.path.join(SCRIPT_DIR, "logo.png")
IP_CACHE_PATH = os.environ.get("IP_CACHE_PATH", "/tmp/ip_country_cache.json")

# GeoIP2 Database (e.g., /path/to/GeoLite2-Country.mmdb)
GEOIP_DB = os.environ.get("GEOIP_DB")
GEOIP_READER = None
# ==============================

# ---------- Utilities ----------
def fmt_num(n):
    """Format integer with thousands separator."""
    try:
        return f"{int(n):,}"
    except (ValueError, TypeError):
        return str(n)

def pct(part, total):
    if not total:
        return "0.0%"
    return f"{(part / total) * 100:.1f}%"

# ---------- GeoIP & Caching ----------
def _init_geoip():
    global GEOIP_READER
    if not ENABLE_COUNTRY or not GEOIP_DB:
        return
    if os.path.isfile(GEOIP_DB):
        try:
            import geoip2.database
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB)
            print(f"[INFO] GeoIP database loaded from {GEOIP_DB}")
        except Exception as e:
            print(f"[WARN] GeoIP init failed: {e}", file=sys.stderr)
    else:
        print(f"[WARN] GEOIP_DB path not found: {GEOIP_DB}", file=sys.stderr)

try:
    with open(IP_CACHE_PATH, "r") as f:
        IP_CACHE = json.load(f)
except Exception:
    IP_CACHE = {}

def _save_ip_cache():
    if IP_CACHE:
        try:
            with open(IP_CACHE_PATH, "w") as f:
                json.dump(IP_CACHE, f)
                print(f"[INFO] IP cache saved to {IP_CACHE_PATH}")
        except Exception as e:
            print(f"[ERROR] Failed to save IP cache: {e}", file=sys.stderr)

def _is_local_ip(ip):
    return (
        ip == "N/A" or ip.startswith(("10.", "192.168.", "127.")) or
        (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31)
    )

def enrich_ips_bulk(ips_to_check: set):
    """Efficiently enriches a set of IPs with country data using cache, local DB, and a batch API fallback."""
    if not ENABLE_COUNTRY:
        return {ip: "Unknown" for ip in ips_to_check}

    ip_to_country = {}
    remaining_ips = set()

    # Step 1: Check cache and local IPs
    for ip in ips_to_check:
        if _is_local_ip(ip):
            ip_to_country[ip] = "Local Network"
        elif ip in IP_CACHE:
            ip_to_country[ip] = IP_CACHE[ip]
        else:
            remaining_ips.add(ip)

    if not remaining_ips:
        return ip_to_country

    # Step 2: Use local GeoIP2 database
    if GEOIP_READER:
        still_unresolved = set()
        for ip in remaining_ips:
            try:
                resp = GEOIP_READER.country(ip)
                country = resp.country.name or "Unknown"
                ip_to_country[ip] = country
                IP_CACHE[ip] = country
            except Exception:
                still_unresolved.add(ip)
        remaining_ips = still_unresolved
    
    if not remaining_ips:
        return ip_to_country

    # Step 3: Fallback to Batch API for any remaining IPs
    print(f"[INFO] Falling back to ip-api.com for {len(remaining_ips)} IPs.")
    api_ips = list(remaining_ips)
    for i in range(0, len(api_ips), 100): # ip-api.com allows up to 100 per batch
        batch = api_ips[i:i+100]
        try:
            resp = requests.post("http://ip-api.com/batch?fields=status,country,query", json=batch, timeout=10)
            resp.raise_for_status()
            for result in resp.json():
                ip = result.get("query")
                country = "Unknown"
                if result.get("status") == "success":
                    country = result.get("country", "Unknown")
                ip_to_country[ip] = country
                IP_CACHE[ip] = country
        except requests.RequestException as e:
            print(f"[ERROR] IP API batch request failed: {e}", file=sys.stderr)
            for ip in batch:
                ip_to_country[ip] = "Unknown" # Mark as unknown on failure

    return ip_to_country

# ---------- Parsing ----------
def _parse_time(block):
    ts_match = re.search(r"\[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2})", block)
    if not ts_match:
        return None
    try:
        return datetime.datetime.strptime(f"{ts_match.group(1)}:{ts_match.group(2)}", "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None

def parse_all_domains():
    """Parse entire log, enrich IPs in bulk, and return a dict of attacks per domain."""
    try:
        with open(LOG_FILE, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read log file {LOG_FILE}: {e}", file=sys.stderr)
        return {}

    by_domain = defaultdict(list)
    all_ips = set()
    
    # First pass: Extract data and collect all unique IPs
    for block in re.split(r"\n--[a-f0-9]+-A--", content):
        if "Host:" not in block:
            continue

        dt = _parse_time(block)
        if not dt or not (START_DATE <= dt.date() <= END_DATE):
            continue
        
        host_m = re.search(r"Host:\s*([^\s]+)", block)
        if not host_m:
            continue
        dom = host_m.group(1).strip().lower()

        ip_match = re.search(r"X-Real-IP:\s*([\d\.]+)") or re.search(r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE)
        attacker_ip = ip_match.group(1) if ip_match else "N/A"
        all_ips.add(attacker_ip)

        req_match = re.search(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS) ([^\s]+) HTTP", block)
        request_line = f"{req_match.group(1)} {req_match.group(2)}" if req_match else "N/A"

        for msg in re.findall(r'\[msg "(.+?)"\]', block):
            by_domain[dom].append({
                "ip": attacker_ip,
                "request": request_line,
                "message": msg,
                "_datetime": dt,
            })

    # Bulk enrich all collected IPs at once
    ip_to_country_map = enrich_ips_bulk(all_ips)

    # Second pass: Apply country data and sort
    for dom, attacks in by_domain.items():
        for attack in attacks:
            attack["country"] = ip_to_country_map.get(attack["ip"], "Unknown")
            attack["date"] = attack["_datetime"].strftime("%d/%b/%Y")
            attack["time"] = attack["_datetime"].strftime("%H:%M:%S")
        attacks.sort(key=lambda a: a["_datetime"], reverse=True)

    return by_domain

# ---------- Stats & Charting ----------
def generate_stats(attacks):
    stats = defaultdict(lambda: defaultdict(int))
    stats["total_attacks"] = len(attacks)

    for attack in attacks:
        stats["attack_types"][attack["message"]] += 1
        stats["top_attackers"][(attack["ip"], attack.get("country", "Unknown"))] += 1
        stats["hourly_distribution"][attack["_datetime"].hour] += 1
        if attack["request"] != "N/A":
            stats["methods"][attack["request"].split()[0]] += 1
        
        msg_lower = attack["message"].lower()
        if any(k in msg_lower for k in ("sql injection", "rce", "remote code execution")):
            stats["by_severity"]["Critical"] += 1
        elif any(k in msg_lower for k in ("xss", "cross-site scripting")):
            stats["by_severity"]["High"] += 1
        elif any(k in msg_lower for k in ("injection", "traversal", "file inclusion")):
            stats["by_severity"]["Medium"] += 1
        else:
            stats["by_severity"]["Low"] += 1

    stats["top_5_attack_types"] = sorted(stats["attack_types"].items(), key=lambda x: x[1], reverse=True)[:5]
    stats["top_5_attackers"] = sorted(stats["top_attackers"].items(), key=lambda x: x[1], reverse=True)[:5]
    return stats

def generate_chart_image(stats_data):
    """Generates a horizontal bar chart image from stats data."""
    if not VIZ_ENABLED or not stats_data:
        return None

    labels = [text[:40] + '...' if len(text) > 40 else text for text, count in stats_data]
    counts = [count for text, count in stats_data]
    
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=110)
    bars = ax.barh(labels, counts, color='#e74c3c')
    ax.invert_yaxis()

    ax.set_title('Top 5 Attack Types', fontsize=14, weight='bold')
    ax.tick_params(axis='y', labelsize=9)
    ax.tick_params(axis='x', labelsize=8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#dddddd')
    ax.spines['bottom'].set_color('#dddddd')
    
    # Add counts on bars
    for bar in bars:
        width = bar.get_width()
        ax.text(width + (max(counts) * 0.01), bar.get_y() + bar.get_height()/2, f'{width:,}', ha='left', va='center', fontsize=8)

    ax.set_xlim(right=max(counts) * 1.15) # Make space for labels
    fig.tight_layout()
    
    img_buffer = io.BytesIO()
    fig.savefig(img_buffer, format='png', bbox_inches='tight')
    plt.close(fig)
    img_buffer.seek(0)
    return img_buffer.read()

# ---------- HTML Report ----------
def build_html_report(domain, attacks, stats, chart_image_data):
    # This function remains largely the same, but now accepts chart_image_data
    # and has a placeholder for the chart image.
    
    # (HTML building code from the original script, with one key change)
    
    # In place of the old HTML bar chart loop:
    attack_types_chart_html = ""
    if chart_image_data and VIZ_ENABLED:
        attack_types_chart_html = '<img src="cid:attack_chart" alt="Top Attack Types Chart" style="width:100%; max-width:600px; height:auto;"/>'
    else: # Fallback to simple HTML if viz is disabled
        for msg, count in stats["top_5_attack_types"]:
            percentage = (count / stats["total_attacks"]) * 100 if stats["total_attacks"] else 0
            attack_types_chart_html += f"""
            <div style="margin-bottom: 10px; font-size: 13px;">
                <div>{msg}</div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <div style="width:100%; background:#eee; border-radius:3px;"><div style="width:{percentage}%; height:12px; background:#e74c3c; border-radius:3px;"></div></div>
                    <div style="white-space:nowrap;">{fmt_num(count)} ({percentage:.1f}%)</div>
                </div>
            </div>"""

    # ... The rest of the HTML template ...
    # Be sure to insert {attack_types_chart_html} in the right place.
    
    # This is a placeholder for the full HTML generation logic.
    # To keep this response clean, I am not re-printing the entire 200+ line HTML string.
    # The full logic from the original script should be used, replacing the attack types chart section.
    
    # --- Start of condensed HTML Template ---
    return f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background:#f5f5f5; margin:0; padding:0; }}
            .container {{ max-width: 900px; margin: auto; padding: 20px; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
            h2 {{ border-bottom: 2px solid #eee; padding-bottom: 8px; color:#333; }}
            table {{ width:100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; vertical-align: top; font-size: 13px; }}
            th {{ background-color: #f4f4f4; }}
            .header {{ display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card header">...Header Content...</div>
            <div class="card">
                <h2>Security Overview</h2>
                <p><strong>Total Attacks:</strong> {fmt_num(stats["total_attacks"])}</p>
                ...Other stats...
            </div>
            <div class="card">
                <h2>Top Attack Types</h2>
                {attack_types_chart_html}
            </div>
            <div class="card">
                <h2>Top Attackers</h2>
                ...Attackers Table...
            </div>
            <div class="card">
                <h2>Recent Attacks</h2>
                ...Recent Attacks Table...
            </div>
            <div class="card">...Footer...</div>
        </div>
    </body>
    </html>
    """ # --- End of condensed HTML Template ---


# ---------- Email ----------
def send_email(subject, html_content, to_email, attachments=None):
    """Sends an email with optional image attachments."""
    related = MIMEMultipart("related")
    related["From"] = SMTP_USER
    related["To"] = to_email
    related["Subject"] = subject

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText("Please view this email in HTML format.", "plain"))
    alt.attach(MIMEText(html_content, "html"))
    related.attach(alt)

    # Attach images (logo, chart, etc.)
    if attachments:
        for cid, img_data in attachments.items():
            mime_image = MIMEImage(img_data)
            mime_image.add_header("Content-ID", f"<{cid}>")
            related.attach(mime_image)
            
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_email, related.as_string())

# ---------- Driver ----------
def process_and_send_reports(reports_to_process):
    """Generates reports and sends emails concurrently."""
    with ThreadPoolExecutor(max_workers=EMAIL_WORKERS) as executor:
        futs = []
        for r in reports_to_process:
            domain, attacks, to_email = r["domain"], r["attacks"], r["to_email"]
            
            if not attacks and not SEND_EMPTY_REPORTS:
                print(f"[INFO] Skipping empty report for {domain}")
                continue

            stats = generate_stats(attacks)
            chart_img = generate_chart_image(stats.get("top_5_attack_types"))
            
            html = build_html_report(domain, attacks, stats, chart_img)
            subj = f"Weekly Security Update for {domain} - {END_DATE.strftime('%b %d, %Y')}"
            
            attachments = {}
            if os.path.isfile(LOGO_PATH):
                with open(LOGO_PATH, "rb") as f:
                    attachments["logo"] = f.read()
            if chart_img:
                attachments["attack_chart"] = chart_img

            futs.append(executor.submit(send_email, subj, html, to_email, attachments))
            
        for f in as_completed(futs):
            try:
                f.result()  # Propagate errors
            except Exception as e:
                print(f"[ERROR] An email failed to send: {e}", file=sys.stderr)
    
    print(f"Processed {len(reports_to_process)} domains.")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Parse ModSecurity logs and email security reports.")
    parser.add_argument('--log-file', type=str, default=LOG_FILE, help="Path to the modsec_audit.log file.")
    parser.add_argument('--days', type=int, default=7, help="Number of past days to analyze.")
    args = parser.parse_args()
    
    global LOG_FILE, START_DATE
    LOG_FILE = args.log_file
    START_DATE = END_DATE - datetime.timedelta(days=args.days)
    
    print(f"Analyzing logs from {START_DATE} to {END_DATE}")

    if not SMTP_PASS:
        print("[ERROR] SMTP_PASS environment variable not set. Exiting.", file=sys.stderr)
        sys.exit(1)
        
    _init_geoip()
    
    all_domain_attacks = parse_all_domains()
    reports = []
    
    # Multi-domain mode
    if RECIPIENTS:
        # Include domains from logs AND from recipient list to handle no-attack cases
        all_relevant_domains = set(all_domain_attacks.keys()) | set(RECIPIENTS.keys())
        for dom in all_relevant_domains:
            to_email = RECIPIENTS.get(dom, DEFAULT_TO_EMAIL)
            reports.append({"domain": dom, "attacks": all_domain_attacks.get(dom, []), "to_email": to_email})
    # Single-domain mode
    else:
        attacks = all_domain_attacks.get(DEFAULT_DOMAIN.lower(), [])
        reports.append({"domain": DEFAULT_DOMAIN, "attacks": attacks, "to_email": DEFAULT_TO_EMAIL})
        
    if reports:
        process_and_send_reports(reports)

if __name__ == "__main__":
    try:
        main()
    finally:
        # Ensure the cache is always saved on exit
        _save_ip_cache()
