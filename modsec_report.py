#!/usr/bin/env python3 
import re
import smtplib
import requests
from functools import lru_cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
import datetime

# ==============================
# Config
# ==============================
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"
DOMAIN = "zpanel.site"  # replace with the actual domain, e.g., "abc.com"
SMTP_SERVER = "cloud.zergaw.com"
SMTP_PORT = 587
SMTP_USER = "security.update@zergaw.com"
SMTP_PASS = "YOUR_PASSWORD"
TO_EMAIL = "recipient@example.com"

# Date Range (Default: last 7 days)
END_DATE = datetime.date.today()
START_DATE = END_DATE - datetime.timedelta(days=7)
# ==============================

# 🌍 Get country for IP with caching
@lru_cache(maxsize=200)
def get_ip_country(ip):
    """Return country name for given IP."""
    if (
        ip == "N/A"
        or ip.startswith("10.")
        or ip.startswith("192.168")
        or ip.startswith("172.")
        or ip.startswith("127.")
    ):
        return "Local Network"
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country", timeout=3
        )
        data = resp.json()
        if data.get("status") == "success":
            return data.get("country", "Unknown")
    except:
        pass
    return "Unknown"

def parse_modsec_log():
    """Parse ModSecurity log for the given domain and date range."""
    with open(LOG_FILE, "r", errors="ignore") as f:
        content = f.read()

    blocks = re.split(r"\n--[a-f0-9]+-A--", content)
    attacks = []

    for block in blocks:
        if f"Host: {DOMAIN}" not in block:
            continue

        # Extract timestamp
        ts_match = re.search(
            r"\[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2})", block
        )
        if not ts_match:
            continue

        timestamp_str = ts_match.group(1)  # Example: 01/Aug/2025
        time_str = ts_match.group(2)       # Example: 11:43:15

        try:
            attack_datetime = datetime.datetime.strptime(
                f"{timestamp_str}:{time_str}", "%d/%b/%Y:%H:%M:%S"
            )
        except ValueError:
            continue

        # Filter by date range
        if not (START_DATE <= attack_datetime.date() <= END_DATE):
            continue

        attacker_ip = "N/A"
        ip_match = re.search(
            r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE
        )
        if not ip_match:
            ip_match = re.search(r"X-Real-IP:\s*([\d\.]+)", block)
        if ip_match:
            attacker_ip = ip_match.group(1)

        country = get_ip_country(attacker_ip)  # 🌍 Get country

        req_match = re.search(
            r"(GET|POST|HEAD|PUT|DELETE|OPTIONS) ([^\s]+) HTTP", block
        )
        request_line = (
            f"{req_match.group(1)} {req_match.group(2)}"
            if req_match
            else "N/A"
        )

        messages = re.findall(r'\[msg "(.+?)"\]', block)
        if not messages:
            continue

        for msg in messages:
            attacks.append(
                {
                    "date": attack_datetime.strftime("%d/%b/%Y"),  # ✅ date only
                    "time": attack_datetime.strftime("%H:%M:%S"),  # ✅ time only
                    "ip": attacker_ip,
                    "country": country,
                    "request": request_line,
                    "message": msg,
                    "_datetime": attack_datetime,  # for sorting
                }
            )

    # sort newest first
    attacks.sort(key=lambda a: a["_datetime"], reverse=True)
    return attacks

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
        stats["top_attackers"][(attack["ip"], attack["country"])] += 1

        try:
            dt = datetime.datetime.strptime(f"{attack['date']} {attack['time']}", "%d/%b/%Y %H:%M:%S")
            stats["hourly_distribution"][dt.hour] += 1
        except:
            pass

        if attack["request"] != "N/A":
            method = attack["request"].split()[0]
            stats["methods"][method] += 1

        # Enhanced severity classification
        msg_lower = attack["message"].lower()
        if "sql injection" in msg_lower or "rce" in msg_lower or "remote code execution" in msg_lower:
            stats["by_severity"]["Critical"] += 1
        elif "xss" in msg_lower or "cross-site scripting" in msg_lower:
            stats["by_severity"]["High"] += 1
        elif "injection" in msg_lower or "traversal" in msg_lower or "file inclusion" in msg_lower:
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

def build_html_report(attacks, stats):
    title_text = f"Weekly security update for your site: {DOMAIN}"
    subtitle = "Zergaw Cloud WAF Security Update"
    date_range_str = f"{START_DATE} to {END_DATE}"

    if not attacks:
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background:#f5f5f5; }}
                .container {{ max-width: 900px; margin: auto; padding: 20px; }}
                .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
                h1 {{ margin:0; }}
                .header {{ display: flex; align-items: center; gap: 20px; }}
                .small {{ font-size:12px; color:#666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card header">
                    <div style="flex:0 0 auto;">
                        <img src="https://office.zergaw.com/web/image/website/1/logo/" alt="Logo" style="height:60px; object-fit:contain;">
                    </div>
                    <div style="flex:1;">
                        <div style="font-size:20px; font-weight:bold;">{title_text}</div>
                        <div style="font-size:14px; margin-top:4px;">{subtitle}</div>
                        <div class="small" style="margin-top:6px;">Report from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong></div>
                    </div>
                </div>
                <div class="card">
                    <h2>No Security Events</h2>
                    <p>This is a weekly security update for <strong>{DOMAIN}</strong>. There were no recorded security events from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong>.</p>
                </div>
            </div>
        </body>
        </html>
        """

    # Calculate severity counts
    severity_counts = {
        "Critical": stats["by_severity"].get("Critical", 0),
        "High": stats["by_severity"].get("High", 0),
        "Medium": stats["by_severity"].get("Medium", 0),
        "Low": stats["by_severity"].get("Low", 0)
    }

    # Severity cards HTML
    severity_cards = f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0;">
        <div style="background: linear-gradient(135deg, #ff4d4d, #ff1a1a); padding: 15px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="font-size: 12px; opacity: 0.9;">CRITICAL</div>
            <div style="font-size: 24px; font-weight: bold;">{severity_counts['Critical']}</div>
            <div style="font-size: 11px;">{(severity_counts['Critical']/stats['total_attacks'])*100:.1f}%</div>
        </div>
        <div style="background: linear-gradient(135deg, #ff9966, #ff5e62); padding: 15px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="font-size: 12px; opacity: 0.9;">HIGH</div>
            <div style="font-size: 24px; font-weight: bold;">{severity_counts['High']}</div>
            <div style="font-size: 11px;">{(severity_counts['High']/stats['total_attacks'])*100:.1f}%</div>
        </div>
        <div style="background: linear-gradient(135deg, #ffcc00, #ffaa00); padding: 15px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="font-size: 12px; opacity: 0.9;">MEDIUM</div>
            <div style="font-size: 24px; font-weight: bold;">{severity_counts['Medium']}</div>
            <div style="font-size: 11px;">{(severity_counts['Medium']/stats['total_attacks'])*100:.1f}%</div>
        </div>
        <div style="background: linear-gradient(135deg, #66cc66, #2eb82e); padding: 15px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="font-size: 12px; opacity: 0.9;">LOW</div>
            <div style="font-size: 24px; font-weight: bold;">{severity_counts['Low']}</div>
            <div style="font-size: 11px;">{(severity_counts['Low']/stats['total_attacks'])*100:.1f}%</div>
        </div>
    </div>
    """

    attack_types_chart = ""
    for msg, count in stats["top_5_attack_types"]:
        percentage = (count / stats["total_attacks"]) * 100 if stats["total_attacks"] else 0
        attack_types_chart += f"""
        <div style="margin-bottom: 15px;">
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
                <span>{msg}</span>
                <span>{count} ({percentage:.1f}%)</span>
            </div>
            <div style="height: 8px; background-color: #ddd; border-radius: 4px; overflow: hidden;">
                <div style="height: 100%; width: {percentage}%; background-color: #e74c3c;"></div>
            </div>
        </div>
        """

    top_attackers_rows = "".join(
        f"<tr><td>{ip}<br><small>{country}</small></td><td>{count}</td><td>{(count / stats['total_attacks']) * 100:.1f}%</td></tr>"
        for (ip, country), count in stats["top_attackers"]
    )

    recent_attacks_rows = "".join(
        f"""
        <tr>
            <td>
                <div>{atk['date']}</div>
                <div style="font-size:11px; color:#777;">{atk['time']}</div>
            </td>
            <td>{atk['ip']}<br><small>{atk['country']}</small></td>
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
            <!-- Header with logo and title -->
            <div class="card">
                <div class="header">
                    <div style="flex:0 0 auto;">
                        <img src="https://office.zergaw.com/web/image/website/1/logo/" alt="Logo" style="height:70px; object-fit:contain;">
                    </div>
                    <div class="title-block">
                        <div style="font-size:22px; font-weight:bold; margin-bottom:4px;">{title_text}</div>
                        <div style="font-size:16px; color:#444; margin-bottom:6px;">{subtitle}</div>
                        <div class="small">Report from <strong>{START_DATE}</strong> to <strong>{END_DATE}</strong></div>
                    </div>
                </div>
            </div>

            <!-- Overview / Security Update -->
            <div class="card">
                <h2>{subtitle}</h2>
                <p><strong>Total Attacks:</strong> {stats["total_attacks"]}</p>
                <p><strong>Unique Attack Types:</strong> {len(stats["attack_types"])}</p>
                <p><strong>Unique Attackers:</strong> {len(stats["top_attackers"])}</p>
                
                {severity_cards}
            </div>

            <div class="card">
                <h2>Top Attack Types</h2>
                {attack_types_chart}
            </div>

            <div class="card">
                <h2>Top Attackers</h2>
                <table>
                    <thead><tr><th>IP Address</th><th>Requests</th><th>Percentage</th></tr></thead>
                    <tbody>{top_attackers_rows}</tbody>
                </table>
            </div>

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

            <div class="card" style="text-align:right; font-size:11px; color:#666;">
                <div>Generated on {datetime.datetime.now().strftime("%d/%b/%Y")}</div>
                <div style="margin-top:4px;">Time: {datetime.datetime.now().strftime("%H:%M:%S")}</div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def send_email(subject, html_content):
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_USER
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText("Please view this email in HTML format.", "plain"))
    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, TO_EMAIL, msg.as_string())

def main():
    attacks = parse_modsec_log()
    stats = generate_stats(attacks)
    html_report = build_html_report(attacks, stats)
    subject = f"Weekly Security Update for your site: {DOMAIN} - {datetime.datetime.now().strftime('%b %d, %Y')}"
    send_email(
        subject,
        html_report,
    )
    print(
        f"Report sent to {TO_EMAIL} with {len(attacks)} attack entries."
    )

if __name__ == "__main__":
    main()
