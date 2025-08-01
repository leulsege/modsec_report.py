#!/usr/bin/env python3
import re
import smtplib
import requests
from functools import lru_cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
import datetime

# Config
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"
DOMAIN = "zpanel.site"
SMTP_SERVER = "cloud.zergaw.com"
SMTP_PORT = 587
SMTP_USER = "security.update@zergaw.com"
SMTP_PASS = "YOUR_PASSWORD"
TO_EMAIL = "recipient@example.com"

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
    """Parse ModSecurity log for the given domain."""
    with open(LOG_FILE, "r", errors="ignore") as f:
        content = f.read()

    blocks = re.split(r"\n--[a-f0-9]+-A--", content)
    attacks = []

    for block in blocks:
        if f"Host: {DOMAIN}" not in block:
            continue

        ts_match = re.search(
            r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})", block
        )
        timestamp = ts_match.group(1) if ts_match else "N/A"

        ip_match = re.search(
            r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE
        )
        if not ip_match:
            ip_match = re.search(r"X-Real-IP:\s*([\d\.]+)", block)
        attacker_ip = ip_match.group(1) if ip_match else "N/A"

        country = get_ip_country(attacker_ip)  # 🌍 Get country here

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
                    "time": timestamp,
                    "ip": attacker_ip,
                    "country": country,
                    "request": request_line,
                    "message": msg,
                }
            )

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

        if attack["time"] != "N/A":
            try:
                dt = datetime.datetime.strptime(
                    attack["time"], "%d/%b/%Y:%H:%M:%S"
                )
                stats["hourly_distribution"][dt.hour] += 1
            except:
                pass

        if attack["request"] != "N/A":
            method = attack["request"].split()[0]
            stats["methods"][method] += 1

        if "SQL Injection" in attack["message"]:
            stats["by_severity"]["High"] += 1
        elif "XSS" in attack["message"]:
            stats["by_severity"]["Medium"] += 1
        else:
            stats["by_severity"]["Low"] += 1

    stats["top_5_attack_types"] = sorted(
        stats["attack_types"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    stats["top_5_attackers"] = sorted(
        stats["top_attackers"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    return stats

def build_html_report(attacks, stats):
    if not attacks:
        return f"<html><body><h1>No Security Events</h1></body></html>"

    attack_types_chart = ""
    for msg, count in stats["top_5_attack_types"]:
        percentage = (count / stats["total_attacks"]) * 100
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

    # Top Attackers
    top_attackers_rows = "".join(
        f"<tr><td>{ip}<br><small>[{country}]</small></td><td>{count}</td><td>{(count / stats['total_attacks']) * 100:.1f}%</td></tr>"
        for (ip, country), count in stats["top_5_attackers"]
    )

    # Recent Attacks
    recent_attacks_rows = "".join(
        f"""
        <tr>
            <td>{atk['time']}</td>
            <td>{atk['ip']}<br><small>[{atk['country']}]</small></td>
            <td style="word-break:break-word;">{atk['request']}</td>
            <td style="word-break:break-word;">{atk['message']}</td>
            <td><span style="background-color:#e74c3c;color:white;padding:2px 8px;border-radius:12px;">BLOCKED</span></td>
        </tr>
        """
        for atk in attacks[:10]
    )

    # HTML
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h2>Security Overview</h2>
                <p><strong>Total Attacks:</strong> {stats["total_attacks"]}</p>
                <p><strong>Unique Attack Types:</strong> {len(stats["attack_types"])}</p>
                <p><strong>Unique Attackers:</strong> {len(stats["top_attackers"])}</p>
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
                            <th>Time</th><th>IP</th><th>Request</th><th>Message</th><th>Status</th>
                        </tr>
                    </thead>
                    <tbody>{recent_attacks_rows}</tbody>
                </table>
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
    send_email(
        f"Security Threat Report - {DOMAIN} - {datetime.datetime.now().strftime('%b %d')}",
        html_report,
    )
    print(
        f"Report sent to {TO_EMAIL} with {len(attacks)} attack entries."
    )

if __name__ == "__main__":
    main()
