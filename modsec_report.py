#!/usr/bin/env python3
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Config
LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"
DOMAIN = "zpanel.site"
SMTP_SERVER = "mail.zergaw.com"
SMTP_PORT = 587
SMTP_USER = "security.update@zergaw.com"
SMTP_PASS = "YOUR_PASSWORD"  # Change to your password
TO_EMAIL = "recipient@example.com"  # Change to your target email

def parse_modsec_log():
    """Parse ModSecurity log for the given domain and return list of attack records."""
    with open(LOG_FILE, "r", errors="ignore") as f:
        content = f.read()

    # Split into ModSecurity blocks
    blocks = re.split(r"\n--[a-f0-9]+-A--", content)

    attacks = []
    for block in blocks:
        if f"Host: {DOMAIN}" not in block:
            continue

        # Timestamp
        ts_match = re.search(r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})", block)
        timestamp = ts_match.group(1) if ts_match else "N/A"

        # Attacker IP - first try from -A-- section header, then X-Real-IP
        ip_match = re.search(r"^\[.*?\]\s+[a-zA-Z0-9]+\s+([\d\.]+)\s", block, re.MULTILINE)
        if not ip_match:
            ip_match = re.search(r"X-Real-IP:\s*([\d\.]+)", block)
        attacker_ip = ip_match.group(1) if ip_match else "N/A"

        # Request method + URI
        req_match = re.search(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS) ([^\s]+) HTTP", block)
        request_line = f"{req_match.group(1)} {req_match.group(2)}" if req_match else "N/A"

        # Rule message(s) only
        messages = re.findall(r'\[msg "(.+?)"\]', block)
        if not messages:
            continue

        for msg in messages:
            attacks.append({
                "time": timestamp,
                "ip": attacker_ip,
                "request": request_line,
                "message": msg
            })

    return attacks

def build_html_table(attacks):
    """Build HTML table from attack records."""
    if not attacks:
        return f"<p>No ModSecurity events found for {DOMAIN}.</p>"

    rows = ""
    for atk in attacks:
        rows += f"""
        <tr>
            <td>{atk['time']}</td>
            <td>{atk['ip']}</td>
            <td>{atk['request']}</td>
            <td>{atk['message']}</td>
        </tr>
        """

    html = f"""
    <html>
    <body>
        <h2>ModSecurity Attack Summary for {DOMAIN}</h2>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th>Time</th>
                <th>Attacker IP</th>
                <th>Request</th>
                <th>Message</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """
    return html

def send_email(subject, html_content):
    """Send email via SMTP."""
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_USER
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, TO_EMAIL, msg.as_string())

def main():
    attacks = parse_modsec_log()
    html_report = build_html_table(attacks)
    send_email(f"ModSecurity Attack Report - {DOMAIN}", html_report)
    print(f"Report sent to {TO_EMAIL} with {len(attacks)} attack entries.")

if __name__ == "__main__":
    main()
