#!/usr/bin/env python3
import re
import smtplib
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
SMTP_PASS = "YOUR_PASSWORD"  # Change to your real password
TO_EMAIL = "recipient@example.com"  # Where to send the report

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

        # Attacker IP - First try from -A-- section header, then from X-Real-IP
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

def generate_stats(attacks):
    """Generate statistics from attack data."""
    stats = {
        "total_attacks": len(attacks),
        "attack_types": defaultdict(int),
        "top_attackers": defaultdict(int),
        "hourly_distribution": defaultdict(int),
        "methods": defaultdict(int),
        "by_severity": defaultdict(int)
    }
    
    for attack in attacks:
        stats["attack_types"][attack["message"]] += 1
        stats["top_attackers"][attack["ip"]] += 1
        
        # Parse time if available
        if attack["time"] != "N/A":
            try:
                dt = datetime.datetime.strptime(attack["time"], "%d/%b/%Y:%H:%M:%S")
                stats["hourly_distribution"][dt.hour] += 1
            except:
                pass
        
        # Get HTTP method
        if attack["request"] != "N/A":
            method = attack["request"].split()[0]
            stats["methods"][method] += 1
        
        # Categorize by severity (simple example)
        if "SQL Injection" in attack["message"]:
            stats["by_severity"]["High"] += 1
        elif "XSS" in attack["message"]:
            stats["by_severity"]["Medium"] += 1
        else:
            stats["by_severity"]["Low"] += 1
    
    # Sort and get top 5
    stats["top_5_attack_types"] = sorted(stats["attack_types"].items(), key=lambda x: x[1], reverse=True)[:5]
    stats["top_5_attackers"] = sorted(stats["top_attackers"].items(), key=lambda x: x[1], reverse=True)[:5]
    
    return stats

def build_hourly_chart(hourly_data):
    """Build AM/PM hourly distribution chart."""
    max_count = max(hourly_data.values()) if hourly_data else 1
    
    def build_hour_row(start, end, period):
        row_html = f"""
        <div style="margin-bottom: 15px;">
            <div style="font-size: 12px; color: #7f8c8d; margin-bottom: 8px; font-weight: 600;">{period}</div>
            <div style="display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 10px;">
        """
        
        for hour in range(start, end+1):
            count = hourly_data.get(hour, 0)
            height = (count / max_count) * 50 if max_count > 0 else 0
            display_hour = hour if hour <= 12 else hour - 12
            if hour == 0:
                display_hour = 12
            
            row_html += f"""
            <div style="text-align: center; width: 30px;">
                <div style="height: {height}px; background-color: #3498db; margin-bottom: 3px; border-radius: 3px 3px 0 0;"></div>
                <small>{display_hour}</small>
            </div>
            """
        
        row_html += "</div></div>"
        return row_html
    
    # Build AM (12am-11am) and PM (12pm-11pm) sections
    return build_hour_row(0, 11, "AM") + build_hour_row(12, 23, "PM")

def build_html_report(attacks, stats):
    """Build beautiful HTML report with charts and tables."""
    if not attacks:
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa;">
            <div style="max-width: 800px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px;">
                <h1 style="color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px;">ModSecurity Report</h1>
                <p>No security events detected for {DOMAIN} during the reporting period.</p>
            </div>
        </body>
        </html>
        """

    # Generate HTML for charts
    attack_types_chart = ""
    for msg, count in stats["top_5_attack_types"]:
        percentage = (count / stats["total_attacks"]) * 100
        attack_types_chart += f"""
        <div style="margin-bottom: 15px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 13px;">
                <span style="color: #2c3e50;">{msg[:50]}{'...' if len(msg) > 50 else ''}</span>
                <span style="font-weight: 600; color: #7f8c8d;">{count} ({percentage:.1f}%)</span>
            </div>
            <div style="height: 8px; background-color: #e0e0e0; border-radius: 4px; overflow: hidden;">
                <div style="height: 100%; width: {percentage}%; background-color: #e74c3c; border-radius: 4px;"></div>
            </div>
        </div>
        """
    
    hourly_chart = build_hourly_chart(stats["hourly_distribution"])
    
    # Generate HTML for top attackers table
    top_attackers_rows = ""
    for ip, count in stats["top_5_attackers"]:
        top_attackers_rows += f"""
        <tr>
            <td style="font-family: 'Courier New', monospace;">{ip}</td>
            <td>{count}</td>
            <td>{(count / stats["total_attacks"]) * 100:.1f}%</td>
        </tr>
        """
    
    # Generate HTML for recent attacks table
    recent_attacks_rows = ""
    for atk in attacks[:10]:  # Show only last 10 attacks in detail
        recent_attacks_rows += f"""
        <tr>
            <td>{atk['time']}</td>
            <td style="font-family: 'Courier New', monospace;">{atk['ip']}</td>
            <td>{atk['request'][:50]}{'...' if len(atk['request']) > 50 else ''}</td>
            <td>{atk['message'][:50]}{'...' if len(atk['message']) > 50 else ''}</td>
            <td><span style="color: white; background-color: #e74c3c; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600;">BLOCKED</span></td>
        </tr>
        """
    
    # Severity distribution
    severity_distribution = ""
    for severity, count in stats["by_severity"].items():
        color = {
            "High": "#e74c3c",
            "Medium": "#f39c12",
            "Low": "#f1c40f"
        }.get(severity, "#95a5a6")
        
        severity_distribution += f"""
        <div style="display: inline-block; width: 32%; text-align: center;">
            <div style="font-size: 24px; font-weight: bold; color: {color};">{count}</div>
            <div style="font-size: 12px; color: #7f8c8d; text-transform: uppercase;">{severity}</div>
        </div>
        """
    
    # Main HTML template
    html = f"""
    <html>
    <head>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&family=Courier+New&display=swap');
            body {{ 
                font-family: 'Open Sans', sans-serif; 
                margin: 0; 
                padding: 0; 
                background-color: #f5f7fa; 
                color: #333; 
                line-height: 1.5;
            }}
            .container {{ 
                max-width: 900px; 
                margin: 0 auto; 
                padding: 20px; 
            }}
            .card {{ 
                background-color: white; 
                border-radius: 8px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.05); 
                padding: 25px; 
                margin-bottom: 25px; 
            }}
            .card-header {{ 
                border-bottom: 1px solid #eee; 
                padding-bottom: 10px; 
                margin-bottom: 15px; 
                color: #2c3e50;
                font-size: 18px;
                font-weight: 600;
            }}
            .stats-grid {{ 
                display: grid; 
                grid-template-columns: repeat(3, 1fr); 
                gap: 15px; 
                margin-bottom: 20px; 
            }}
            .stat-box {{ 
                background-color: #f8f9fa; 
                padding: 15px; 
                border-radius: 6px; 
                text-align: center; 
            }}
            .stat-value {{ 
                font-size: 24px; 
                font-weight: bold; 
                color: #2c3e50; 
                margin: 5px 0; 
            }}
            .stat-label {{ 
                font-size: 12px; 
                color: #7f8c8d; 
                text-transform: uppercase; 
            }}
            table {{ 
                width: 100%; 
                border-collapse: collapse; 
                font-size: 14px;
            }}
            th {{ 
                text-align: left; 
                background-color: #f8f9fa; 
                padding: 12px 10px; 
                font-size: 13px; 
                text-transform: uppercase; 
                color: #7f8c8d; 
                font-weight: 600;
            }}
            td {{ 
                padding: 12px 10px; 
                border-bottom: 1px solid #eee; 
                vertical-align: top;
            }}
            .badge {{ 
                display: inline-block; 
                padding: 3px 8px; 
                border-radius: 12px; 
                font-size: 12px; 
                font-weight: 600; 
                text-transform: uppercase;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Header -->
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #2c3e50; margin-bottom: 5px; font-size: 24px;">Security Threat Report</h1>
                <p style="color: #7f8c8d; margin-top: 0; font-size: 14px;">
                    {DOMAIN} • {datetime.datetime.now().strftime('%B %d, %Y %H:%M')}
                </p>
            </div>
            
            <!-- Overview Card -->
            <div class="card">
                <h2 class="card-header">Security Overview</h2>
                
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-value" style="color: #e74c3c;">{stats["total_attacks"]}</div>
                        <div class="stat-label">Total Attacks Blocked</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{len(stats["attack_types"])}</div>
                        <div class="stat-label">Unique Attack Types</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{len(stats["top_attackers"])}</div>
                        <div class="stat-label">Unique Attackers</div>
                    </div>
                </div>
                
                <!-- Severity Distribution -->
                <div style="text-align: center; margin: 20px 0;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 15px; color: #7f8c8d;">
                        ATTACK SEVERITY DISTRIBUTION
                    </h3>
                    <div>
                        {severity_distribution}
                    </div>
                </div>
                
                <!-- Charts Row -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-top: 20px;">
                    <div>
                        <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 15px; color: #7f8c8d;">
                            TOP ATTACK TYPES
                        </h3>
                        {attack_types_chart}
                    </div>
                    <div>
                        <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 15px; color: #7f8c8d;">
                            HOURLY DISTRIBUTION
                        </h3>
                        {hourly_chart}
                    </div>
                </div>
            </div>
            
            <!-- Top Attackers Card -->
            <div class="card">
                <h2 class="card-header">Top Attackers</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Requests</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {top_attackers_rows}
                    </tbody>
                </table>
            </div>
            
            <!-- Recent Attacks Card -->
            <div class="card">
                <h2 class="card-header">Recent Attack Attempts</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Request</th>
                            <th>Message</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {recent_attacks_rows}
                    </tbody>
                </table>
                <p style="text-align: center; margin-top: 15px; color: #7f8c8d; font-size: 13px;">
                    Showing 10 of {len(attacks)} total attacks • Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
            
            <!-- Footer -->
            <div style="text-align: center; margin-top: 30px; color: #95a5a6; font-size: 12px;">
                <p>This is an automated security report. Please review any critical items.</p>
                <p>© {datetime.datetime.now().year} Security Team • {DOMAIN}</p>
            </div>
        </div>
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
    
    # Attach both HTML and plain text versions
    msg.attach(MIMEText("Please view this email in an HTML-compatible client to see the security report.", "plain"))
    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, TO_EMAIL, msg.as_string())

def main():
    attacks = parse_modsec_log()
    stats = generate_stats(attacks)
    html_report = build_html_report(attacks, stats)
    send_email(f"Security Threat Report - {DOMAIN} - {datetime.datetime.now().strftime('%b %d')}", html_report)
    print(f"Report sent to {TO_EMAIL} with {len(attacks)} attack entries.")

if __name__ == "__main__":
    main()