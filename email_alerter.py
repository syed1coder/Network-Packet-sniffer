#!/usr/bin/env python3
"""
Email Alert System for Packet Sniffer
Sends alerts when anomalies are detected
"""

import smtplib
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import time
import json
import os

CONFIG_FILE = "alert_config.json"
DB_NAME = "packet_logs.db"
CHECK_INTERVAL = 30  # Check for new anomalies every 30 seconds

class EmailAlerter:
    def __init__(self, config_file=CONFIG_FILE):
        self.config = self.load_config(config_file)
        self.last_alert_id = 0
        
    def load_config(self, config_file):
        """Load email configuration"""
        default_config = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "your_email@gmail.com",
            "sender_password": "your_app_password",
            "recipient_emails": ["admin@example.com"],
            "alert_on": {
                "PORT_SCAN": True,
                "FLOODING": True
            },
            "min_severity": "MEDIUM"  # MEDIUM, HIGH, CRITICAL
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                print(f"[!] Error loading config: {e}")
        else:
            # Create default config file
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(f"[+] Created default config file: {config_file}")
            print("[!] Please update with your email credentials")
        
        return default_config
    
    def get_new_anomalies(self):
        """Get new anomalies from database"""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, anomaly_type, source_ip, description, severity
                FROM anomalies
                WHERE id > ?
                ORDER BY id ASC
            """, (self.last_alert_id,))
            
            anomalies = cursor.fetchall()
            conn.close()
            
            if anomalies:
                self.last_alert_id = anomalies[-1][0]  # Update last processed ID
            
            return anomalies
            
        except Exception as e:
            print(f"[!] Database error: {e}")
            return []
    
    def should_alert(self, anomaly_type, severity):
        """Check if alert should be sent based on config"""
        # Check if anomaly type is enabled
        if not self.config['alert_on'].get(anomaly_type, False):
            return False
        
        # Check severity level
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_severity = severity_levels.get(self.config['min_severity'], 2)
        current_severity = severity_levels.get(severity, 2)
        
        return current_severity >= min_severity
    
    def create_alert_email(self, anomalies):
        """Create email message for anomalies"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[ALERT] Network Anomaly Detected - {len(anomalies)} event(s)"
        msg['From'] = self.config['sender_email']
        msg['To'] = ', '.join(self.config['recipient_emails'])
        
        # Create text content
        text_content = "NETWORK SECURITY ALERT\n"
        text_content += "="*60 + "\n\n"
        text_content += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        text_content += f"Anomalies Detected: {len(anomalies)}\n\n"
        
        for anomaly_id, timestamp, atype, source, desc, severity in anomalies:
            text_content += f"[{severity}] {atype}\n"
            text_content += f"  Time: {timestamp}\n"
            text_content += f"  Source IP: {source}\n"
            text_content += f"  Details: {desc}\n"
            text_content += "-"*60 + "\n"
        
        text_content += "\nPlease investigate immediately.\n"
        text_content += "This is an automated alert from the Network Packet Sniffer.\n"
        
        # Create HTML content
        html_content = f"""
        <html>
          <head>
            <style>
              body {{ font-family: Arial, sans-serif; }}
              .header {{ background-color: #d9534f; color: white; padding: 15px; }}
              .anomaly {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
              .critical {{ background-color: #f8d7da; }}
              .high {{ background-color: #fff3cd; }}
              .medium {{ background-color: #d1ecf1; }}
              .severity {{ font-weight: bold; color: #d9534f; }}
            </style>
          </head>
          <body>
            <div class="header">
              <h2>⚠️ NETWORK SECURITY ALERT</h2>
            </div>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Anomalies Detected:</strong> {len(anomalies)}</p>
            <hr>
        """
        
        for anomaly_id, timestamp, atype, source, desc, severity in anomalies:
            severity_class = severity.lower()
            html_content += f"""
            <div class="anomaly {severity_class}">
              <p><span class="severity">[{severity}]</span> <strong>{atype}</strong></p>
              <p><strong>Time:</strong> {timestamp}</p>
              <p><strong>Source IP:</strong> {source}</p>
              <p><strong>Details:</strong> {desc}</p>
            </div>
            """
        
        html_content += """
            <hr>
            <p><strong>Action Required:</strong> Please investigate immediately.</p>
            <p><em>This is an automated alert from the Network Packet Sniffer.</em></p>
          </body>
        </html>
        """
        
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        return msg
    
    def send_email(self, msg):
        """Send email alert"""
        try:
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], self.config['sender_password'])
                server.send_message(msg)
            
            print(f"[+] Alert email sent to {', '.join(self.config['recipient_emails'])}")
            return True
            
        except Exception as e:
            print(f"[!] Error sending email: {e}")
            return False
    
    def monitor(self):
        """Continuously monitor for new anomalies"""
        print("[+] Email alerting system started")
        print(f"[+] Checking every {CHECK_INTERVAL} seconds")
        print(f"[+] Recipients: {', '.join(self.config['recipient_emails'])}")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            while True:
                anomalies = self.get_new_anomalies()
                
                if anomalies:
                    # Filter anomalies based on config
                    filtered_anomalies = [
                        a for a in anomalies 
                        if self.should_alert(a[2], a[5])  # atype and severity
                    ]
                    
                    if filtered_anomalies:
                        print(f"[!] {len(filtered_anomalies)} new anomalie(s) detected")
                        msg = self.create_alert_email(filtered_anomalies)
                        self.send_email(msg)
                
                time.sleep(CHECK_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n[+] Email alerting stopped")

def main():
    print("="*60)
    print("Network Packet Sniffer - Email Alert System")
    print("="*60 + "\n")
    
    alerter = EmailAlerter()
    
    # Check if config is properly set
    if alerter.config['sender_email'] == "your_email@gmail.com":
        print("[!] WARNING: Email configuration not set!")
        print(f"[!] Please edit '{CONFIG_FILE}' with your email credentials")
        print("[!] Running in demo mode (no emails will be sent)\n")
    
    alerter.monitor()

if __name__ == "__main__":
    main()
