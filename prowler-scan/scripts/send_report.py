import smtplib
import os
import sys
import datetime
import json
import glob
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def get_ordinal_date_string(dt):
    if not dt:
        return "N/A"
    suffix = "th" if 11 <= dt.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(dt.day % 10, "th")
    return dt.strftime(f"%d{suffix} %b %Y")

def parse_prowler_report(file_path):
    if not file_path or not os.path.exists(file_path):
        return None
    with open(file_path, 'r') as f:
        content = f.read().strip()
        if not content:
            return None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = [json.loads(line) for line in content.splitlines() if line.strip()]
    normalized_data = []
    for item in data:
        if 'metadata' in item and 'event_code' in item['metadata']:
            normalized_data.append({
                'CheckID': item['metadata'].get('event_code'),
                'Status': item.get('status_code'),
                'Region': item['resources'][0].get('region') if item.get('resources') else 'N/A',
                'ResourceId': item['resources'][0].get('uid') if item.get('resources') else 'N/A',
                'Timestamp': item.get('time_dt')
            })
        else:
            normalized_data.append(item)
    failed_items = [i for i in normalized_data if i.get('Status') == 'FAIL']
    return {
        'date': datetime.date.today(),
        'total_findings': len(normalized_data),
        'total_failed': len(failed_items),
        'failed_items': failed_items,
        'failed_ids': {f"{i.get('CheckID')}:{i.get('ResourceId')}:{i.get('Region')}" for i in failed_items}
    }

def send_email():
    # Gmail SMTP config
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_username = os.environ.get('SMTP_USERNAME')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    sender_email = os.environ.get('EMAIL_FROM')
    receiver_email_env = os.environ.get('EMAIL_TO')
    report_dir = os.environ.get('REPORT_DIR', 'output')

    if not smtp_username or not smtp_password or not sender_email or not receiver_email_env:
        print("Error: SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, and EMAIL_TO must be set.")
        sys.exit(1)

    # Determine today's date
    today_str = datetime.date.today().strftime("%Y-%m-%d")

    # Locate report
    current_report_path = None
    if os.path.exists(report_dir):
        json_files = glob.glob(os.path.join(report_dir, "*.json"))
        if json_files:
            current_report_path = max(json_files, key=os.path.getmtime)

    curr = parse_prowler_report(current_report_path)

    # Prepare email
    msg = MIMEMultipart('mixed')
    msg['From'] = sender_email
    recipient_list = [e.strip() for e in receiver_email_env.split(',') if e.strip()]
    msg['To'] = ", ".join(recipient_list)
    msg['Subject'] = f"[Security Scan] Prowler Report - {today_str}"

    # Body content
    html_content = f"""
    <html>
      <body>
        <h2>Prowler Security Report - {today_str}</h2>
        <p>Total Findings: {curr['total_findings'] if curr else 'N/A'}</p>
        <p>Total Failed: {curr['total_failed'] if curr else 'N/A'}</p>
        <p>Attached are the full report and diff report if available.</p>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_content, 'html'))

    # Attach report files
    if os.path.exists(report_dir):
        for filename in os.listdir(report_dir):
            if filename.endswith(".html") or filename.endswith(".json"):
                filepath = os.path.join(report_dir, filename)
                try:
                    with open(filepath, "rb") as f:
                        part = MIMEApplication(f.read(), Name=filename)
                    part['Content-Disposition'] = f'attachment; filename="{filename}"'
                    msg.attach(part)
                except Exception as e:
                    print(f"Warning: Could not attach {filename}: {e}")

    # Send email via Gmail
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
        sys.exit(1)
    finally:
        try:
            server.quit()
        except:
            pass

if __name__ == "__main__":
    send_email()