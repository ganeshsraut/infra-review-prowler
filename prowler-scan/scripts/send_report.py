import smtplib
import os
import sys
import datetime
import json
import glob
import boto3
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def get_ordinal_date_string(dt):
    if not dt: return "N/A"
    suffix = "th" if 11 <= dt.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(dt.day % 10, "th")
    return dt.strftime(f"%d{suffix} %b %Y")

def upload_report_to_s3(file_path, bucket_name, s3_key):
    """Upload a report file to S3"""
    try:
        s3_client = boto3.client('s3')
        s3_client.upload_file(file_path, bucket_name, s3_key)
        print(f"Successfully uploaded {file_path} to s3://{bucket_name}/{s3_key}")
        return True
    except ClientError as e:
        print(f"Error uploading to S3: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error uploading to S3: {e}")
        return False

def download_report_from_s3(bucket_name, s3_key, local_path):
    """Download a report file from S3"""
    try:
        s3_client = boto3.client('s3')
        s3_client.download_file(bucket_name, s3_key, local_path)
        print(f"Successfully downloaded s3://{bucket_name}/{s3_key} to {local_path}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            print(f"Previous report not found in S3: s3://{bucket_name}/{s3_key}")
        else:
            print(f"Error downloading from S3: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error downloading from S3: {e}")
        return False

def get_s3_key_for_date(date_obj, prefix="prowler-reports"):
    """Generate S3 key for a given date"""
    return f"{prefix}/{date_obj.strftime('%Y/%m/%d')}/prowler-report.json"


def parse_prowler_report(file_path):
    print(f"DEBUG: Parsing report file: {file_path}")
    try:
        if not file_path or not os.path.exists(file_path):
            print(f"Warning: File path does not exist: {file_path}")
            return None
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content: 
                print(f"Warning: File content is empty: {file_path}")
                return None
            try:
                data = json.loads(content)
                print("DEBUG: Successfully parsed as JSON array")
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON decode error (might be NDJSON), error: {e}")
                try:
                    data = [json.loads(line) for line in content.splitlines() if line.strip()]
                    print(f"DEBUG: Successfully parsed as NDJSON with {len(data)} lines")
                except Exception as e2:
                    print(f"ERROR: Failed to parse as NDJSON too: {e2}")
                    return None

        if not isinstance(data, list):
            print(f"Error: Parsed data is not a list: {type(data)}")
            return None
            
        # Normalize data to support both Standard JSON and OCSF JSON
        normalized_data = []
        for item in data:
            if 'metadata' in item and 'event_code' in item['metadata']:
                # OCSF Format
                normalized_data.append({
                    'CheckID': item['metadata'].get('event_code'),
                    'Status': item.get('status_code'),
                    'Region': item['resources'][0].get('region') if item.get('resources') else 'N/A',
                    'ResourceId': item['resources'][0].get('uid') if item.get('resources') else 'N/A',
                    'Timestamp': item.get('time_dt') # OCSF uses time_dt
                })
            else:
                # Standard Format
                normalized_data.append(item)
        
        print(f"DEBUG: Normalized data contains {len(normalized_data)} items")
        failed_items = [i for i in normalized_data if i.get('Status') == 'FAIL']
        print(f"DEBUG: Found {len(failed_items)} failed items")
        
        # Determine date
        scan_date = datetime.date.today()
        # Try to get date from the first item
        if normalized_data:
            ts = normalized_data[0].get('Timestamp')
            if ts:
                try:
                    if 'T' in ts:
                        # Handle ISO format with potential Z
                        ts_clean = ts.replace('Z', '+00:00')
                        dt_obj = datetime.datetime.fromisoformat(ts_clean)
                        
                        # Ensure timezone awareness (assume UTC if missing)
                        if dt_obj.tzinfo is None:
                            dt_obj = dt_obj.replace(tzinfo=datetime.timezone.utc)
                        
                        # Convert to IST (UTC+5:30)
                        ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
                        ist_dt = dt_obj.astimezone(ist_tz)
                        
                        scan_date = ist_dt.date()
                        print(f"DEBUG: Extracted date from report (Converted to IST): {scan_date}")
                except Exception as e_date:
                    print(f"DEBUG: Date parsing failed: {e_date}")
                    pass
        
        return {
            'date': scan_date,
            'total_findings': len(normalized_data),
            'total_failed': len(failed_items),
            'failed_items': failed_items,
            # Create a unique key for diffing: CheckID + ResourceId + Region
            'failed_ids': {f"{i.get('CheckID')}:{i.get('ResourceId')}:{i.get('Region')}" for i in failed_items}
        }
    except Exception as e:
        print(f"Error parsing report {file_path}: {e}")
        import traceback
        traceback.print_exc()
        return None

def format_finding_html(finding):
    # Format: [CheckID] ResourceId (Region) - Description
    check_id = finding.get('CheckID', 'N/A')
    resource_id = finding.get('ResourceId', 'N/A')
    region = finding.get('Region', 'N/A')
    return f"<li><b>[{check_id}]</b> {resource_id} ({region})</li>"

def send_email():
    # Get configuration from environment variables
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT') or 587)
    smtp_username = os.environ.get('SMTP_USERNAME')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    sender_email = os.environ.get('EMAIL_FROM')
    receiver_email_env = os.environ.get('EMAIL_TO')
    report_dir = os.environ.get('REPORT_DIR', 'output')
    
    # S3 Configuration
    s3_bucket = os.environ.get('S3_BUCKET_NAME')  # e.g., 'prowler-reports-bucket'
    s3_prefix = os.environ.get('S3_REPORTS_PREFIX', 'prowler-reports')  # Optional prefix

    # CENTRALIZED DATE LOGIC (IST: UTC+5:30)
    # This ensures consistency across S3 keys, Email Subject, Diff Reports, and Filenames
    utc_now = datetime.datetime.utcnow()
    ist_now = utc_now + datetime.timedelta(hours=5, minutes=30)
    today = ist_now.date()
    yesterday = today - datetime.timedelta(days=1)
    
    today_str = today.strftime("%Y-%m-%d")
    print(f"DEBUG: Operation Date (IST): {today_str}")

    if not sender_email or not receiver_email_env:
        print("Error: EMAIL_FROM and EMAIL_TO environment variables must be set.")
        sys.exit(1)

    # Locate current report
    current_report_path = None
    if os.path.exists(report_dir):
        # Look for json files (standard or OCSF)
        json_files = glob.glob(os.path.join(report_dir, "*.json"))
        if json_files:
            # Pick the most recent one
            current_report_path = max(json_files, key=os.path.getmtime)
            print(f"Using current report: {current_report_path}")

    # Parse current report
    curr = parse_prowler_report(current_report_path)
    
    # Handle S3 operations if bucket is configured
    prev = None
    prev_report_path = None
    
    if s3_bucket and curr:
        # Use centralized IST dates calculated above
        
        # Upload today's report to S3
        today_s3_key = get_s3_key_for_date(today, s3_prefix)
        if current_report_path:
            print(f"Uploading today's report to S3...")
            upload_report_to_s3(current_report_path, s3_bucket, today_s3_key)
        
        # Download yesterday's report from S3
        yesterday_s3_key = get_s3_key_for_date(yesterday, s3_prefix)
        prev_report_path = os.path.join(report_dir, 'previous_report.json')
        
        print(f"Attempting to download yesterday's report from S3...")
        if download_report_from_s3(s3_bucket, yesterday_s3_key, prev_report_path):
            prev = parse_prowler_report(prev_report_path)
            # Clean up temporary file
            try:
                os.remove(prev_report_path)
            except:
                pass
        else:
            print("No previous report available for comparison")
    else:
        if not s3_bucket:
            print("Warning: S3_BUCKET_NAME not configured. Skipping S3 storage and comparison.")
        # Fallback to environment variable for previous report path
        prev_report_path = os.environ.get('PREVIOUS_REPORT_PATH')
        prev = parse_prowler_report(prev_report_path)
    
    # Analyze Differences
    new_failures = []
    fixed_failures = []
    
    if curr and prev:
        new_fail_ids = curr['failed_ids'] - prev['failed_ids']
        new_failures = [i for i in curr['failed_items'] if f"{i.get('CheckID')}:{i.get('ResourceId')}:{i.get('Region')}" in new_fail_ids]
        
        fixed_fail_ids = prev['failed_ids'] - curr['failed_ids']
        fixed_failures = [i for i in prev['failed_items'] if f"{i.get('CheckID')}:{i.get('ResourceId')}:{i.get('Region')}" in fixed_fail_ids]

    # Recipient processing
    recipient_list = [e.strip() for e in receiver_email_env.split(',') if e.strip()]
    receiver_email = ", ".join(recipient_list)
    
    cc_email_env = os.environ.get('EMAIL_CC', '')  # optional CC
    cc_email = ""
    if cc_email_env:
        cc_list = [e.strip() for e in cc_email_env.split(',') if e.strip()]
        cc_email = ", ".join(cc_list)

    # Use centralized IST date
    subject = f"[Security Scan] Prowler Report - {today_str}"
    
    # Message Setup
    msg = MIMEMultipart('mixed')
    msg['From'] = sender_email
    msg['To'] = receiver_email
    if cc_email:
        msg['Cc'] = cc_email
    msg['Subject'] = subject
    
    msg_body = MIMEMultipart('alternative')
    msg.attach(msg_body)
    
    # Build HTML Content
    # Default values for display
    prev_date_display = get_ordinal_date_string(prev['date']) if prev else "N/A"
    prev_total = prev['total_findings'] if prev else "N/A"
    prev_failed = prev['total_failed'] if prev else "N/A"
    
    curr_date_display = get_ordinal_date_string(curr['date']) if curr else get_ordinal_date_string(datetime.date.today())
    curr_total = curr['total_findings'] if curr else "N/A"
    curr_failed = curr['total_failed'] if curr else "N/A"

    # Delta formatting
    diff_failed_str = "-"
    if isinstance(curr_failed, int) and isinstance(prev_failed, int):
        diff = curr_failed - prev_failed
        if diff > 0:
            diff_failed_str = f"<span style='color: red;'>+{diff}</span>"
        elif diff < 0:
            diff_failed_str = f"<span style='color: green;'>{diff}</span>"
        else:
            diff_failed_str = "0"

    # Lists
    # Generate diff content
    diff_report_content = f"Security Scan Comparison Report - {today_str}\n"
    diff_report_content += "=" * 50 + "\n\n"

    # 1. OLD FAILED ITEMS (Yesterday)
    if prev and prev.get('failed_items'):
        diff_report_content += f"1. FAILED ITEMS FROM YESTERDAY REPORT [{prev_date_display}] ({len(prev['failed_items'])})\n"
        diff_report_content += "-" * 40 + "\n"
        for f in prev['failed_items']:
            check_id = f.get('CheckID', 'N/A')
            resource_id = f.get('ResourceId', 'N/A')
            region = f.get('Region', 'N/A')
            status = f.get('Status', 'FAIL')
            diff_report_content += f"[{status}] {check_id} - {resource_id} ({region})\n"
        diff_report_content += "\n"
    else:
        diff_report_content += f"1. FAILED ITEMS FROM YESTERDAY REPORT [{prev_date_display}]\nNo previous report available.\n\n"

    # 2. FAILED ITEMS FROM TODAY
    if curr and curr.get('failed_items'):
        diff_report_content += f"2. FAILED ITEMS FROM TODAY REPORT [{curr_date_display}] ({len(curr['failed_items'])})\n"
        diff_report_content += "-" * 40 + "\n"
        for f in curr['failed_items']:
            check_id = f.get('CheckID', 'N/A')
            resource_id = f.get('ResourceId', 'N/A')
            region = f.get('Region', 'N/A')
            status = f.get('Status', 'FAIL')
            diff_report_content += f"[{status}] {check_id} - {resource_id} ({region})\n"
        diff_report_content += "\n"
    else:
        diff_report_content += f"2. FAILED ITEMS FROM TODAY REPORT [{curr_date_display}]\nNo failures found.\n\n"

    # 3. NEW FAILED ITEMS (Difference)
    if new_failures:
        diff_report_content += f"3. NEW FAILED ITEMS (DIFFERENCE) ({len(new_failures)})\n"
        diff_report_content += "-" * 40 + "\n"
        for f in new_failures:
            check_id = f.get('CheckID', 'N/A')
            resource_id = f.get('ResourceId', 'N/A')
            region = f.get('Region', 'N/A')
            status = f.get('Status', 'FAIL')
            diff_report_content += f"[NEW] {check_id} - {resource_id} ({region})\n"
        diff_report_content += "\n"
    else:
        diff_report_content += "3. NEW FAILED ITEMS (DIFFERENCE)\nNo new failed items.\n\n"

    # Generate Top 5 New Failures for Inline HTML
    top_new_failures_html = ""
    if new_failures:
        top_new_failures_html = """
        <div style="margin-bottom: 20px;">
            <h4 style="color: #d9534f; border-bottom: 1px solid #ddd; padding-bottom: 5px;">⚠️ Top New Failures (Preview)</h4>
            <table style="width:100%; border-collapse: collapse; font-size: 0.9em;">
                <tr style="background-color: #f9f9f9;">
                    <th style="text-align: left; padding: 5px; border-bottom: 1px solid #eee;">Check ID</th>
                    <th style="text-align: left; padding: 5px; border-bottom: 1px solid #eee;">Resource</th>
                    <th style="text-align: left; padding: 5px; border-bottom: 1px solid #eee;">Region</th>
                </tr>
        """
        for f in new_failures[:5]: # Top 5 only
            top_new_failures_html += f"""
                <tr>
                    <td style="padding: 5px; border-bottom: 1px solid #eee;">{f.get('CheckID')}</td>
                    <td style="padding: 5px; border-bottom: 1px solid #eee;">{f.get('ResourceId')}</td>
                    <td style="padding: 5px; border-bottom: 1px solid #eee;">{f.get('Region')}</td>
                </tr>
            """
        top_new_failures_html += "</table></div>"
        if len(new_failures) > 5:
            top_new_failures_html += f"<p style='font-size: 0.8em; color: #777;'>...and {len(new_failures)-5} more (see attachment).</p>"
    else:
        # Message if no new failures
        top_new_failures_html = """
        <div style="margin-bottom: 20px; padding: 15px; background-color: #f0fff4; border: 1px solid #bef5cb; border-radius: 6px; color: #22863a; text-align: center;">
            <strong>✅ No new failed items</strong><br>
            <span style="font-size: 0.9em;">Great job! No new security findings compared to yesterday's report.</span>
        </div>
        """

    html_content = f"""
    <html>
      <head>
        <style>
          body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
          .container {{ width: 95%; max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #e1e4e8; border-radius: 6px; }}
          .header {{ background-color: #24292e; color: white; padding: 15px; text-align: center; border-radius: 6px 6px 0 0; }}
          .content {{ padding: 20px; background-color: white; }}
          .comparison-table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; }}
          .comparison-table th {{ background-color: #f6f8fa; padding: 12px; border: 1px solid #e1e4e8; text-align: center; }}
          .comparison-table td {{ padding: 12px; border: 1px solid #e1e4e8; text-align: center; }}
          .metric-name {{ text-align: left !important; font-weight: 600; }}
          .summary-cards {{ display: flex; gap: 15px; margin-bottom: 25px; }}
          .card {{ flex: 1; padding: 15px; border-radius: 6px; border: 1px solid transparent; text-align: center; }}
          .card-new {{ background-color: #fff5f5; border-color: #ffaeb0; color: #b31d28; }}
          .card-fixed {{ background-color: #f0fff4; border-color: #bef5cb; color: #22863a; }}
          .card-number {{ font-size: 24px; font-weight: bold; display: block; }}
          .card-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
          .footer {{ margin-top: 30px; font-size: 0.85em; text-align: center; color: #586069; border-top: 1px solid #eee; padding-top: 15px; }}
          .btn {{ display: inline-block; background-color: #0366d6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; }}
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2 style="margin:0;">🛡️ Prowler Security Report</h2>
            <p style="margin:5px 0 0 0; opacity: 0.8;">{today_str}</p>
          </div>
          
          <div class="content">
            <p>Automated security scan results summary.</p>
            
            <div class="summary-cards">
                <div class="card card-new">
                    <span class="card-number">{len(new_failures) if curr and prev else 'N/A'}</span>
                    <span class="card-label">New Failures</span>
                </div>
                <div class="card card-fixed">
                    <span class="card-number">{len(fixed_failures) if curr and prev else 'N/A'}</span>
                    <span class="card-label">Fixed Issues</span>
                </div>
            </div>

            <table class="comparison-table">
                <thead>
                    <tr>
                        <th class="metric-name">Metric</th>
                        <th>Yesterday<br><span style="font-weight:normal; font-size:0.8em; color:#666;">{prev_date_display}</span></th>
                        <th>Today<br><span style="font-weight:normal; font-size:0.8em; color:#666;">{curr_date_display}</span></th>
                        <th>Change</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="metric-name">Total Findings</td>
                        <td>{prev_total}</td>
                        <td>{curr_total}</td>
                        <td style="color: #666;">-</td>
                    </tr>
                    <tr>
                        <td class="metric-name">Total Failed</td>
                        <td>{prev_failed}</td>
                        <td style="font-weight: bold;">{curr_failed}</td>
                        <td>{diff_failed_str}</td>
                    </tr>
                </tbody>
            </table>

            {top_new_failures_html}
            
            <div style="background-color: #eef3f8; padding: 15px; border-radius: 6px; margin-top: 20px;">
                <strong>Attachments:</strong>
                 <ul style="margin: 5px 0 0 0; padding-left: 20px;">
                    <li><strong>prowler-report.html</strong>: Full graphical report</li>
                    <li><strong>diff_report.txt</strong>: List of specific New {f"and Fixed ({len(fixed_failures)})" if fixed_failures else ""} items</li>
                 </ul>
            </div>
            
          </div>
          <div class="footer">
            <p>Generated by DevOps Security Pipeline &bull; &copy; {datetime.date.today().year}</p>
          </div>
        </div>
      </body>
    </html>
    """

    msg_body.attach(MIMEText(html_content, 'html'))
    
    # Attach diff report if generated
    if diff_report_content:
        part = MIMEApplication(diff_report_content.encode('utf-8'), Name="diff_report.txt")
        part['Content-Disposition'] = 'attachment; filename="diff_report.txt"'
        msg.attach(part)
        print("Attached: diff_report.txt")

    # Attach files
    files_attached = 0
    if os.path.exists(report_dir):
        print(f"Looking for reports in: {report_dir}")
        for filename in os.listdir(report_dir):
            if filename.endswith(".html") or filename.endswith(".json"):
                filepath = os.path.join(report_dir, filename)
                try:
                    with open(filepath, "rb") as f:
                        part = MIMEApplication(f.read(), Name=filename)
                    
                    # Append date to filename
                    name, ext = os.path.splitext(filename)
                    new_filename = f"{name}-{today_str}{ext}"
                    
                    part['Content-Disposition'] = f'attachment; filename="{new_filename}"'
                    msg.attach(part)
                    files_attached += 1
                    print(f"Attached: {new_filename}")
                except Exception as e:
                    print(f"Could not attach {filename}: {e}")

    # Send email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()               # Identify to server
        server.starttls() # Upgrade to secure TLS
        server.ehlo()               # Re-identify after TLS
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
        sys.exit(1)

if __name__ == "__main__":
    send_email()
