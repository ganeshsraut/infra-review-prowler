# AWS Security Hardening & Prowler Scan (Non-Prod)

## Purpose
To ensure baseline security hygiene across AWS non-production environments by running automated daily scans using **Prowler**.

## Repository Structure
```
DevOps/
├── .github/
│   └── workflows/
│       └── dev-prowler-scan.yml   # GitHub Actions Workflow
│
└── prowler-scan/
    ├── config/
    │   ├── config.yaml          # Prowler General Configuration
    │   ├── checklist.yaml       # List of specific checks to run
    │   └── aws_mutelist.yaml    # Exceptions (False Positives)
    ├── scripts/
    │   └── send_report.py       # Python script to email reports
    └── requirements.txt         # Python dependencies
```

## Automation (GitHub Actions)
The workflow **`dev-prowler-scan.yml`** is configured to run:

1.  **On Schedule:** Daily at **12:00 AM IST** (18:30 UTC).
2.  **On Push:** Whenever code is pushed to the `DevOps` branch.

### Workflow Steps
1.  **Checkout Code:** Pulls the latest code from the repository.
2.  **Install Prowler:** Installs Prowler and dependencies from `requirements.txt`.
3.  **Configure AWS Credentials:** Authenticates using OIDC (Role: `ProwlerScanRole`).
4.  **Run Scan:** Executes Prowler against the **`us-west-2`** region.
    *   **Output:** Generates `HTML` and `JSON-OCSF` reports.
    *   **Config:** Uses `checklist.yaml` for checks and `aws_mutelist.yaml` for exceptions.
5.  **Send Email:** Emails the reports to the team.

## Configuration

### 1. Checklist (`checklist.yaml`)
Defines the specific Prowler checks to run (e.g., `ec2_securitygroup_allow_ingress_from_internet_to_any_port`).

### 2. Mutelist (`aws_mutelist.yaml`)
Defines resources to ignore (false positives).
*   **Note:** Currently using the default Prowler mutelist. To use the custom file, update the workflow command to include `--mutelist-file`.

### 3. Email Reporting
The `send_report.py` script sends an email with the scan results attached.
*   **Subject:** `[Security Scan] Prowler Report - YYYY-MM-DD`
*   **Recipients:** Configured via GitHub Repository Variables (`EMAIL_TO`, `EMAIL_CC`).

## Setup Requirements

### GitHub Secrets
| Secret Name | Description |
|---|---|
| `AWS_ACCOUNT_ID` | The AWS Account ID where the scan runs. |
| `SMTP_SERVER` | SMTP Server address (e.g., `smtp.office365.com`). |
| `SMTP_PORT` | SMTP Port (e.g., `587`). |
| `SMTP_USERNAME` | Username for the email account. |
| `SMTP_PASSWORD` | Password for the email account. |

### GitHub Variables
| Variable Name | Description |
|---|---|
| `EMAIL_FROM` | The email address sending the report. |
| `EMAIL_TO` | Comma-separated list of primary recipients. |
| `EMAIL_CC` | Comma-separated list of CC recipients. |
| `S3_BUCKET_NAME` | **(Required for comparison)** S3 bucket name to store reports (e.g., `prowler-reports-bucket`). |
| `S3_REPORTS_PREFIX` | *(Optional)* S3 prefix/folder path (default: `prowler-reports`). |

### S3 Report Storage & Comparison
The workflow now stores daily reports in S3 and compares today's scan with yesterday's to track security posture changes.

**S3 Structure:**
```
s3://your-bucket/prowler-reports/
  └── YYYY/
      └── MM/
          └── DD/
              └── prowler-report.json
```

**Email Comparison Format:**
```
Date: 5th Jan 2026
Total Finding: 505
Total Failed: 75

Date: 6th Jan 2026
Total Finding: 500
Total Failed: 76
```

**Setup Steps:**
1. Create an S3 bucket (e.g., `prowler-reports-nonprod`)
2. Ensure the IAM role (`ProwlerScanRole`) has permissions:
   - `s3:PutObject` - Upload today's report
   - `s3:GetObject` - Download yesterday's report
   - `s3:ListBucket` - List reports (optional, for cleanup)
3. Add `S3_BUCKET_NAME` to GitHub Variables
4. (Optional) Add `S3_REPORTS_PREFIX` for custom folder structure

## Usage (Local)
To run the scan locally (assuming you have AWS credentials configured):

```bash
prowler aws \
  --config-file ./prowler-scan/config/config.yaml \
  --checks-file ./prowler-scan/config/checklist.yaml \
  --output-directory output \
  --output-modes html json-ocsf \
  --region us-west-2
```



