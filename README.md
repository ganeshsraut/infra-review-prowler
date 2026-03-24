# AWS Security Hardening & Prowler Scan (Non-Prod)

## Purpose
To ensure baseline security hygiene across AWS non-production environments by running automated daily scans using **Prowler**.

## Repository Structure
```
DevOps/
└── prowler-scan/
    ├── config/
    │   ├── config.yaml          # Prowler General Configuration
    │   ├── checklist.yaml       # List of specific checks to run
    │   └── aws_mutelist.yaml    # Exceptions (False Positives)
    ├── scripts/
    │   └── send_report.py       # Python script to email reports
    └── requirements.txt         # Python dependencies
    ├── .env.example # Sample environment variables
```

## Prerequisites
Python 3.8+
Virtual environment (venv)
Gmail App Password (for email sending)

### Workflow Steps
1.  **Checkout Code:** Pulls the latest code from the repository.
2.  **Install Prowler:** Installs Prowler and dependencies from `requirements.txt`.
3.  **Configure AWS Credentials:** Authenticates using OIDC (Role: `ProwlerScanRole`).
4.  **Run Scan:** Executes Prowler against the **`ap-south-1`** region.
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

Copy the example file:

cp .env.example .env \

Update .env with your values:

SMTP_SERVER=smtp.gmail.com \ 
SMTP_PORT=587 \
SMTP_USERNAME=your_email@gmail.com \
SMTP_PASSWORD=your_app_password \

EMAIL_FROM=your_email@gmail.com \
EMAIL_TO=recipient@gmail.com \


## Usage (Local)
To run the scan locally (assuming you have AWS credentials configured):

Copy the example file:

cp .env.example .env

Update .env with your values:

SMTP_SERVER=smtp.gmail.com \
SMTP_PORT=587 \
SMTP_USERNAME=your_email@gmail.com \
SMTP_PASSWORD=your_app_password \

EMAIL_FROM=your_email@gmail.com \
EMAIL_TO=recipient@gmail.com \

REPORT_DIR=output

```bash
prowler aws \
  --config-file ./config/config.yaml --checks-file ./config/checklist.yaml \
  --output-directory output \
  --output-modes html json-ocsf \
  --output-filename prowler-report \
  --region ap-south-1  
```


## Verify on local view report
explorer.exe output/prowler-report.html \
cd output/ \
python3 -m http.server 8000