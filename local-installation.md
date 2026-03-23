# Update
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3 python3-pip git unzip -y

## Use pipx (clean + safe)
sudo apt install pipx -y
pipx ensurepath
pipx install prowler


cd DevOps/prowler-scan
prowler aws \
--config-file ./config/config.yaml \
--checks-file ./config/checklist.yaml \
--output-directory output \
--output-modes html json-ocsf \
--output-filename prowler-report \
--ignore-exit-code-3 \
--region ap-south-1

OUTPUT:

ganeshr@GaneshR-WIN:/mnt/c/Users/ganeshr/Documents/00-NOC Team-2025-26-imp/FY-2025-26/KRA/Security hardening/DevOps-main/prowler-scan$ prowler aws \
--config-file ./config/config.yaml \
--checks-file ./config/checklist.yaml \
--output-directory output \
--output-modes html json-ocsf \
--output-filename prowler-report \
--ignore-exit-code-3 \
--region ap-south-1
                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v5.20.0
|_| Get the most at https://cloud.prowler.com 

New! Send findings from Prowler CLI to Prowler Cloud
More details here: goto.prowler.com/import-findings

Date: 2026-03-17 10:50:56


Using alias eks_endpoints_not_publicly_accessible for check eks_cluster_not_publicly_accessible...
-> Using the AWS credentials below:
  · AWS-CLI Profile: default
  · AWS Regions: ap-south-1
  · AWS Account: 150361542164
  · User Id: AIDASGAR7BYKG4XNYTGQT
  · Caller Identity ARN: arn:aws:iam::150361542164:user/tf-ganesh

-> Using the following configuration:
  · Config File: ./config/config.yaml
  · Mutelist File: /home/ganeshr/.local/share/pipx/venvs/prowler/lib/python3.12/site-packages/prowler/config/aws_mutelist.yaml
  · Scanning unused services and resources: False

Executing 18 checks, please wait...
-> Scan completed! |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠︎          | (!) 13/18 [72%] in 45.6s
-> Scan completed! |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠︎          | (!) 13/18 [72%] in 45.6s

-> Scan completed! |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠︎          | (!) 13/18 [72%] in 45.6s

Overview Results:
-> Scan completed! |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠︎          | (!) 13/18 [72%] in 45.6s

Overview Results:
╭───────────────────┬───────────────────┬────────────────╮
│ 55.56% (5) Failed │ 44.44% (4) Passed │ 0.0% (0) Muted │
╰───────────────────┴───────────────────┴────────────────╯


Overview Results:
╭───────────────────┬───────────────────┬────────────────╮
│ 55.56% (5) Failed │ 44.44% (4) Passed │ 0.0% (0) Muted │
╰───────────────────┴───────────────────┴────────────────╯

Overview Results:
╭───────────────────┬───────────────────┬────────────────╮
│ 55.56% (5) Failed │ 44.44% (4) Passed │ 0.0% (0) Muted │
╰───────────────────┴───────────────────┴────────────────╯

╭───────────────────┬───────────────────┬────────────────╮
│ 55.56% (5) Failed │ 44.44% (4) Passed │ 0.0% (0) Muted │
╰───────────────────┴───────────────────┴────────────────╯

╰───────────────────┴───────────────────┴────────────────╯


Account 150361542164 Scan Results (severity columns are for fails only):
╭────────────┬───────────┬──────────┬────────────┬────────┬──────────┬───────┬─────────╮
│ Provider   │ Service   │ Status   │   Critical │   High │   Medium │   Low │   Muted │
├────────────┼───────────┼──────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ ec2       │ FAIL (3) │          0 │      2 │        1 │     0 │       0 │
├────────────┼───────────┼──────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ iam       │ FAIL (1) │          0 │      0 │        1 │     0 │       0 │
├────────────┼───────────┼──────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ vpc       │ FAIL (1) │          0 │      0 │        1 │     0 │       0 │
╰────────────┴───────────┴──────────┴────────────┴────────┴──────────┴───────┴─────────╯
* You only see here those services that contains resources.

Detailed results are in:
 - JSON-OCSF: output/prowler-report.ocsf.json
 - HTML: output/prowler-report.html


check report 
cd output
python3 -m http.server

## Create app password for email and use that password to login to email account in prowler cloud.
https://myaccount.google.com/apppasswords?pli=1&rapt=AEjHL4NSoH8Vd_S41qAGQN9Hh0XyWZDwSvu65KJQTg75OywXXO15HN9FCU65P4jFC2dlFTAvsXG_68085mu3CgpB1wuA6-pH7ly416KHhGergSlzlrgA97U

## Export path variables 
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587

export SMTP_USERNAME=adFA@gmail.com
export SMTP_PASSWORD=<16 digit app password>

export EMAIL_FROM=<>@gmail.com
export EMAIL_TO=<>@gmail.com

python3 -m prowler-env venv
source prowler-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python scripts/send_report.py