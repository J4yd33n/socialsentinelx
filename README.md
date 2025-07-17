SocialSentinelX
Overview
SocialSentinelX is an ethical social engineering toolkit designed for cybersecurity professionals and researchers to conduct authorized phishing simulations. Built on the foundation of SentinelX, it integrates with the Social-Engineer Toolkit (SET) to capture and analyze phishing campaign results, storing them in a SQLite database for real-time analysis and visualization via a Tkinter GUI or terminal dashboard. This tool aligns with a 2035–2045 vision for advancing cybersecurity awareness and ethical testing.
Note: Use this tool only with explicit permission from all parties involved. Unauthorized use is illegal and unethical.
Features

Phishing Campaign Management: Integrates with SET to capture credentials from phishing simulations.
Data Storage: Stores results in a SQLite database (logs/socialsentinelx.db) with encrypted credentials.
Real-Time Analysis: Analyzes captured credentials using NLTK for sentiment scoring.
Visualization: Displays results in a terminal-based table or a Tkinter GUI with a logo.
Audit Logging: Maintains logs for compliance and transparency.

Prerequisites

Operating System: Kali Linux (x86_64 recommended)
Python: 3.13.5 or higher
SET: Social-Engineer Toolkit (sudo apt install set)
Dependencies:
Python libraries: nltk, pycryptodome, pillow, tk
Install via:pip install nltk pycryptodome pillow





Installation

Clone the Repository:
git clone https://github.com/J4yd33n/socialsentinelx.git
cd socialsentinelx


Set Up Virtual Environment:
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install nltk pycryptodome pillow


Download NLTK Data:
python3 -m nltk.downloader vader_lexicon


Create Directories:
mkdir -p logs images templates
wget https://via.placeholder.com/100 -O images/socialsentinelx_logo.png


Configure SET:

Ensure SET is installed:sudo apt update
sudo apt install set


Optionally, configure SET to use port 80 (default) or another port:sudo mkdir -p /root/.set/config
sudo nano /root/.set/config/set_config


Add:WEB_PORT=80
WEBATTACK_EMAIL=OFF


Save and set permissions:sudo chmod 600 /root/.set/config/set_config






Set Permissions:
sudo mkdir -p /root/.set/reports
sudo chown teni:teni /root/.set/reports/ -R
sudo chmod -R u+r /root/.set/reports/
sudo chown teni:teni logs/ -R
sudo chmod -R u+w logs/



Usage

Run SET Phishing Campaign:
sudo setoolkit


Select:
1 (Social-Engineering Attacks)
2 (Website Attack Vectors)
3 (Credential Harvester Attack Method)
3 (Custom Import) or enter URL (e.g., https://accounts.google.com)
Path to template (if custom): templates/simple_login.html
IP: 192.168.72.131
Port: 80
Web attack only: 2


Test the phishing page:
Open http://192.168.72.131 in a browser (on a permitted device).
Submit dummy credentials (e.g., username: testuser, password: test123).




Check Captured Credentials:
sudo cat /root/.set/reports/credentials.txt


Run SocialSentinelX:

Terminal mode:source venv/bin/activate
python3 backend/socialsentinelx.py


GUI mode:python3 backend/socialsentinelx.py --gui





Example Output
    ____            _       _       ___           _ _       _ _                              |
   / ___|  ___ _ __| |_ ___| |__   / __|___ _ __ | | | ___ (_) |_ ___                        |
   \___ \ / __| '__| __/ __| '_ \ / /  | '_ \| | |/ __|| | __/ __|                           | 
    ___) | (__| |  | || (__| | | | \__ | | | | | | (__| | || (__                             |
   |____/ \___|_|   \__|\___|_| |_| ___|_| |_|_|_|\___|_|_|\___|                             |
                                                                                             |
   === SocialSentinelX Ethical Social Engineering ===

Initialized SQLite database: logs/socialsentinelx.db
Phishing campaign processed for test@example.com

Campaign Results
Email                | Clicked  | Credentials                    | Sentiment | Timestamp
--------------------|---------|-------------------------------|-----------|------------------------------
test@example.com    | Yes     | username: testuser, password: test123 | 0.00      | Thu Jul 17 17:50:00 2025

Ethical Guidelines

Permission: Use only with explicit, written consent from all parties involved.
Compliance: Maintain audit logs (logs/socialsentinelx.db) for transparency.
Testing: Use dummy credentials and test on your own systems or authorized environments.
Legal: Unauthorized social engineering is illegal and unethical.

Troubleshooting

Database Errors (e.g., no such column: key):
Delete the database and recreate:rm logs/socialsentinelx.db
python3 backend/socialsentinelx.py




No Credentials Captured:
Ensure the cloned page has a login form (e.g., use templates/simple_login.html).
Verify form submission at http://192.168.72.131.


Port Conflicts:
Check port 80:sudo netstat -tuln | grep :80


Stop conflicting services:sudo systemctl stop apache2
sudo systemctl stop nginx





Contributing
Contributions are welcome! Please submit pull requests to https://github.com/J4yd33n/socialsentinelx.
License
This project is licensed under the MIT License.
