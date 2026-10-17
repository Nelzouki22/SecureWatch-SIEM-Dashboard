# 🛡️ SecureWatch SIEM Dashboard
**Security Event Monitoring & Incident Response Platform**

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

A complete, open-source Security Information and Event Management (SIEM) system built for SOC Analysts and Blue Teams. It collects, normalizes, and analyzes logs from multiple sources, detects threats in real-time, and provides a comprehensive dashboard for incident response.

## 🚀 Key Features
- 🔐 **Authentication & Security:** Role-based access, CSRF protection, Rate Limiting, and Session Management.
- 📊 **SOC Dashboard:** Real-time metrics, Security Score gauge, and 6 interactive Chart.js visualizations.
- 📥 **Log Ingestion:** Supports Windows Security, Linux, Firewall, Active Directory, CSV, and JSON formats.
- 🧠 **Threat Detection Engine:** Auto-detects Brute Force, Privilege Escalation, Unauthorized Access, and Suspicious Processes.
- 🚨 **Alert & Incident Management:** Full lifecycle tracking (Open → Investigating → Resolved) with investigation notes.
- 📄 **Automated Reporting:** Export Daily/Weekly/Monthly security reports in PDF and CSV formats.
- 🌍 **Multi-language & UI:** Full English/Arabic support with RTL layout, plus Light/Dark mode persistence.

## 🏗️ Architecture & Tech Stack
- **Backend:** Python 3.12+, Flask, SQLAlchemy, Flask-Login, Flask-Limiter
- **Frontend:** HTML5, Bootstrap 5, Chart.js, Vanilla JS
- **Database:** SQLite (easily upgradable to PostgreSQL)
- **Tools:** Docker, VS Code, Pytest

## 🚀 Quick Start
```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/SecureWatch-SIEM-Dashboard.git
cd SecureWatch-SIEM-Dashboard

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py

Navigate to http://localhost:5000
Default Admin: admin / Admin@1234 (Change this in production!)
📂 Project Structure
├── app.py                  # Main application factory
├── models.py               # SQLAlchemy database models
├── siem_engine.py          # Log parsing and normalization
├── alert_engine.py         # Threat detection logic
├── report_generator.py     # PDF/CSV report generation
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, and assets
└── tests/                  # Unit and integration tests

🛡️ Skills Demonstrated
SIEM Architecture | Threat Detection | Incident Response | Python Web Development | Data Visualization | Secure Coding Practices
