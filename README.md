# PhishGuard AI — AI-Powered Phishing Detection Platform

OPCODE IMPACT 2026 | Hackathon Submission

Team ID:OPC026

## 1. Problem Statement

Phishing attacks use fake websites and deceptive URLs to steal sensitive information such as passwords and banking details. Traditional security methods may fail to identify new or disguised phishing links. Users need a fast and accessible way to assess whether a URL may be malicious before visiting it.

## 2. Solution Title
PhishGuard AI — Full-Stack Phishing Detection Platform

## 3. Solution Description

PhishGuard AI is a web-based platform that analyzes URLs to identify potential phishing threats. It combines machine learning, URL feature extraction, and security checks such as SSL/TLS verification, DNS resolution, and redirect tracking. The platform provides a risk score from 0 to 100 and displays a threat report through an interactive dashboard. It also includes input validation, protection against Server-Side Request Forgery (SSRF), and SQLite-based scan history.

## 4. Architecture Diagram

<img width="1688" height="1075" alt="image" src="https://github.com/user-attachments/assets/3b67a862-82c2-4e79-ad3e-fd4200f8f40b" />


Workflow:

1. The user enters a URL through the web interface.
2. The frontend sends the URL to the FastAPI backend through a REST API.
3. The backend validates the URL and checks for potentially unsafe internal network destinations.
4. The feature extractor analyzes URL characteristics, while the machine learning model predicts the potential phishing risk.
5. The threat intelligence module checks available SSL/TLS, DNS, redirect, and threat-signature information.
6. The backend returns the scan report, and the frontend displays the risk score and results.
7. Scan records and audit information are stored in the SQLite database.

## 5. Technology Stack

- Frontend: HTML5, CSS3, JavaScript (ES6), SVG
- Backend:Python, FastAPI, Uvicorn
- Database: SQLite
- Machine Learning:Scikit-learn-based model training and evaluation; Random Forest, Gradient Boosting, and Logistic Regression are benchmarked.
- Feature Engineering: URL length, entropy, subdomains, suspicious keywords, high-risk TLDs, HTTPS status, and spoofing indicators.
- Security:Pydantic validation, SSRF protection, SSL/TLS checks, DNS resolution, and redirect tracking.
- API: REST API with CORS support.

## 6. Quick Start Guide

Prerequisites:

- Python 3.10 or a compatible version
- pip
- A modern web browser
- Project dependencies listed in `backend/requirements.txt`
**Prerequisites:**
- Python 3.10 or compatible version
- pip
- FastAPI
- Uvicorn
- Scikit-learn
- Pydantic
- SQLite

Installation & Execution:

Run these commands from the project root directory.

```bash
# 1. Install backend dependencies
pip install -r backend/requirements.txt

# 2. Start the backend API
python -m uvicorn backend.main:app --host 0.0.0.0 --port 5000
```
INFO:     Started server process [1108]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
ERROR:    [Errno 10048] error while attempting to bind on address ('0.0.0.0', 5000): [winerror 10048] only one usage of each socket address (protocol/network address/port) is normally permitted
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
Open a second terminal in the project root:

```bash
# 3. Start the frontend web server
python -m http.server 8080
```
Serving HTTP on :: port 8080 (http://[::]:8080/) ..

Open the application in your browser:

- Frontend: http://localhost:8080
- API documentation: http://localhost:5000/docs
- Health check: http://localhost:5000/api/health

The frontend is configured to communicate with the backend at `http://localhost:5000/api/scan`. It can use client-side heuristic fallback when the backend is unavailable.

## 7. Output Screenshots

<img width="1405" height="821" alt="image" src="https://github.com/user-attachments/assets/ea36c708-6774-46c1-af04-3289200a27cd" />

<img width="1370" height="817" alt="image" src="https://github.com/user-attachments/assets/0303a95f-aa2b-4196-9d60-8bddf3d69668" />

Output Description:

The dashboard presents the URL scan results, risk score, and threat information in a cybersecurity-themed interface. It also provides telemetry statistics and scan history. The displayed results depend on the URL submitted and the checks successfully completed.
<img width="1405" height="821" alt="Screenshot 2026-10-10 093623" src="https://github.com/user-attachments/assets/c881dfc4-37a2-4245-ae8d-067dfc87b25b" />

<img width="1370" height="817" alt="image" src="https://github.com/user-attachments/assets/5f8cf576-9035-40c1-b00c-bca48a1e72e7" />
<img width="1688" height="1075" alt="image" src="https://github.com/user-attachments/assets/42a4c7e0-7aa4-4009-af67-80b38909cb79" />

## 8. Future Scope

- Integrate additional trusted phishing threat feeds and reputation services.
- Improve detection accuracy using larger, more diverse datasets and further model evaluation.
- Add browser-extension support for real-time URL checking.
- Enhance reporting with downloadable scan reports and historical trend analysis.
- Deploy the platform to a secure cloud environment for wider accessibility.

## 9. Team Contributions

| Member Name | Contribution |
|---|---|
| Georgekutty Senni | Frontend development: cybersecurity UI/UX, radar scanner, SVG gauges, and responsive dashboard |
| Aswathy Shabu | Machine learning: dataset generation, feature engineering, model training, and performance evaluation |
| Devanantha S | Backend development: FastAPI endpoints, threat intelligence, ML integration, input validation, and SSRF protection |

## 10. Tools Used

| Tool / Platform | Purpose / Why Used |
|---|---|
| Python | Backend development and machine learning |
| FastAPI | Building REST API endpoints |
| Uvicorn | Running the backend server |
| Scikit-learn | Training and evaluating machine learning classifiers |
| SQLite | Storing scan history and audit records |
| HTML5, CSS3, JavaScript | Building the interactive frontend |
| Git and GitHub | Version control and project collaboration |
| AI tools, if used | Assisting with implementation ideas, debugging, documentation, or UI development; specify the tools actually used by the team |

---

Project:PhishGuard AI  
Event:OPCODE IMPACT 2026  
Track: Industry
