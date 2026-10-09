# PhishGuard AI — Full-Stack Phishing Detection Platform
**Project Roles**:
- **Member 1 — Frontend**: Cyber HUD UI/UX, Radar Scanner, SVG Gauges, Responsive Telemetry Dashboard
- **Member 2 — Machine Learning**: Dataset Synthesis & Curation, 24-D Feature Engineering, Ensemble Classifier Training & Performance Benchmarking
- **Member 3 — Backend**: FastAPI REST API, Threat Intelligence Engine, ML Model Integration, Input Validation & SSRF Guard


---

## 🌟 Architecture Overview

```
Frontend (HTML5 / Vanilla CSS / ES6)  <---- REST API (CORS) ---->  Backend (FastAPI / Uvicorn)
    │                                                                   │
    ├── Scanner & Radar HUD                                             ├── Input Validator (SSRF Protection)
    ├── Risk Report (0-100 Score)                                      ├── ML Feature Extractor (18+ features)
    └── Telemetry Dashboard                                            ├── Threat Intelligence (SSL, DNS, Redirects)
                                                                        └── SQLite Audit Database (data/scans.db)
```

---

## 🚀 Quick Start Guide

### 1. Start the Backend API (FastAPI)
```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 5000
```
- API Docs & Swagger UI: **http://localhost:5000/docs**
- Health Check: **http://localhost:5000/api/health**

### 2. Start the Frontend (Member 1)
```powershell
python -m http.server 8080
```
- Open browser at: **http://localhost:8080**

The frontend automatically communicates with the backend at `http://localhost:5000/api/scan`, with an automatic fallback to client-side heuristics if the server is offline.

---

## 🛡️ Backend Features (Member 3)

### 1. REST API Endpoints
- **`POST /api/scan`**: Accepts `{ "url": "..." }`, runs input validation, SSRF checks, feature extraction, ML prediction, live SSL handshake, DNS routing, and returns the comprehensive threat report.
- **`GET /api/history`**: Returns recent audit log scans stored in SQLite.
- **`GET /api/threat-intel`**: Returns global telemetry stats, DEFCON indicator, and active campaign vectors.
- **`GET /api/health`**: Service availability and model status.

### 2. Machine Learning Model & Feature Extractor (`backend/model.py`)
Extracts **18 structural, lexical, and behavioral features**:
1. `url_len` & `host_len` (Length anomalies)
2. `host_entropy` & `url_entropy` (Shannon entropy for algorithmic generation / DGA)
3. `subdomains` (Subdomain stacking tiers)
4. `dots_count` & `hyphens_count` (Punctuation cloaking)
5. `has_ip` (Direct numeric IP address detection)
6. `has_high_risk_tld` (Disposable TLD blacklist: `.xyz`, `.top`, `.tk`, etc.)
7. `keyword_count` & `keyword_hits` (Targeted credential harvesting phrases)
8. `is_spoofing` & `detected_brand` (Typosquatting & homoglyph distance)
9. `is_https` & `has_at_symbol` (Protocol integrity and `@` prefix obfuscation)
10. `has_double_slash_redirect` & `has_punycode` (Punycode `xn--` disguise)

### 3. Threat Intelligence Probes (`backend/threat_intel.py`)
- **Live SSL / TLS Socket Handshake**: Direct socket probe verifying certificate issuer, validity, and cipher strength.
- **Authoritative DNS Resolution**: Resolves A records, reverse PTR, and ASN network details.
- **HTTP Redirection Chain Tracker**: Follows multi-hop link shorteners (e.g. `bit.ly` -> phishing portal).
- **Signature Threat Feeds**: Blacklist signature matching for active phishing campaigns.

### 4. Input Sanitization & SSRF Defense (`backend/validator.py`)
- Pydantic schema validation for URL structure.
- RFC 1918 private IP range filtering (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.0.0/16`) to prevent Server-Side Request Forgery.

---

## 🤖 Machine Learning Pipeline (Member 2)

### 1. Dataset Generation & Curation (`backend/dataset_generator.py`)
- Balanced benchmark dataset of **2,400 labeled samples** (`1,200 Phishing` vs `1,200 Legitimate`).
- Synthesizes zero-day attack patterns: typosquatting, DGA entropy, subdomain stacking, IP-based destinations, `@` credential obfuscation, disposable TLDs (`.xyz`, `.top`, `.tk`), and punycode.
- Persisted at [data/phishing_dataset.csv](file:///c:/Users/GP/OneDrive/Desktop/Hack/data/phishing_dataset.csv).

### 2. Feature Extraction (`backend/feature_pipeline.py`)
- Extracts **24 numerical & lexical features** per URL in `< 0.1ms`.
- Top predictive signals: `is_https`, `has_high_risk_tld`, `keyword_count`, `digits_count`, `is_spoofing`, `host_entropy`, and `subdomain_depth`.

### 3. Model Training & Evaluation (`backend/train_model.py`)
- Benchmarked **Random Forest**, **Gradient Boosting**, and **Logistic Regression**.
- Evaluated via **Stratified 5-Fold Cross Validation** on holdout test splits.
- Production artifact exported to [data/phishguard_model.joblib](file:///c:/Users/GP/OneDrive/Desktop/Hack/data/phishguard_model.joblib).
- Comprehensive evaluation report at [data/model_evaluation_report.md](file:///c:/Users/GP/OneDrive/Desktop/Hack/data/model_evaluation_report.md).


---

## 📂 Project Structure
```
Hack/
├── backend/
│   ├── main.py             # FastAPI router, CORS middleware, API endpoints
│   ├── model.py            # ML feature extractor & ensemble classifier
│   ├── threat_intel.py     # Live SSL probe, DNS resolver, redirection tracer
│   ├── validator.py        # Pydantic schema validation & SSRF protection
│   ├── database.py         # SQLite persistence & telemetry statistics
│   └── requirements.txt    # Backend dependencies
├── data/
│   └── scans.db            # Persistent SQLite database
├── css/
│   └── style.css           # Cyber-Defense design system & responsive layout
├── js/
│   ├── scanner.js          # Client bridge connecting to backend API
│   ├── dashboard.js        # KPI metrics, SVG trend chart, audit log table
│   └── app.js              # Application controller, audio synth, pipeline HUD
├── index.html              # Frontend application page
└── README.md               # Platform documentation
```
