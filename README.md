# PhishGuard AI — Frontend & Threat Telemetry Dashboard
**Role**: Member 1 — Frontend Specialist  
**Tech Stack**: Modern Semantic HTML5, Vanilla CSS (Cyber Defense Design System), Modular ES6+ JavaScript, Web Audio API, Canvas Matrix FX, SVG Visualizations.

---

## 🌟 Overview & Deliverables
PhishGuard AI is an autonomous, high-performance web interface designed for real-time phishing detection and cyber threat analysis. It provides security operations teams and end-users with instant verification of suspicious links, domain spoofing, and credential harvesting vectors.

### Key Components Built:
1. **Homepage & Hero Section**
   - Cyber-defense HUD aesthetic with matrix dust backdrop canvas.
   - Live Threat Telemetry ticker simulating global threat intercepts.
   - Quick sample pills for rapid demonstration (PayPal impersonation, crypto giveaways, raw IP hosts, legitimate domains).

2. **URL Input & Controls**
   - High-contrast glowing input bar with clipboard paste and one-click clear.
   - Real-time client-side protocol and URL syntax validator.
   - Toggle options for Shannon Entropy Matrix and SSL Chain validation.

3. **Multi-Stage Animated Scanning Pipeline (Radar HUD)**
   - Sweeping radar spinner with dynamic progress percentage (0% → 100%).
   - 4-Phase inspection pipeline:
     1. **Phase 1: DNS & Network Routing** (ASN telemetry, reverse PTR).
     2. **Phase 2: SSL / TLS Handshake** (Chain of trust, cipher integrity).
     3. **Phase 3: Lexical & Homoglyph Engine** (Shannon entropy, typosquatting).
     4. **Phase 4: AI Phishing Model** (Neural classification, credential harvesting).
   - Real-time streaming diagnostic terminal log with color-coded severity tags.
   - Built-in futuristic Web Audio API sound synthesizers (safe chimes, stage pass, danger alarms).

4. **Comprehensive Risk Report**
   - Dynamic Verdict Banner (`SAFE`, `SUSPICIOUS`, `PHISHING DETECTED`).
   - Circular SVG animated Risk Score Gauge (0–100 scale).
   - Brand Impersonation Alert Banner (flags spoofing targets like PayPal, Google, Microsoft, Apple, Binance).
   - 4 Detail Breakdown Cards:
     - **SSL / TLS Encryption**: Chain status, CA authority, cipher protocol.
     - **Domain & WHOIS Intel**: Domain age, registrar, ASN, country code.
     - **Lexical & Homoglyph Engine**: Shannon entropy calculation, subdomain depth, IP-in-hostname flag.
     - **Heuristic Threat Flags**: Specific indicators triggered (e.g. `@` obfuscation, high-risk TLD, credential keywords).
   - Actionable Security Recommendations.
   - One-Click Actions:
     - **Copy Report Summary** (formatted for tickets, Slack, or incident logs).
     - **Export JSON** (full machine-readable payload).
     - **Print / PDF Report** (clean print-optimized stylesheet).
   - Raw JSON inspector accordion.

5. **Responsive Security Dashboard**
   - 4 Live KPI Cards (Total Analyzed, Phishing Intercepted, Legitimate Verified, Average Latency).
   - Interactive 7-Day Threat Trend SVG Chart with gradient fills and guide lines.
   - Attack Vector Breakdown meters (Credential harvesting, Typosquatting, High-risk TLDs, IP obfuscation).
   - Top Targeted Brands Watchlist.
   - Filterable & Searchable Audit Log Table (filter by All, Phishing, Suspicious, Safe).
   - One-click historical report re-inspection.
   - CSV export functionality.

6. **Backend & ML Model Bridge Modal (Member 2 & Member 3 Ready)**
   - Pre-configured settings modal to point the UI to a live REST endpoint (e.g. `http://localhost:5000/api/scan` or `http://localhost:8000/scan`).
   - Seamless toggle between client-side autonomous heuristic engine and remote API proxy.

---

## 🚀 How to Run Locally

You can run PhishGuard AI using any local web server or by opening `index.html` directly in any modern browser:

### Option 1: Python Built-in Server (Recommended)
```powershell
python -m http.server 8080
```
Then navigate to: **`http://localhost:8080`**

### Option 2: Direct File Access
Simply double-click `index.html` or open `file:///.../index.html` in Chrome, Edge, Firefox, or Safari.

---

## 📂 Project Structure
```
Hack/
├── index.html          # Semantic HTML5 layout, HUD header, scanner, report, dashboard
├── css/
│   └── style.css       # Custom Cyber-Defense design system, tokens, glassmorphism, print CSS
├── js/
│   ├── scanner.js      # Lexical heuristics, Shannon entropy, brand homoglyphs, risk scoring
│   ├── dashboard.js    # Telemetry KPIs, SVG trend charts, history management, CSV export
│   └── app.js          # App orchestrator, Web Audio synth, multi-stage animation, modal events
└── README.md           # Documentation and team handover guide
```
