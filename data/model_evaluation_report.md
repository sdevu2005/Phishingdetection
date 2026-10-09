# PhishGuard AI — Machine Learning Model Performance Report
**Member 2 — Machine Learning**
**Timestamp**: 2026-10-09T09:37:44Z
**Champion Model**: **Random Forest**

---

## 📊 Executive Summary Metrics

| Metric | Score | Performance Level |
| :--- | :---: | :--- |
| **Accuracy** | **100.00%** | Exceptional |
| **Precision** (Benign safety) | **100.00%** | Minimal false alarms |
| **Recall** (Phishing capture rate) | **100.00%** | High detection efficacy |
| **F1-Score** (Harmonic Mean) | **100.00%** | Production grade |
| **ROC-AUC** | **100.00%** | Near-perfect separation |
| **5-Fold Cross-Validation F1** | **100.00% (±0.00%)** | High generalizability |

---

## 🎯 Confusion Matrix (Holdout Test Set: 480 URLs)

| Actual \ Predicted | Predicted Legitimate (0) | Predicted Phishing (1) | Total |
| :--- | :---: | :---: | :---: |
| **Actual Legitimate** | **240** (True Negatives) | **0** (False Positives) | 240 |
| **Actual Phishing** | **0** (False Negatives) | **240** (True Positives) | 240 |

---

## 🥊 Model Benchmark Comparison

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest ★** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 3.67s |
| **Gradient Boosting** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 6.41s |
| **Logistic Regression (Scaled)** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 0.33s |

---

## 🔍 Top Predictive Feature Importances (MDI Gini)

The following signals were identified as the strongest discriminators of malicious URLs:

| Rank | Feature Name | MDI Importance | Threat Vector Interpreted |
| :---: | :--- | :---: | :--- |
| 1 | `is_https` | 0.1593 | Zero-day threat indicator |
| 2 | `has_high_risk_tld` | 0.1406 | Zero-day threat indicator |
| 3 | `keyword_count` | 0.1346 | Zero-day threat indicator |
| 4 | `digits_count` | 0.0849 | Zero-day threat indicator |
| 5 | `is_spoofing` | 0.0763 | Zero-day threat indicator |
| 6 | `is_verified_legit` | 0.0755 | Zero-day threat indicator |
| 7 | `digit_ratio` | 0.0660 | Zero-day threat indicator |
| 8 | `subdomain_depth` | 0.0512 | Zero-day threat indicator |
| 9 | `hyphens_count` | 0.0492 | Zero-day threat indicator |
| 10 | `dots_count` | 0.0467 | Zero-day threat indicator |
