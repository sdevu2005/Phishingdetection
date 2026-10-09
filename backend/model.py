"""
PhishGuard AI — Machine Learning Model & Feature Extraction Engine
Member 2 — Machine Learning & Member 3 Backend Integration

Implements production feature extraction, loads the trained Random Forest classifier
from data/phishguard_model.joblib, and provides risk scoring and threat explanations.
"""

import os
import json
from typing import Dict, Any, List
import pandas as pd

from feature_pipeline import URLFeatureExtractor

# Re-export PhishFeatureExtractor for backward-compatibility with Member 3
class PhishFeatureExtractor(URLFeatureExtractor):
    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        return cls.extract_features_dict(url)


class PhishMLClassifier:
    """
    Trained Production Machine Learning Classifier for Zero-Day Phishing Detection
    Loads serialized Random Forest model with automatic heuristic fallback.
    """

    def __init__(self):
        self.model = None
        self.feature_columns = URLFeatureExtractor.FEATURE_NAMES
        self.model_loaded = False

        # Attempt to load serialized model artifact
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "..", "data", "phishguard_model.joblib")
        features_meta_path = os.path.join(base_dir, "..", "data", "feature_columns.json")

        try:
            import joblib
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.model_loaded = True
                if os.path.exists(features_meta_path):
                    with open(features_meta_path, "r", encoding="utf-8") as f:
                        self.feature_columns = json.load(f)
                print(f"[OK] PhishGuard AI ML Model successfully loaded from: {model_path}")
        except Exception as e:
            print(f"[WARN] Failed to load trained ML model ({e}). Using heuristic ensemble fallback.")
            self.model = None
            self.model_loaded = False

        # Heuristic calibration weights (fallback)
        self.weights = {
            "is_spoofing": 0.38,
            "has_ip": 0.28,
            "has_at_symbol": 0.25,
            "has_high_risk_tld": 0.20,
            "insecure_http": 0.18,
            "keyword_density": 0.16,
            "high_entropy": 0.14,
            "subdomain_stacking": 0.12,
            "hyphen_density": 0.10,
        }

    def _extract_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Constructs human-readable risk factor telemetry for HUD and reports"""
        risk_factors: List[str] = []

        if features["is_spoofing"]:
            risk_factors.append(f"Brand Impersonation / Typosquatting ({features.get('detected_brand')})")

        if features["has_ip"]:
            risk_factors.append("Direct IP Address used as Hostname")

        if features["has_at_symbol"]:
            risk_factors.append("URL Obfuscation with '@' credential prefix")

        if features["has_high_risk_tld"]:
            risk_factors.append("High-Risk / Low-Reputation Top-Level Domain")

        if not features["is_https"]:
            risk_factors.append("Insecure Plaintext HTTP protocol")

        if features["keyword_count"] > 0:
            hits = features.get("keyword_hits", [])
            kw_str = ", ".join(hits[:3]) if hits else f"{features['keyword_count']} detected"
            risk_factors.append(f"Credential Harvesting Keywords ({kw_str})")

        if features["host_entropy"] > 3.85:
            risk_factors.append(f"High Lexical Entropy ({features['host_entropy']} bits)")

        if features["subdomain_depth"] >= 3:
            risk_factors.append(f"Excessive Subdomain Depth ({features['subdomain_depth']} levels)")

        if features["hyphens_count"] >= 3:
            risk_factors.append(f"Multiple Hyphen Chains in Hostname ({features['hyphens_count']})")

        if features["has_double_slash_redirect"]:
            risk_factors.append("Path contains '//' redirection sequence")

        if features["has_punycode"]:
            risk_factors.append("Internationalized Punycode homoglyph detected")

        return risk_factors

    def predict(self, url: str) -> Dict[str, Any]:
        features = URLFeatureExtractor.extract_features_dict(url)
        risk_factors = self._extract_risk_factors(features)

        # 1. Immediate whitelist check for authoritative domains
        if features["is_verified_legit"] and not features["is_spoofing"] and not features["has_ip"] and features["is_https"]:
            return {
                "prediction": "Legitimate",
                "risk_score": 3,
                "confidence": 0.99,
                "verdict": "SAFE",
                "verdict_severity": "safe",
                "features": features,
                "top_risk_factors": [],
                "model_engine": "Trained Random Forest (Whitelisted Clean)"
            }

        # 2. ML Model Inference
        if self.model_loaded and self.model is not None:
            try:
                # Prepare single-row DataFrame with named columns to avoid scikit-learn warnings
                feat_row = {col: float(features.get(col, 0.0)) for col in self.feature_columns}
                input_df = pd.DataFrame([feat_row])

                if hasattr(self.model, "predict_proba"):
                    proba_classes = self.model.predict_proba(input_df)[0]
                    # Probability of class 1 (Phishing)
                    prob_phishing = float(proba_classes[1])
                else:
                    pred = self.model.predict(input_df)[0]
                    prob_phishing = float(pred)

                # Calibrate probability if severe heuristic signals exist
                if features["is_spoofing"] or features["has_ip"] or features["has_at_symbol"]:
                    prob_phishing = max(prob_phishing, 0.75)

                risk_score = int(round(prob_phishing * 100))
                confidence = round(max(prob_phishing, 1.0 - prob_phishing), 3)

                if risk_score >= 65:
                    verdict = "PHISHING DETECTED"
                    verdict_severity = "danger"
                    prediction = "Phishing"
                elif risk_score >= 25:
                    verdict = "SUSPICIOUS"
                    verdict_severity = "warning"
                    prediction = "Suspicious"
                else:
                    verdict = "SAFE"
                    verdict_severity = "safe"
                    prediction = "Legitimate"

                return {
                    "prediction": prediction,
                    "risk_score": risk_score,
                    "confidence": confidence,
                    "verdict": verdict,
                    "verdict_severity": verdict_severity,
                    "features": features,
                    "top_risk_factors": risk_factors,
                    "model_engine": "Trained Random Forest (Production ML)"
                }
            except Exception as e:
                print(f"[WARN] ML inference exception ({e}). Falling back to heuristic ensemble.")

        # 3. Fallback Heuristic Calculation
        score = 0.0
        if features["is_spoofing"]:
            score += self.weights["is_spoofing"]
        if features["has_ip"]:
            score += self.weights["has_ip"]
        if features["has_at_symbol"]:
            score += self.weights["has_at_symbol"]
        if features["has_high_risk_tld"]:
            score += self.weights["has_high_risk_tld"]
        if not features["is_https"]:
            score += self.weights["insecure_http"]
        if features["keyword_count"] > 0:
            kw_weight = min(self.weights["keyword_density"], features["keyword_count"] * 0.06)
            score += kw_weight
        if features["host_entropy"] > 3.85:
            score += self.weights["high_entropy"]
        if features["subdomain_depth"] >= 3:
            score += self.weights["subdomain_stacking"]
        if features["hyphens_count"] >= 3:
            score += self.weights["hyphen_density"]

        probability = min(1.0, max(0.02, score))
        risk_score = int(round(probability * 100))

        if risk_score >= 65:
            verdict = "PHISHING DETECTED"
            verdict_severity = "danger"
            prediction = "Phishing"
            confidence = round(0.70 + (probability * 0.28), 3)
        elif risk_score >= 25:
            verdict = "SUSPICIOUS"
            verdict_severity = "warning"
            prediction = "Suspicious"
            confidence = round(0.60 + (probability * 0.25), 3)
        else:
            verdict = "SAFE"
            verdict_severity = "safe"
            prediction = "Legitimate"
            confidence = round(1.0 - probability, 3)

        return {
            "prediction": prediction,
            "risk_score": risk_score,
            "confidence": confidence,
            "verdict": verdict,
            "verdict_severity": verdict_severity,
            "features": features,
            "top_risk_factors": risk_factors,
            "model_engine": "Heuristic Rule-Based Ensemble"
        }


# Global model singleton
phish_model = PhishMLClassifier()
