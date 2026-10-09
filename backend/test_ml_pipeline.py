"""
Test Suite for Member 2 Machine Learning Subsystem
Verifies:
1. Feature extraction correctness
2. Serialized model loading
3. Prediction accuracy on known test URLs
4. Response shape and contract compliance for Member 1 & Member 3
"""

import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_pipeline import URLFeatureExtractor
from model import phish_model

def run_tests():
    print("=" * 60)
    print("TESTING MEMBER 2 MACHINE LEARNING SUBSYSTEM")
    print("=" * 60)

    # Test 1: Model Loaded
    assert phish_model.model_loaded is True, "Model should be loaded from joblib!"
    print("[PASS] Trained ML Model is successfully loaded in memory.")

    # Test 2: Feature Extractor
    sample_url = "http://paypal-verification.xyz/login.php?client_id=123"
    features = URLFeatureExtractor.extract_features_dict(sample_url)
    assert features["url_len"] == len(sample_url), "url_len mismatch"
    assert features["is_spoofing"] == 1, "Should detect spoofing"
    assert features["has_high_risk_tld"] == 1, "Should detect .xyz high risk TLD"
    assert "login" in features["keyword_hits"], "Should detect login keyword"
    print("[PASS] Feature extraction logic verified.")

    # Test 3: Predictions on Phishing URLs
    phishing_cases = [
        "http://paypal-verify-account.xyz/login.php",
        "http://192.168.1.100/chase/auth/verify.html",
        "http://google.com@phish-domain.top/account/security-check",
        "http://x9f8w123zq78lm.biz/wallet?session=472409"
    ]
    for url in phishing_cases:
        res = phish_model.predict(url)
        assert res["verdict_severity"] in ["danger", "warning"], f"Expected danger/warning for {url}, got {res['verdict_severity']}"
        assert res["risk_score"] >= 50, f"Expected high risk score for {url}, got {res['risk_score']}"
        assert len(res["top_risk_factors"]) > 0, f"Expected risk factors for {url}"
        print(f" [PASS] Phishing detected: {url[:45]}... -> Score: {res['risk_score']} ({res['verdict']})")

    # Test 4: Predictions on Legitimate URLs
    benign_cases = [
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/torvalds/linux",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://developer.mozilla.org/en-US/docs/Web/API"
    ]
    for url in benign_cases:
        res = phish_model.predict(url)
        assert res["verdict_severity"] == "safe", f"Expected safe for {url}, got {res['verdict_severity']}"
        assert res["risk_score"] < 25, f"Expected low risk score for {url}, got {res['risk_score']}"
        print(f" [PASS] Benign verified:   {url[:45]}... -> Score: {res['risk_score']} ({res['verdict']})")

    print("\n[ALL 4 TEST SUITES PASSED SUCCESSFULLY]")

if __name__ == "__main__":
    run_tests()
