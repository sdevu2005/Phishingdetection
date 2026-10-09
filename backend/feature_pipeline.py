"""
PhishGuard AI — Feature Extraction Pipeline
Member 2 — Machine Learning

Transforms raw URLs into structured 24-dimensional feature vectors
engineered for zero-day phishing detection and classifier evaluation.
"""

import math
import re
from typing import Dict, Any, List, Union
from urllib.parse import urlparse
import pandas as pd
import numpy as np


class URLFeatureExtractor:
    """Production feature extraction engine for Cyber Threat Detection"""

    HIGH_RISK_TLDS = {
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
        ".cam", ".work", ".icu", ".fit", ".rest", ".sur", ".click",
        ".live", ".link", ".club", ".online", ".site", ".cc", ".su"
    }

    SENSITIVE_KEYWORDS = [
        "login", "signin", "verify", "verification", "update", "account",
        "banking", "secure", "confirm", "wallet", "auth", "recover",
        "suspended", "unlock", "password", "security-alert", "claim",
        "bonus", "airdrop", "invoice", "billing", "validate", "support"
    ]

    TARGET_BRANDS = {
        "PayPal": ["paypal", "paypa1", "pay-pal", "paypol", "paypall"],
        "Google": ["google", "g00gle", "goog1e", "g0ogle", "goog-le"],
        "Microsoft": ["microsoft", "micros0ft", "ms-verify", "office365", "o365", "outlook"],
        "Apple": ["apple", "appl-id", "apple-id", "icloud", "ic1oud"],
        "Amazon": ["amazon", "amaz0n", "amz-order", "aws-verify"],
        "Netflix": ["netflix", "netf1ix", "net-flix"],
        "Bank of America": ["bankofamerica", "bofa", "bank-america"],
        "Chase Bank": ["chase", "chase-security", "chasebank"],
        "Binance": ["binance", "binance-auth", "metamask", "coinbase", "crypto-claim"],
        "Meta / Facebook": ["facebook", "faceb00k", "meta-support", "instagram", "fb-verify"]
    }

    LEGITIMATE_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
        "github.com", "linkedin.com", "youtube.com", "netflix.com", "wikipedia.org",
        "stackoverflow.com", "gitlab.com", "reddit.com", "twitter.com", "x.com",
        "nytimes.com", "bbc.com", "cnn.com", "chase.com", "bankofamerica.com",
        "cloudflare.com", "stripe.com", "shopify.com", "zoom.us", "dropbox.com",
        "slack.com", "notion.so", "medium.com", "quora.com", "spotify.com"
    }

    FEATURE_NAMES = [
        "url_len",
        "host_len",
        "path_len",
        "query_len",
        "dots_count",
        "hyphens_count",
        "subdomain_depth",
        "slashes_count",
        "question_marks_count",
        "equals_count",
        "digits_count",
        "digit_ratio",
        "has_ip",
        "host_entropy",
        "url_entropy",
        "has_high_risk_tld",
        "keyword_count",
        "is_spoofing",
        "is_https",
        "has_at_symbol",
        "has_double_slash_redirect",
        "has_punycode",
        "special_chars_count",
        "is_verified_legit"
    ]

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Computes Shannon Entropy of character distribution (DGA indicator)"""
        if not text:
            return 0.0
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def extract_features_dict(cls, url: str) -> Dict[str, Any]:
        """Extracts complete feature dictionary for an individual URL"""
        clean_url = (url or "").strip()
        parsed = urlparse(clean_url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        full_url = clean_url.lower()

        # Structural & Lexical Metrics
        url_len = len(clean_url)
        host_len = len(hostname)
        path_len = len(path)
        query_len = len(query)

        dots_count = hostname.count(".")
        hyphens_count = hostname.count("-")
        subdomain_depth = max(0, dots_count - 1)
        slashes_count = clean_url.count("/")
        question_marks_count = clean_url.count("?")
        equals_count = clean_url.count("=")

        digits_count = sum(c.isdigit() for c in clean_url)
        digit_ratio = round(digits_count / max(1, url_len), 4)

        special_symbols = set("@?=&%-_~;:+")
        special_chars_count = sum(c in special_symbols for c in clean_url)

        # IP host detection
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        has_ip = 1 if re.match(ip_pattern, hostname) else 0

        # Shannon Entropy
        host_entropy = cls.calculate_entropy(hostname)
        url_entropy = cls.calculate_entropy(full_url)

        # High-risk TLD
        has_high_risk_tld = 1 if any(hostname.endswith(tld) for tld in cls.HIGH_RISK_TLDS) else 0

        # Sensitive Keywords
        keyword_hits = [kw for kw in cls.SENSITIVE_KEYWORDS if kw in full_url]
        keyword_count = len(keyword_hits)

        # Brand Spoofing / Impersonation Check
        detected_brand = None
        is_spoofing = 0
        for brand, patterns in cls.TARGET_BRANDS.items():
            for pat in patterns:
                if pat in full_url:
                    official = hostname == (patterns[0] + ".com") or hostname.endswith("." + patterns[0] + ".com")
                    if not official:
                        detected_brand = brand
                        is_spoofing = 1
                        break
            if detected_brand:
                break

        # Protocol & Obfuscation
        is_https = 1 if parsed.scheme == "https" else 0
        has_at_symbol = 1 if "@" in clean_url else 0
        has_double_slash_redirect = 1 if "//" in path else 0
        has_punycode = 1 if "xn--" in hostname else 0

        # Whitelist / Authority Domain Check
        is_verified_legit = 1 if any(
            hostname == dom or hostname.endswith("." + dom)
            for dom in cls.LEGITIMATE_DOMAINS
        ) else 0

        return {
            "url_len": url_len,
            "host_len": host_len,
            "path_len": path_len,
            "query_len": query_len,
            "dots_count": dots_count,
            "hyphens_count": hyphens_count,
            "subdomain_depth": subdomain_depth,
            "subdomains": subdomain_depth,
            "slashes_count": slashes_count,
            "question_marks_count": question_marks_count,
            "equals_count": equals_count,
            "digits_count": digits_count,
            "digit_ratio": digit_ratio,
            "has_ip": has_ip,
            "host_entropy": host_entropy,
            "url_entropy": url_entropy,
            "has_high_risk_tld": has_high_risk_tld,
            "keyword_count": keyword_count,
            "is_spoofing": is_spoofing,
            "is_https": is_https,
            "has_at_symbol": has_at_symbol,
            "has_double_slash_redirect": has_double_slash_redirect,
            "has_punycode": has_punycode,
            "special_chars_count": special_chars_count,
            "is_verified_legit": is_verified_legit,
            # Metadata keys (not directly used as numerical features in matrix)
            "detected_brand": detected_brand,
            "keyword_hits": keyword_hits
        }

    @classmethod
    def extract_features_vector(cls, url: str) -> List[Union[int, float]]:
        """Extracts numerical feature vector aligned with FEATURE_NAMES"""
        d = cls.extract_features_dict(url)
        return [float(d[col]) for col in cls.FEATURE_NAMES]

    @classmethod
    def extract_from_dataframe(cls, df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
        """Batch feature extraction from a pandas DataFrame of URLs"""
        records = []
        for url in df[url_col]:
            d = cls.extract_features_dict(url)
            # Only keep the feature matrix columns
            clean_record = {k: float(d[k]) for k in cls.FEATURE_NAMES}
            records.append(clean_record)
        return pd.DataFrame(records)


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=machine+learning",
        "http://paypal-verification-update.xyz/login.php?client_id=9821",
        "http://192.168.1.100/chase/verify.php",
        "http://google.com@evil-site.top/account/security-check"
    ]
    print(f"Feature Vector length: {len(URLFeatureExtractor.FEATURE_NAMES)}")
    for u in test_urls:
        vec = URLFeatureExtractor.extract_features_vector(u)
        d = URLFeatureExtractor.extract_features_dict(u)
        print(f"\nURL: {u}")
        print(f"  Spoofing: {d['is_spoofing']} (Brand: {d['detected_brand']})")
        print(f"  Has IP: {d['has_ip']}, Has @: {d['has_at_symbol']}, High Risk TLD: {d['has_high_risk_tld']}")
        print(f"  Host Entropy: {d['host_entropy']}, Keywords: {d['keyword_hits']}")
