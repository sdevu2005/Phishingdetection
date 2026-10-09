"""
PhishGuard AI — Dataset Generator for Machine Learning
Member 2 — Machine Learning

Generates a balanced, diverse benchmark dataset of phishing and legitimate URLs
covering realistic attack vectors (typosquatting, DGA entropy, subdomain stacking,
credential harvesting keywords, IP hosts, disposable TLDs) and legitimate domains.
"""

import os
import random
import csv
from typing import List, Tuple

# Reproducible random seed
random.seed(42)

# High-Risk TLDs often abused in phishing campaigns
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
    ".cam", ".work", ".icu", ".fit", ".rest", ".click", ".live",
    ".link", ".club", ".online", ".site", ".cc", ".su", ".top"
]

# Standard reputable TLDs
BENIGN_TLDS = [".com", ".org", ".net", ".edu", ".gov", ".io", ".dev", ".ai", ".co.uk", ".de"]

# Target Brands for Impersonation
TARGET_BRANDS = [
    ("paypal", ["paypa1", "pay-pal", "paypol", "paypall", "paypal-security", "paypal-verification"]),
    ("google", ["g00gle", "goog1e", "g0ogle", "goog-le", "google-security-auth", "google-drive-share"]),
    ("microsoft", ["micros0ft", "ms-verify", "office365-update", "o365-login", "outlook-security"]),
    ("apple", ["appl-id", "apple-id", "icloud-find", "ic1oud-verify", "appleid-support"]),
    ("amazon", ["amaz0n", "amz-order", "aws-verify-alert", "amazon-delivery-update"]),
    ("netflix", ["netf1ix", "net-flix", "netflix-billing-update", "netflix-renewal"]),
    ("bankofamerica", ["bofa-update", "bank-america-secure", "bofa-onlineauth"]),
    ("chase", ["chase-security", "chasebank-alert", "chase-secure-update"]),
    ("binance", ["binance-auth", "binance-airdrop", "binance-wallet-claim"]),
    ("coinbase", ["coinbase-support", "coinbase-auth-verify", "coinbase-claim"]),
    ("metamask", ["metamask-recovery", "metamask-seed-phrase", "metamask-wallet-claim"]),
    ("facebook", ["faceb00k", "meta-support-ticket", "fb-security-alert", "instagram-badge-verify"])
]

# Sensitive phishing keywords
KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "account",
    "banking", "secure", "confirm", "wallet", "auth", "recover",
    "suspended", "unlock", "password", "security-alert", "claim",
    "bonus", "airdrop", "invoice", "billing", "validate", "support"
]

# Real Legitimate Root Domains
AUTHORITATIVE_BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "github.com", "linkedin.com", "youtube.com", "netflix.com", "wikipedia.org",
    "stackoverflow.com", "gitlab.com", "reddit.com", "twitter.com", "x.com",
    "nytimes.com", "bbc.com", "cnn.com", "chase.com", "bankofamerica.com",
    "harvard.edu", "mit.edu", "stanford.edu", "cloudflare.com", "stripe.com",
    "shopify.com", "zoom.us", "dropbox.com", "slack.com", "notion.so",
    "medium.com", "quora.com", "spotify.com", "twitch.tv", "salesforce.com",
    "atlassian.com", "docker.com", "kubernetes.io", "mozilla.org", "python.org",
    "apache.org", "w3schools.com", "developer.mozilla.org", "kernel.org", "ubuntu.com"
]

BENIGN_PATHS = [
    "", "/about", "/contact", "/pricing", "/products", "/docs", "/documentation",
    "/blog/2026/how-to-secure-api", "/news/latest-release", "/support/help-center",
    "/careers", "/terms", "/privacy", "/features", "/tutorials/python-guide",
    "/explore", "/downloads", "/changelog", "/api/v1/status", "/resources/whitepaper"
]

BENIGN_QUERIES = [
    "", "?ref=homepage", "?utm_source=newsletter", "?page=2", "?sort=asc",
    "?query=security+best+practices", "?lang=en", "?view=grid", "?filter=all"
]


def generate_dga_domain(length: int = 14) -> str:
    """Generate algorithmic high-entropy hostname string (DGA simulation)"""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choices(chars, k=length))


def generate_phishing_url() -> str:
    """Generate realistic phishing URL spanning different threat archetypes"""
    pattern_type = random.choice([
        "typosquatting",
        "ip_address",
        "dga_high_entropy",
        "subdomain_stacking",
        "at_symbol_obfuscation",
        "keyword_stuffing",
        "disposable_tld",
        "punycode_homoglyph"
    ])

    scheme = random.choice(["http://", "https://", "http://"])  # Phishing often uses HTTP

    if pattern_type == "typosquatting":
        brand, variations = random.choice(TARGET_BRANDS)
        variant = random.choice(variations)
        tld = random.choice(SUSPICIOUS_TLDS + [".com", ".net", ".org"])
        path = f"/{random.choice(KEYWORDS)}/{random.choice(['index.php', 'auth.html', 'session', 'confirm'])}"
        query = f"?client_id={random.randint(1000, 9999)}&redirect=auth"
        return f"{scheme}{variant}{tld}{path}{query}"

    elif pattern_type == "ip_address":
        octets = [str(random.randint(1, 254)) for _ in range(4)]
        ip = ".".join(octets)
        brand = random.choice([b[0] for b in TARGET_BRANDS])
        path = f"/{brand}/{random.choice(KEYWORDS)}/verify.php"
        return f"http://{ip}{path}?token={generate_dga_domain(8)}"

    elif pattern_type == "dga_high_entropy":
        dga = generate_dga_domain(random.randint(12, 22))
        tld = random.choice(SUSPICIOUS_TLDS)
        kw = random.choice(KEYWORDS)
        return f"{scheme}{dga}{tld}/{kw}?session={random.randint(100000, 999999)}"

    elif pattern_type == "subdomain_stacking":
        brand = random.choice([b[0] for b in TARGET_BRANDS])
        sub1 = random.choice(["secure", "login", "account", "update", "verify"])
        sub2 = random.choice(["portal", "auth", "session", "ssl"])
        fake_root = f"{generate_dga_domain(8)}{random.choice(SUSPICIOUS_TLDS)}"
        return f"{scheme}{sub1}.{sub2}.{brand}.com.{fake_root}/login.html"

    elif pattern_type == "at_symbol_obfuscation":
        legit_target = random.choice(["paypal.com", "google.com", "bankofamerica.com", "chase.com"])
        evil_host = f"{generate_dga_domain(7)}{random.choice(SUSPICIOUS_TLDS)}"
        return f"http://{legit_target}@{evil_host}/account/security-check"

    elif pattern_type == "keyword_stuffing":
        kws = random.sample(KEYWORDS, k=random.randint(2, 4))
        host_stem = "-".join(kws[:2])
        tld = random.choice(SUSPICIOUS_TLDS)
        path = "/" + "/".join(kws[2:])
        return f"{scheme}{host_stem}{tld}{path}?action=validate"

    elif pattern_type == "punycode_homoglyph":
        punycode = f"xn--{generate_dga_domain(8)}"
        tld = random.choice([".com", ".net", ".xyz"])
        brand = random.choice([b[0] for b in TARGET_BRANDS])
        return f"{scheme}{punycode}{tld}/{brand}/login"

    else:  # disposable_tld
        host = f"portal-{random.choice(['secure', 'verify', 'update'])}-{random.randint(10, 99)}"
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"{scheme}{host}{tld}/auth/recover"


def generate_legitimate_url() -> str:
    """Generate realistic benign URL"""
    domain = random.choice(AUTHORITATIVE_BENIGN_DOMAINS)
    sub = random.choice(["", "www.", "api.", "developer.", "support.", "docs.", "blog."])
    host = f"{sub}{domain}" if sub else domain
    path = random.choice(BENIGN_PATHS)
    query = random.choice(BENIGN_QUERIES)
    scheme = "https://"  # Most modern legitimate websites enforce HTTPS
    return f"{scheme}{host}{path}{query}"


def build_dataset(num_samples: int = 2400) -> List[Tuple[str, int]]:
    """Build a balanced dataset of phishing (1) and legitimate (0) URLs"""
    samples: List[Tuple[str, int]] = []
    half = num_samples // 2

    # Phishing samples
    phishing_set = set()
    while len(phishing_set) < half:
        url = generate_phishing_url()
        phishing_set.add(url)
    for u in phishing_set:
        samples.append((u, 1))

    # Legitimate samples
    benign_set = set()
    while len(benign_set) < half:
        url = generate_legitimate_url()
        benign_set.add(url)
    for u in benign_set:
        samples.append((u, 0))

    random.shuffle(samples)
    return samples


def save_dataset_to_csv(filepath: str, num_samples: int = 2400) -> str:
    """Saves the generated benchmark dataset to CSV"""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    dataset = build_dataset(num_samples)

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in dataset:
            writer.writerow([url, label])

    print(f"Dataset successfully generated with {len(dataset)} balanced samples at: {filepath}")
    return filepath


if __name__ == "__main__":
    output_path = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_dataset.csv")
    save_dataset_to_csv(output_path, num_samples=2400)
