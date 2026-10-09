"""
Input Validation and SSRF Protection Module
Member 3 — Backend
"""

import ipaddress
import re
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to inspect", min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def clean_and_validate_url(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty")

        # Auto-prepend https if missing scheme
        if not (clean.startswith("http://") or clean.startswith("https://")):
            clean = "https://" + clean

        parsed = urlparse(clean)
        if not parsed.netloc:
            raise ValueError("Invalid URL structure: Hostname missing")

        # Basic host format check
        host = parsed.netloc.split(":")[0].strip()
        if len(host) < 2 or " " in host:
            raise ValueError("Invalid hostname format")

        return clean


class URLValidator:
    """Performs safety checks including private network / SSRF filters"""

    PRIVATE_IP_RANGES = [
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("10.0.0.0/8"),       # Private A
        ipaddress.ip_network("172.16.0.0/12"),    # Private B
        ipaddress.ip_network("192.168.0.0/16"),   # Private C
        ipaddress.ip_network("169.254.0.0/16"),   # Link-Local / Cloud Metadata
        ipaddress.ip_network("::1/128"),          # IPv6 Loopback
        ipaddress.ip_network("fc00::/7"),         # IPv6 Private
        ipaddress.ip_network("fe80::/10"),        # IPv6 Link-Local
    ]

    @classmethod
    def is_private_or_loopback_ip(cls, hostname: str) -> bool:
        # Strip port if present
        host = hostname.split(":")[0].strip()
        if host.lower() == "localhost":
            return True

        try:
            ip = ipaddress.ip_address(host)
            for network in cls.PRIVATE_IP_RANGES:
                if ip in network:
                    return True
        except ValueError:
            # Not a raw IP address
            pass
        return False

    @classmethod
    def sanitize_for_display(cls, text: str) -> str:
        if not text:
            return ""
        # Strip potential control characters
        return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)[:500]
