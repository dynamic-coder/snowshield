import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "free", "gift", "claim", "password"
]


def has_ip_address(domain: str) -> int:
    """Return 1 if the domain looks like an IP address."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return 1 if re.match(pattern, domain) else 0



def extract_features(url: str):
    """Convert a URL into a list of numeric features."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = (domain + path).lower()

    features = [
        len(url),                              # URL length
        domain.count('.'),                     # Number of dots
        domain.count('-'),                     # Number of hyphens
        url.count('/'),                        # Number of slashes
        url.count('@'),                        # Number of @ symbols
        sum(c.isdigit() for c in url),         # Number of digits
        1 if parsed.scheme == 'https' else 0,  # Uses HTTPS
        has_ip_address(domain),                # Domain is an IP address
        len(domain),                           # Domain length
        domain.count('.'),                     # Number of subdomain separators
        sum(1 for word in SUSPICIOUS_WORDS if word in full),  # Suspicious words count
        1 if any(tld in domain for tld in ['.xyz', '.top', '.click', '.info']) else 0,
    ]

    return features