"""
IOC Validators
Strict validation routines for IPs, Domains, URLs, Hashes (MD5, SHA1, SHA256), and Emails.
Non-AI rule-based and cryptographic validation using Python standard libraries.
"""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from threat_aggregator.models import IOCType
from threat_aggregator.defang import refang

# Regex for hashes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

# Regex for Domain validation (RFC 1035 / 1123)
# Matches domain names with at least 2 labels, valid TLD (2+ alpha chars)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Regex for Email
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

# Common non-routable / bogon networks for IPv4
BOGON_NETWORKS_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def is_valid_ipv4(value: str) -> Tuple[bool, bool]:
    """
    Validates IPv4 string.
    Returns: (is_valid, is_private_or_bogon)
    """
    clean = refang(value).strip()
    try:
        ip = ipaddress.IPv4Address(clean)
        is_bogon = any(ip in net for net in BOGON_NETWORKS_V4) or ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
        return True, is_bogon
    except (ipaddress.AddressValueError, ValueError):
        return False, False


def is_valid_ipv6(value: str) -> Tuple[bool, bool]:
    """
    Validates IPv6 string.
    Returns: (is_valid, is_private_or_bogon)
    """
    clean = refang(value).strip()
    try:
        ip = ipaddress.IPv6Address(clean)
        is_bogon = ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
        return True, is_bogon
    except (ipaddress.AddressValueError, ValueError):
        return False, False


def is_valid_domain(value: str) -> bool:
    """
    Validates internet domain name.
    Excludes pure IP addresses.
    """
    clean = refang(value).strip().lower()
    
    # Must not exceed 253 characters
    if not clean or len(clean) > 253:
        return False
        
    # Cannot be an IP address
    if is_valid_ipv4(clean)[0] or is_valid_ipv6(clean)[0]:
        return False

    # Check against domain regex
    if not DOMAIN_REGEX.match(clean):
        return False

    # Avoid common false positives (like filenames: file.exe, malware.zip)
    common_file_exts = {
        "exe", "dll", "zip", "tar", "gz", "rar", "bin", "sh", "bat", "py", 
        "txt", "doc", "docx", "pdf", "xls", "xlsx", "elf", "so", "dmg"
    }
    tld = clean.split(".")[-1].lower()
    if tld in common_file_exts:
        return False

    return True


def is_valid_url(value: str) -> bool:
    """
    Validates web URL format.
    Must have http, https, or ftp scheme and a valid netloc.
    """
    clean = refang(value).strip()
    if not clean or " " in clean:
        return False
    
    try:
        parsed = urlparse(clean)
        if parsed.scheme.lower() not in ("http", "https", "ftp"):
            return False
        if not parsed.netloc:
            return False
        
        # Strip port if present for host validation
        host = parsed.netloc.split(":")[0].strip("[]")
        
        # Host must be a valid IP or valid domain
        if is_valid_ipv4(host)[0] or is_valid_ipv6(host)[0] or is_valid_domain(host):
            return True
            
        return False
    except Exception:
        return False


def is_valid_md5(value: str) -> bool:
    clean = value.strip().lower()
    return bool(MD5_REGEX.match(clean))


def is_valid_sha1(value: str) -> bool:
    clean = value.strip().lower()
    return bool(SHA1_REGEX.match(clean))


def is_valid_sha256(value: str) -> bool:
    clean = value.strip().lower()
    return bool(SHA256_REGEX.match(clean))


def is_valid_email(value: str) -> bool:
    clean = refang(value).strip().lower()
    return bool(EMAIL_REGEX.match(clean))


def detect_and_validate_ioc(value: str) -> Optional[Tuple[IOCType, str, bool]]:
    """
    Automatically detects IOC type and verifies validity.
    Returns: (IOCType, canonical_value, is_private_or_bogon) or None if invalid.
    """
    if not value or not isinstance(value, str):
        return None
    
    clean = refang(value).strip()
    if not clean:
        return None

    # 1. Hashes (strictly based on length and hex representation)
    raw_hash = clean.lower()
    if len(raw_hash) == 32 and is_valid_md5(raw_hash):
        return IOCType.MD5, raw_hash, False
    if len(raw_hash) == 40 and is_valid_sha1(raw_hash):
        return IOCType.SHA1, raw_hash, False
    if len(raw_hash) == 64 and is_valid_sha256(raw_hash):
        return IOCType.SHA256, raw_hash, False

    # 2. URLs (Must have scheme or clear path structure)
    if clean.lower().startswith(("http://", "https://", "ftp://")):
        if is_valid_url(clean):
            return IOCType.URL, clean, False

    # 3. Emails
    if "@" in clean and is_valid_email(clean):
        return IOCType.EMAIL, clean.lower(), False

    # 4. IPv4
    is_ipv4, is_bogon = is_valid_ipv4(clean)
    if is_ipv4:
        return IOCType.IPV4, clean, is_bogon

    # 5. IPv6
    is_ipv6, is_bogon = is_valid_ipv6(clean)
    if is_ipv6:
        return IOCType.IPV6, clean.lower(), is_bogon

    # 6. Domain
    if is_valid_domain(clean):
        return IOCType.DOMAIN, clean.lower(), False

    return None
