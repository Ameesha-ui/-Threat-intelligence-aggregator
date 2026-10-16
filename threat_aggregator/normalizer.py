"""
Normalization Engine
Standardizes, refangs, deduplicates, and validates threat intelligence indicators.
Converts heterogeneous RawIndicators into canonical UnifiedIOC records.
"""

import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Tuple
from urllib.parse import urlparse, urlunparse

from threat_aggregator.models import RawIndicator, UnifiedIOC, IOCType, Severity
from threat_aggregator.defang import refang, defang
from threat_aggregator.validators import detect_and_validate_ioc


def canonicalize_ioc(val: str, ioc_type: IOCType) -> str:
    """
    Standardizes indicator representation to ensure exact cross-feed matching.
    """
    clean = refang(val).strip()

    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.EMAIL, IOCType.DOMAIN):
        clean = clean.lower()
        if ioc_type == IOCType.DOMAIN:
            clean = clean.rstrip(".")

    elif ioc_type == IOCType.URL:
        try:
            parsed = urlparse(clean)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path or "/"
            # Reconstruct canonical URL
            clean = urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))
        except Exception:
            pass

    elif ioc_type in (IOCType.IPV4, IOCType.IPV6):
        clean = clean.lower()

    return clean


def generate_ioc_id(ioc_type: IOCType, canonical_val: str) -> str:
    """Generates a reproducible 16-character SHA-256 fingerprint ID."""
    raw = f"{ioc_type.value}:{canonical_val}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


class NormalizationEngine:
    """
    Transforms a stream of RawIndicators into a deduplicated collection of UnifiedIOCs.
    """

    def __init__(self, filter_bogons: bool = False):
        self.filter_bogons = filter_bogons

    def normalize(self, raw_indicators: List[RawIndicator]) -> List[UnifiedIOC]:
        """
        Processes, validates, refangs, deduplicates, and aggregates raw indicators.
        """
        ioc_map: Dict[str, UnifiedIOC] = {}

        now_iso = datetime.now(timezone.utc).isoformat()

        for raw in raw_indicators:
            # 1. Validation and Type Detection
            detected = detect_and_validate_ioc(raw.value)
            if not detected:
                continue

            detected_type, validated_val, is_bogon = detected

            # Optionally filter out bogon / private IPs if requested
            if self.filter_bogons and is_bogon:
                continue

            # 2. Canonicalize
            canonical_val = canonicalize_ioc(validated_val, detected_type)
            ioc_id = generate_ioc_id(detected_type, canonical_val)

            # Determine timestamp
            ts = raw.timestamp or now_iso

            # 3. Deduplicate / Aggregate
            if ioc_id in ioc_map:
                existing = ioc_map[ioc_id]
                existing.occurrence_count += 1
                if raw.source not in existing.sources:
                    existing.sources.append(raw.source)
                    existing.feed_count = len(existing.sources)

                # Update tags
                for tag in raw.tags:
                    if tag and tag not in existing.tags:
                        existing.tags.append(tag)

                # Update timestamps
                if ts < existing.first_seen:
                    existing.first_seen = ts
                if ts > existing.last_seen:
                    existing.last_seen = ts

                # Retain bogon flag
                if is_bogon:
                    existing.is_private_or_bogon = True

            else:
                ioc_map[ioc_id] = UnifiedIOC(
                    id=ioc_id,
                    ioc_type=detected_type,
                    value=canonical_val,
                    defanged_value=defang(canonical_val),
                    sources=[raw.source],
                    first_seen=ts,
                    last_seen=ts,
                    occurrence_count=1,
                    feed_count=1,
                    severity=Severity.LOW,  # Will be dynamically scored by correlation engine
                    confidence=raw.confidence if raw.confidence is not None else 50,
                    tags=list(set(raw.tags)),
                    is_private_or_bogon=is_bogon,
                    metadata={"initial_feed_format": raw.feed_format}
                )

        return list(ioc_map.values())
