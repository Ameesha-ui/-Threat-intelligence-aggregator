"""
Threat Intelligence Aggregator - Core Data Models
Unified schema and enumerations for threat indicators and feeds.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        scores = {
            Severity.INFO: 10,
            Severity.LOW: 25,
            Severity.MEDIUM: 50,
            Severity.HIGH: 75,
            Severity.CRITICAL: 100
        }
        return scores.get(self, 0)


@dataclass
class RawIndicator:
    """Represents an indicator as extracted from a raw source feed."""
    value: str
    ioc_type: Optional[IOCType] = None
    source: str = "unknown"
    feed_format: str = "raw"
    timestamp: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    confidence: Optional[int] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedIOC:
    """Normalized, canonical representation of a Threat Intelligence Indicator."""
    id: str  # Unique canonical hash
    ioc_type: IOCType
    value: str  # Canonical refanged value
    defanged_value: str  # Safe display value (e.g. hxxp://, 1[.]1[.]1[.]1)
    sources: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    occurrence_count: int = 1
    feed_count: int = 1
    severity: Severity = Severity.LOW
    confidence: int = 50  # 0 - 100 scale
    tags: List[str] = field(default_factory=list)
    is_private_or_bogon: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "defanged_value": self.defanged_value,
            "sources": self.sources,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrence_count": self.occurrence_count,
            "feed_count": self.feed_count,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "tags": sorted(list(set(self.tags))),
            "is_private_or_bogon": self.is_private_or_bogon,
            "metadata": self.metadata
        }


@dataclass
class FeedDefinition:
    """Configuration for an ingestion source."""
    name: str
    format: str  # csv, txt, json, stix
    path_or_url: str
    enabled: bool = True
    weight: float = 1.0  # Reputation multiplier (0.5 to 2.0)
    category: str = "external_osint"
    default_tags: List[str] = field(default_factory=list)
    max_indicators: Optional[int] = None
