"""
Threat Intelligence Aggregator (Non-AI) Package
A deterministic, rule-based cybersecurity aggregator for collecting, normalizing,
correlating, and exporting Indicators of Compromise (IOCs).
"""

from threat_aggregator.models import IOCType, Severity, UnifiedIOC, FeedDefinition, RawIndicator
from threat_aggregator.collector import FeedCollector
from threat_aggregator.normalizer import NormalizationEngine
from threat_aggregator.correlation import CorrelationEngine
from threat_aggregator.blocklist import BlocklistGenerator
from threat_aggregator.reporter import ThreatReporter

__version__ = "1.0.0"
__all__ = [
    "IOCType",
    "Severity",
    "UnifiedIOC",
    "FeedDefinition",
    "RawIndicator",
    "FeedCollector",
    "NormalizationEngine",
    "CorrelationEngine",
    "BlocklistGenerator",
    "ThreatReporter"
]
