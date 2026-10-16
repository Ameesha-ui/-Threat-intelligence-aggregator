"""
IOC Correlation Engine
Cross-feed correlation, frequency analysis, and deterministic risk scoring (Non-AI).
"""

from typing import List, Dict, Set, Tuple, Any
from collections import defaultdict

from threat_aggregator.models import UnifiedIOC, Severity, FeedDefinition


HIGH_RISK_TAGS = {
    "ransomware", "c2", "command-and-control", "apt", "exploit",
    "cobaltstrike", "beacon", "infostealer", "trojan", "botnet",
    "zero-day", "payload", "credential-theft", "rootkit"
}

MEDIUM_RISK_TAGS = {
    "phishing", "scam", "spam", "scanner", "bruteforce", "proxy", "vpn"
}


class CorrelationEngine:
    """
    Correlates indicators across multiple feeds, calculates repetition metrics,
    and assigns deterministic severity ratings.
    """

    def __init__(self, feed_weights: Dict[str, float] = None):
        # Default weight of 1.0 for unspecified feeds
        self.feed_weights = feed_weights or {}

    def correlate(self, iocs: List[UnifiedIOC]) -> List[UnifiedIOC]:
        """
        Calculates correlation metrics, composite risk scores, and severity classifications.
        """
        for ioc in iocs:
            # 1. Distinct feeds and total occurrences
            num_feeds = len(ioc.sources)
            ioc.feed_count = num_feeds

            # 2. Weighted Source Score
            weighted_feed_score = sum(self.feed_weights.get(src, 1.0) for src in ioc.sources)

            # 3. Base Score from feed count
            if num_feeds >= 4:
                base_score = 75
            elif num_feeds == 3:
                base_score = 60
            elif num_feeds == 2:
                base_score = 45
            else:
                base_score = 25

            # 4. Multiplier / adjustment from feed reputation
            rep_boost = min(15.0, (weighted_feed_score - 1.0) * 8.0)

            # 5. Tag Risk Boost
            tag_boost = 0
            has_high_risk_tag = False
            for t in ioc.tags:
                t_lower = t.lower()
                if any(hr in t_lower for hr in HIGH_RISK_TAGS):
                    tag_boost = max(tag_boost, 15)
                    has_high_risk_tag = True
                elif any(mr in t_lower for mr in MEDIUM_RISK_TAGS):
                    tag_boost = max(tag_boost, 8)

            # 6. Composite Score (0 - 100)
            composite_score = int(min(100, max(10, base_score + rep_boost + tag_boost)))
            ioc.confidence = composite_score

            # 7. Severity Rating Assignment
            if num_feeds >= 3 or (num_feeds >= 2 and has_high_risk_tag) or composite_score >= 85:
                ioc.severity = Severity.CRITICAL
            elif num_feeds >= 2 or composite_score >= 65 or has_high_risk_tag:
                ioc.severity = Severity.HIGH
            elif composite_score >= 40:
                ioc.severity = Severity.MEDIUM
            else:
                ioc.severity = Severity.LOW

            # Flag bogon / private
            if ioc.is_private_or_bogon:
                ioc.metadata["warning"] = "RFC1918 or Bogon address detected. Exclude from public egress blocklists."

        # Sort in descending order of feed count and confidence
        iocs.sort(key=lambda x: (x.feed_count, x.confidence, x.occurrence_count), reverse=True)
        return iocs

    def generate_correlation_matrix(self, iocs: List[UnifiedIOC]) -> Dict[str, Any]:
        """
        Produces detailed analytical statistics about feed overlaps, repeated indicators,
        and high-risk cross-source intelligence.
        """
        feed_overlap_matrix: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        feed_ioc_counts: Dict[str, int] = defaultdict(int)
        repeated_iocs: List[UnifiedIOC] = []

        for ioc in iocs:
            for src in ioc.sources:
                feed_ioc_counts[src] += 1

            if len(ioc.sources) > 1:
                repeated_iocs.append(ioc)
                for src_a in ioc.sources:
                    for src_b in ioc.sources:
                        if src_a != src_b:
                            feed_overlap_matrix[src_a][src_b] += 1

        # Convert defaultdicts to regular dicts for clean JSON serialization
        clean_matrix: Dict[str, Dict[str, int]] = {k: dict(v) for k, v in feed_overlap_matrix.items()}

        return {
            "total_correlated_iocs": len(iocs),
            "total_repeated_iocs": len(repeated_iocs),
            "repetition_ratio": round(len(repeated_iocs) / max(1, len(iocs)), 4),
            "feed_ioc_counts": dict(feed_ioc_counts),
            "feed_overlap_matrix": clean_matrix,
            "top_repeated_iocs": [ioc.to_dict() for ioc in repeated_iocs[:20]],
        }
