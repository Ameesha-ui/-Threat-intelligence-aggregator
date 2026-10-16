"""
CSV Feed Parser
Parses structured CSV threat feeds with dynamic header detection and delimiter sniffing.
"""

import csv
import io
from typing import List, Optional, Dict, Any

from threat_aggregator.parsers.base import BaseParser
from threat_aggregator.models import RawIndicator
from threat_aggregator.validators import detect_and_validate_ioc


INDICATOR_ALIASES = {
    "indicator", "ioc", "value", "address", "ip", "domain", 
    "host", "hash", "url", "target", "item", "malicious_indicator"
}

TYPE_ALIASES = {
    "type", "ioc_type", "indicator_type", "category", "kind"
}

TAG_ALIASES = {
    "threat", "threat_type", "malware", "campaign", "tag", "tags", 
    "classification", "description", "label", "family"
}

TIMESTAMP_ALIASES = {
    "timestamp", "date", "first_seen", "last_seen", "created", "reported", "time"
}

CONFIDENCE_ALIASES = {
    "confidence", "severity", "score", "risk"
}


class CSVParser(BaseParser):
    """Parser for comma-, semicolon-, or tab-delimited feeds."""

    def parse(self, content: str) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        if not content or not content.strip():
            return results

        # Sniff delimiter
        first_few_lines = "\n".join(content.strip().splitlines()[:5])
        try:
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(first_few_lines, delimiters=",\t;|")
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ","

        reader = csv.reader(io.StringIO(content.strip()), delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return results

        # Check for header
        header_row = [c.strip().lower() for c in rows[0]]
        indicator_idx: Optional[int] = None
        type_idx: Optional[int] = None
        tag_idx: Optional[int] = None
        time_idx: Optional[int] = None
        conf_idx: Optional[int] = None

        for idx, col in enumerate(header_row):
            clean_col = col.replace("_", "").replace(" ", "").replace("-", "")
            if col in INDICATOR_ALIASES or clean_col in INDICATOR_ALIASES:
                indicator_idx = idx
            elif col in TYPE_ALIASES or clean_col in TYPE_ALIASES:
                type_idx = idx
            elif col in TAG_ALIASES or clean_col in TAG_ALIASES:
                tag_idx = idx
            elif col in TIMESTAMP_ALIASES or clean_col in TIMESTAMP_ALIASES:
                time_idx = idx
            elif col in CONFIDENCE_ALIASES or clean_col in CONFIDENCE_ALIASES:
                conf_idx = idx

        has_header = indicator_idx is not None
        start_row = 1 if has_header else 0

        # If no explicit header matched, assume column 0 is the indicator
        if indicator_idx is None:
            indicator_idx = 0

        for row_num, row in enumerate(rows[start_row:], start=start_row + 1):
            if not row or len(row) <= indicator_idx:
                continue

            val = row[indicator_idx].strip()
            if not val or val.startswith("#"):
                continue

            # Skip header lookalikes in body
            if val.lower() in INDICATOR_ALIASES:
                continue

            detected = detect_and_validate_ioc(val)
            if not detected:
                continue

            ioc_type, _, _ = detected

            tags = list(self.feed_def.default_tags)
            if tag_idx is not None and tag_idx < len(row):
                raw_tags = row[tag_idx].strip()
                if raw_tags:
                    for t in raw_tags.replace(";", ",").split(","):
                        if t.strip():
                            tags.append(t.strip().lower())

            timestamp = None
            if time_idx is not None and time_idx < len(row):
                timestamp = row[time_idx].strip() or None

            confidence = None
            if conf_idx is not None and conf_idx < len(row):
                try:
                    confidence = int(row[conf_idx].strip())
                except ValueError:
                    pass

            meta: Dict[str, Any] = {
                "source_line": row_num,
                "feed_name": self.feed_def.name,
                "feed_format": "csv"
            }

            results.append(
                RawIndicator(
                    value=val,
                    ioc_type=ioc_type,
                    source=self.feed_def.name,
                    feed_format="csv",
                    timestamp=timestamp,
                    tags=tags,
                    confidence=confidence,
                    raw_metadata=meta
                )
            )

        return results
