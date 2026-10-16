"""
JSON Threat Feed Parser
Parses structured JSON feeds (URLhaus, MISP, AlienVault pulse formats, generic lists).
"""

import json
from typing import List, Dict, Any, Union

from threat_aggregator.parsers.base import BaseParser
from threat_aggregator.models import RawIndicator
from threat_aggregator.validators import detect_and_validate_ioc

INDICATOR_KEYS = {"indicator", "ioc", "value", "url", "ip", "domain", "host", "hash", "sha256", "md5"}
TAG_KEYS = {"tags", "tag", "threat", "malware", "classification", "category"}
TIME_KEYS = {"date_added", "timestamp", "first_seen", "created", "reported", "time"}
CONF_KEYS = {"confidence", "confidence_level", "threat_level_id", "severity"}


class JSONParser(BaseParser):
    """Parses JSON arrays or objects containing threat intelligence data."""

    def parse(self, content: str) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        if not content or not content.strip():
            return results

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return results

        # Normalize into a list of items to process
        items: List[Any] = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Check if there is an array under common envelope keys
            found_array = False
            for key in ["results", "data", "indicators", "iocs", "urls", "items", "pulses", "payloads"]:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    found_array = True
                    break
            if not found_array:
                # Treat dict values or dict itself as candidate item
                items = [data]
        else:
            return results

        for idx, item in enumerate(items):
            if isinstance(item, str):
                # Simple string list of IOCs
                detected = detect_and_validate_ioc(item)
                if detected:
                    ioc_type, _, _ = detected
                    results.append(
                        RawIndicator(
                            value=item,
                            ioc_type=ioc_type,
                            source=self.feed_def.name,
                            feed_format="json",
                            tags=list(self.feed_def.default_tags),
                            raw_metadata={"index": idx, "feed_name": self.feed_def.name}
                        )
                    )
            elif isinstance(item, dict):
                # Extract indicator candidate
                candidate_val = None
                for k in INDICATOR_KEYS:
                    if k in item and isinstance(item[k], str) and item[k].strip():
                        candidate_val = item[k].strip()
                        break

                if not candidate_val:
                    # Search nested values
                    for k, v in item.items():
                        if isinstance(v, str) and detect_and_validate_ioc(v):
                            candidate_val = v
                            break

                if not candidate_val:
                    continue

                detected = detect_and_validate_ioc(candidate_val)
                if not detected:
                    continue

                ioc_type, _, _ = detected

                # Extract tags
                tags = list(self.feed_def.default_tags)
                for tk in TAG_KEYS:
                    if tk in item:
                        raw_tag_val = item[tk]
                        if isinstance(raw_tag_val, list):
                            for t in raw_tag_val:
                                if isinstance(t, str):
                                    tags.append(t.lower().strip())
                        elif isinstance(raw_tag_val, str):
                            for t in raw_tag_val.replace(";", ",").split(","):
                                if t.strip():
                                    tags.append(t.lower().strip())

                # Extract timestamp
                timestamp = None
                for time_key in TIME_KEYS:
                    if time_key in item and isinstance(item[time_key], str):
                        timestamp = item[time_key]
                        break

                # Extract confidence
                confidence = None
                for conf_key in CONF_KEYS:
                    if conf_key in item:
                        try:
                            confidence = int(item[conf_key])
                            break
                        except (ValueError, TypeError):
                            pass

                results.append(
                    RawIndicator(
                        value=candidate_val,
                        ioc_type=ioc_type,
                        source=self.feed_def.name,
                        feed_format="json",
                        timestamp=timestamp,
                        tags=tags,
                        confidence=confidence,
                        raw_metadata={"item_index": idx, "feed_name": self.feed_def.name}
                    )
                )

        return results
