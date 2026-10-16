"""
STIX 2.x Threat Intelligence Bundle Parser
Parses STIX 2.0 / 2.1 JSON bundles, extracting indicators from STIX Pattern expressions
and Observed Data objects without requiring heavyweight external dependencies.
"""

import json
import re
from typing import List, Dict, Any

from threat_aggregator.parsers.base import BaseParser
from threat_aggregator.models import RawIndicator
from threat_aggregator.validators import detect_and_validate_ioc

# Regex to extract values from STIX pattern statements:
# e.g., [ipv4-addr:value = '192.0.2.1'] or [domain-name:value = 'evil.com']
STIX_PATTERN_REGEX = re.compile(
    r"\[\s*([\w\-]+):(?:value|hashes\.['\"]?(?:MD5|SHA-1|SHA-256)['\"]?)\s*=\s*['\"]([^'\"]+)['\"]\s*\]",
    re.IGNORECASE
)

STIX_GENERIC_VAL_REGEX = re.compile(r"=\s*['\"]([^'\"]+)['\"]")


class STIXParser(BaseParser):
    """Parses STIX 2.0 / 2.1 JSON Bundles."""

    def parse(self, content: str) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        if not content or not content.strip():
            return results

        try:
            bundle = json.loads(content)
        except json.JSONDecodeError:
            return results

        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        if not objects and isinstance(bundle, list):
            objects = bundle

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            obj_type = obj.get("type")

            # Case 1: STIX Indicator Object
            if obj_type == "indicator":
                pattern = obj.get("pattern", "")
                tags = list(self.feed_def.default_tags)
                
                # Add indicator_types to tags
                for itype in obj.get("indicator_types", []):
                    tags.append(itype.lower())

                # Add labels to tags
                for lbl in obj.get("labels", []):
                    tags.append(lbl.lower())

                timestamp = obj.get("created") or obj.get("modified")
                confidence = obj.get("confidence")

                # Match patterns
                matches = STIX_PATTERN_REGEX.findall(pattern)
                if matches:
                    for p_type, p_val in matches:
                        detected = detect_and_validate_ioc(p_val)
                        if detected:
                            ioc_type, _, _ = detected
                            results.append(
                                RawIndicator(
                                    value=p_val,
                                    ioc_type=ioc_type,
                                    source=self.feed_def.name,
                                    feed_format="stix",
                                    timestamp=timestamp,
                                    tags=tags,
                                    confidence=confidence,
                                    raw_metadata={"stix_id": obj.get("id"), "stix_pattern": pattern}
                                )
                            )
                else:
                    # Fallback pattern extraction
                    for val_match in STIX_GENERIC_VAL_REGEX.findall(pattern):
                        detected = detect_and_validate_ioc(val_match)
                        if detected:
                            ioc_type, _, _ = detected
                            results.append(
                                RawIndicator(
                                    value=val_match,
                                    ioc_type=ioc_type,
                                    source=self.feed_def.name,
                                    feed_format="stix",
                                    timestamp=timestamp,
                                    tags=tags,
                                    confidence=confidence,
                                    raw_metadata={"stix_id": obj.get("id")}
                                )
                            )

            # Case 2: Observed Data / Cyber Observable Objects
            elif obj_type == "observed-data":
                first_observed = obj.get("first_observed")
                obs_objects = obj.get("objects", {})
                if isinstance(obs_objects, dict):
                    for _, obs in obs_objects.items():
                        if not isinstance(obs, dict):
                            continue
                        val = obs.get("value")
                        if not val and obs.get("type") == "file":
                            hashes = obs.get("hashes", {})
                            val = hashes.get("SHA-256") or hashes.get("MD5") or hashes.get("SHA-1")

                        if val:
                            detected = detect_and_validate_ioc(val)
                            if detected:
                                ioc_type, _, _ = detected
                                results.append(
                                    RawIndicator(
                                        value=val,
                                        ioc_type=ioc_type,
                                        source=self.feed_def.name,
                                        feed_format="stix",
                                        timestamp=first_observed,
                                        tags=list(self.feed_def.default_tags),
                                        raw_metadata={"stix_id": obj.get("id")}
                                    )
                                )

        return results
