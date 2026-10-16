"""
Text / Plaintext Feed Parser
Parses plain line-based blocklists and unstructured SOC text feeds.
"""

import re
from typing import List, Dict, Any

from threat_aggregator.parsers.base import BaseParser
from threat_aggregator.models import RawIndicator
from threat_aggregator.validators import detect_and_validate_ioc

# Token splitter for unstructured text
TOKEN_SPLIT_REGEX = re.compile(r"[\s,;\"'<>\[\]{}|\\]+")


class TextParser(BaseParser):
    """
    Parser for line-oriented feeds and raw unstructured security reports.
    """

    def parse(self, content: str) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        if not content:
            return results

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("//"):
                continue

            # Strip inline comments (e.g. '1.1.1.1 # bad host')
            if "#" in line_str:
                line_str = line_str.split("#")[0].strip()
            if ";" in line_str:
                line_str = line_str.split(";")[0].strip()

            # Attempt single-token direct validation first (most line-based feeds)
            detected = detect_and_validate_ioc(line_str)
            if detected:
                ioc_type, _, _ = detected
                results.append(
                    RawIndicator(
                        value=line_str,
                        ioc_type=ioc_type,
                        source=self.feed_def.name,
                        feed_format="txt",
                        tags=list(self.feed_def.default_tags),
                        raw_metadata={"line_number": line_num, "feed_name": self.feed_def.name}
                    )
                )
                continue

            # If not a single token, scan tokens in the line (handles multi-word or space separated feeds)
            tokens = TOKEN_SPLIT_REGEX.split(line)
            for token in tokens:
                token = token.strip().strip("'\"`(),:;")
                if not token or len(token) < 4:
                    continue
                detected_token = detect_and_validate_ioc(token)
                if detected_token:
                    ioc_type, _, _ = detected_token
                    results.append(
                        RawIndicator(
                            value=token,
                            ioc_type=ioc_type,
                            source=self.feed_def.name,
                            feed_format="txt",
                            tags=list(self.feed_def.default_tags),
                            raw_metadata={"line_number": line_num, "feed_name": self.feed_def.name}
                        )
                    )

        return results
