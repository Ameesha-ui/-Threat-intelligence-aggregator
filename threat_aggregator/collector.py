"""
Feed Collector
Fetches threat feeds from local filesystem or remote HTTP/HTTPS endpoints.
"""

import os
from pathlib import Path
from typing import List, Tuple, Dict, Any
import requests

from threat_aggregator.models import FeedDefinition, RawIndicator
from threat_aggregator.parsers import get_parser


class FeedCollector:
    """Orchestrates ingestion of threat intelligence feeds from URLs and files."""

    def __init__(self, timeout: int = 15, user_agent: str = "ThreatIntelAggregator/1.0 (Defensive BlueTeam)"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.headers = {"User-Agent": self.user_agent}

    def fetch_feed_content(self, feed_def: FeedDefinition) -> Tuple[bool, str, str]:
        """
        Fetches the content of a feed either from a remote URL or a local file.
        Returns: (success: bool, content: str, error_msg: str)
        """
        target = feed_def.path_or_url.strip()

        # Check if remote URL
        if target.startswith(("http://", "https://")):
            try:
                response = requests.get(target, headers=self.headers, timeout=self.timeout)
                if response.status_code == 200:
                    return True, response.text, ""
                else:
                    return False, "", f"HTTP error {response.status_code}: {response.reason}"
            except Exception as e:
                return False, "", f"Network error: {str(e)}"

        # Treat as local file
        file_path = Path(target)
        if not file_path.is_absolute():
            # Resolve relative to current working directory
            file_path = Path.cwd() / file_path

        if not file_path.exists():
            return False, "", f"Local feed file not found: {file_path}"

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return True, content, ""
        except Exception as e:
            return False, "", f"File read error: {str(e)}"

    def collect(self, feed_definitions: List[FeedDefinition]) -> Tuple[List[RawIndicator], Dict[str, Any]]:
        """
        Ingests all configured feeds, parsing them into RawIndicators.
        Returns: (list of RawIndicators, collection audit summary)
        """
        all_raw_indicators: List[RawIndicator] = []
        feed_stats: Dict[str, Any] = {}

        for feed_def in feed_definitions:
            if not feed_def.enabled:
                feed_stats[feed_def.name] = {
                    "status": "disabled",
                    "count": 0,
                    "format": feed_def.format
                }
                continue

            success, content, err = self.fetch_feed_content(feed_def)
            if not success:
                feed_stats[feed_def.name] = {
                    "status": "failed",
                    "error": err,
                    "count": 0,
                    "format": feed_def.format
                }
                continue

            parser = get_parser(feed_def)
            try:
                parsed_indicators = parser.parse(content)
                if feed_def.max_indicators and len(parsed_indicators) > feed_def.max_indicators:
                    parsed_indicators = parsed_indicators[:feed_def.max_indicators]
                all_raw_indicators.extend(parsed_indicators)
                feed_stats[feed_def.name] = {
                    "status": "success",
                    "count": len(parsed_indicators),
                    "format": feed_def.format,
                    "weight": feed_def.weight,
                    "category": feed_def.category
                }
            except Exception as e:
                feed_stats[feed_def.name] = {
                    "status": "parse_error",
                    "error": str(e),
                    "count": 0,
                    "format": feed_def.format
                }

        return all_raw_indicators, feed_stats
