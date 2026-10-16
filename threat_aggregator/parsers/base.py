"""
Base Feed Parser
Defines interface for parsing different Threat Intelligence feed formats.
"""

from abc import ABC, abstractmethod
from typing import List
from threat_aggregator.models import RawIndicator, FeedDefinition


class BaseParser(ABC):
    """Abstract base class for all feed parsers."""

    def __init__(self, feed_def: FeedDefinition):
        self.feed_def = feed_def

    @abstractmethod
    def parse(self, content: str) -> List[RawIndicator]:
        """
        Parses raw text content into a list of RawIndicator objects.
        """
        pass
