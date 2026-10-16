"""
Threat Feed Parsers Package
Provides parser registry and factory for CSV, TXT, JSON, and STIX formats.
"""

from typing import Dict, Type
from threat_aggregator.parsers.base import BaseParser
from threat_aggregator.parsers.csv_parser import CSVParser
from threat_aggregator.parsers.txt_parser import TextParser
from threat_aggregator.parsers.json_parser import JSONParser
from threat_aggregator.parsers.stix_parser import STIXParser
from threat_aggregator.models import FeedDefinition

PARSER_REGISTRY: Dict[str, Type[BaseParser]] = {
    "csv": CSVParser,
    "txt": TextParser,
    "text": TextParser,
    "json": JSONParser,
    "stix": STIXParser,
    "stix2": STIXParser,
}


def get_parser(feed_def: FeedDefinition) -> BaseParser:
    """Returns an initialized parser instance for the given feed definition."""
    fmt = feed_def.format.lower().strip()
    parser_cls = PARSER_REGISTRY.get(fmt, TextParser)
    return parser_cls(feed_def)


__all__ = [
    "BaseParser",
    "CSVParser",
    "TextParser",
    "JSONParser",
    "STIXParser",
    "get_parser",
    "PARSER_REGISTRY"
]
