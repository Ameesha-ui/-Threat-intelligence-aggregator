"""
Unit Tests for Threat Intelligence Aggregator (Non-AI)
Tests parsers, validators, normalizer, correlation engine, and blocklist generation.
"""

import unittest
from pathlib import Path

from threat_aggregator.models import FeedDefinition, IOCType, Severity, RawIndicator
from threat_aggregator.defang import refang, defang
from threat_aggregator.validators import (
    detect_and_validate_ioc,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_domain,
    is_valid_url,
    is_valid_md5,
    is_valid_sha1,
    is_valid_sha256,
)
from threat_aggregator.normalizer import NormalizationEngine
from threat_aggregator.correlation import CorrelationEngine
from threat_aggregator.blocklist import BlocklistGenerator
from threat_aggregator.parsers import get_parser


class TestValidatorsAndDefanging(unittest.TestCase):
    def test_refanging_protocols_and_dots(self):
        self.assertEqual(refang("hxxp://evil[.]com/bad"), "http://evil.com/bad")
        self.assertEqual(refang("hxxps://malware[.]net/payload"), "https://malware.net/payload")
        self.assertEqual(refang("1[.]1[.]1[.]1"), "1.1.1.1")
        self.assertEqual(refang("evil(dot)com"), "evil.com")
        self.assertEqual(refang("user[@]bad[.]com"), "user@bad.com")

    def test_defanging(self):
        self.assertEqual(defang("http://evil.com"), "hxxp://evil[.]com")
        self.assertEqual(defang("192.168.1.1"), "192[.]168[.]1[.]1")

    def test_ipv4_validation(self):
        valid, bogon = is_valid_ipv4("1.1.1.1")
        self.assertTrue(valid)
        self.assertFalse(bogon)

        valid_priv, bogon_priv = is_valid_ipv4("192.168.1.1")
        self.assertTrue(valid_priv)
        self.assertTrue(bogon_priv)

        invalid, _ = is_valid_ipv4("999.999.999.999")
        self.assertFalse(invalid)

    def test_domain_validation(self):
        self.assertTrue(is_valid_domain("evil-c2.com"))
        self.assertTrue(is_valid_domain("bad.subdomain.org"))
        self.assertFalse(is_valid_domain("192.168.1.1"))
        self.assertFalse(is_valid_domain("not_a_domain"))

    def test_url_validation(self):
        self.assertTrue(is_valid_url("http://evil.com/malware.exe"))
        self.assertTrue(is_valid_url("https://bad.org/c2"))
        self.assertFalse(is_valid_url("just-a-domain.com"))

    def test_hash_validation(self):
        self.assertTrue(is_valid_md5("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertFalse(is_valid_md5("not_a_hash"))
        self.assertTrue(is_valid_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        self.assertFalse(is_valid_sha256("short"))

    def test_detect_and_validate_ioc(self):
        res_ip = detect_and_validate_ioc("45[.]154[.]255[.]89")
        self.assertIsNotNone(res_ip)
        self.assertEqual(res_ip[0], IOCType.IPV4)
        self.assertEqual(res_ip[1], "45.154.255.89")
        self.assertFalse(res_ip[2])

        res_bogon = detect_and_validate_ioc("192.168.0.1")
        self.assertIsNotNone(res_bogon)
        self.assertTrue(res_bogon[2])


class TestParsers(unittest.TestCase):
    def test_csv_parser(self):
        feed_def = FeedDefinition(name="TestCSV", format="csv", path_or_url="")
        parser = get_parser(feed_def)
        csv_data = "indicator,type,threat\n45.154.255.89,ipv4,c2_scanner\nevil.com,domain,phishing\n"
        results = parser.parse(csv_data)
        self.assertEqual(len(results), 2)
        values = [r.value for r in results]
        self.assertIn("45.154.255.89", values)
        self.assertIn("evil.com", values)

    def test_text_parser(self):
        feed_def = FeedDefinition(name="TestTXT", format="txt", path_or_url="")
        parser = get_parser(feed_def)
        txt_data = "# Comment line\n45.154.255.89\n# Another comment\nmalicious-host.net\n"
        results = parser.parse(txt_data)
        self.assertEqual(len(results), 2)

    def test_json_parser(self):
        feed_def = FeedDefinition(name="TestJSON", format="json", path_or_url="")
        parser = get_parser(feed_def)
        json_data = '[{"url": "http://evil.com/drop.exe", "tags": ["payload"]}, {"ip": "45.154.255.89"}]'
        results = parser.parse(json_data)
        self.assertEqual(len(results), 2)


class TestCorrelationAndScoring(unittest.TestCase):
    def test_multi_feed_correlation(self):
        raw_items = [
            RawIndicator(value="45.154.255.89", source="FeedA"),
            RawIndicator(value="45.154.255.89", source="FeedB"),
            RawIndicator(value="45.154.255.89", source="FeedC"),
            RawIndicator(value="isolated-threat.com", source="FeedA"),
        ]
        normalizer = NormalizationEngine()
        normalized = normalizer.normalize(raw_items)
        self.assertEqual(len(normalized), 2)

        correlator = CorrelationEngine(feed_weights={"FeedA": 1.0, "FeedB": 1.5, "FeedC": 2.0})
        correlated = correlator.correlate(normalized)

        target = next(i for i in correlated if i.value == "45.154.255.89")
        self.assertEqual(target.feed_count, 3)
        self.assertEqual(target.severity, Severity.CRITICAL)
        self.assertGreaterEqual(target.confidence, 70)


class TestBlocklists(unittest.TestCase):
    def test_blocklist_filtering(self):
        raw_items = [
            RawIndicator(value="45.154.255.89", source="FeedA"),  # Public routable IP
            RawIndicator(value="192.168.1.1", source="FeedA"),    # RFC1918 Private
            RawIndicator(value="evil.com", source="FeedA"),
        ]
        normalizer = NormalizationEngine(filter_bogons=False)
        normalized = normalizer.normalize(raw_items)

        gen = BlocklistGenerator(normalized)
        # Exclude bogons should retain 45.154.255.89 and remove 192.168.1.1
        filtered_ips = gen.filter_iocs(ioc_types=[IOCType.IPV4], exclude_bogons=True)
        values = [i.value for i in filtered_ips]
        self.assertIn("45.154.255.89", values)
        self.assertNotIn("192.168.1.1", values)

    def test_suricata_and_snort_rule_generation(self):
        raw_items = [
            RawIndicator(value="45.154.255.89", source="FeedA"),
            RawIndicator(value="evil-c2.com", source="FeedA"),
        ]
        normalizer = NormalizationEngine(filter_bogons=True)
        normalized = normalizer.normalize(raw_items)
        gen = BlocklistGenerator(normalized)

        test_dir = Path("output/test_rules")
        suricata_count = gen.export_suricata_rules(test_dir / "suricata.rules")
        snort_count = gen.export_snort_rules(test_dir / "snort.rules")

        self.assertEqual(suricata_count, 2)
        self.assertEqual(snort_count, 2)

        suricata_content = (test_dir / "suricata.rules").read_text(encoding="utf-8")
        self.assertIn("alert ip any any -> 45.154.255.89 any", suricata_content)
        self.assertIn('content:"evil-c2.com"', suricata_content)

        snort_content = (test_dir / "snort.rules").read_text(encoding="utf-8")
        self.assertIn("alert ip $HOME_NET any -> 45.154.255.89 any", snort_content)
        self.assertIn('content:"evil-c2.com"', snort_content)

        # Cleanup test dir
        for f in test_dir.iterdir():
            f.unlink()
        test_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
