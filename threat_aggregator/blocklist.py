"""
Blocklist Generator
Generates ready-to-deploy defensive blocklists for:
1. Firewalls (IPv4, IPv6 lists, iptables / CIDR rules)
2. Web Filters & DNS Sinkholes (Domain lists, Hosts file format, URL lists)
3. Endpoint Detection & Response (EDR) / Antivirus (MD5, SHA256 hashes)
"""

import json
import csv
import io
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from threat_aggregator.models import UnifiedIOC, IOCType, Severity


class BlocklistGenerator:
    """
    Transforms correlated intelligence into actionable security enforcement lists.
    """

    def __init__(self, iocs: List[UnifiedIOC]):
        self.iocs = iocs

    def filter_iocs(
        self,
        ioc_types: Optional[List[IOCType]] = None,
        min_severity: Severity = Severity.LOW,
        exclude_bogons: bool = True
    ) -> List[UnifiedIOC]:
        """Filters indicators based on type, minimum severity threshold, and bogon flags."""
        min_score = min_severity.score
        filtered: List[UnifiedIOC] = []

        for ioc in self.iocs:
            if ioc_types and ioc.ioc_type not in ioc_types:
                continue
            if ioc.severity.score < min_score:
                continue
            if exclude_bogons and ioc.is_private_or_bogon:
                continue
            filtered.append(ioc)

        return filtered

    # =========================================================================
    # Firewall Blocklists
    # =========================================================================

    def generate_firewall_ips(
        self,
        min_severity: Severity = Severity.MEDIUM,
        exclude_bogons: bool = True
    ) -> List[str]:
        """Returns deduplicated list of malicious IP addresses."""
        targets = self.filter_iocs(
            ioc_types=[IOCType.IPV4, IOCType.IPV6],
            min_severity=min_severity,
            exclude_bogons=exclude_bogons
        )
        return [ioc.value for ioc in targets]

    def export_firewall_txt(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        ips = self.generate_firewall_ips(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Threat Intelligence Aggregator - Firewall IP Blocklist\n")
            f.write(f"# Generated: {len(ips)} malicious IPs (Min Severity: {min_severity.value})\n")
            for ip in sorted(ips):
                f.write(f"{ip}\n")
        return len(ips)

    def export_firewall_iptables(self, output_path: Path, chain: str = "DROP_TI", min_severity: Severity = Severity.LOW) -> int:
        ips = self.generate_firewall_ips(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/bash\n# iptables automated threat enforcement script\n")
            f.write(f"# 1. Initialize custom threat intelligence chain\n")
            f.write(f"iptables -N {chain} 2>/dev/null || iptables -F {chain}\n\n")
            f.write(f"# 2. Hook chain into top of INPUT and FORWARD tables\n")
            f.write(f"iptables -C INPUT -j {chain} 2>/dev/null || iptables -I INPUT 1 -j {chain}\n")
            f.write(f"iptables -C FORWARD -j {chain} 2>/dev/null || iptables -I FORWARD 1 -j {chain}\n\n")
            f.write(f"# 3. Drop all inbound/outbound packets matching malicious indicators\n")
            for ip in sorted(ips):
                if ":" in ip:
                    # IPv6 handled separately
                    continue
                f.write(f"iptables -A {chain} -s {ip} -j DROP\n")
                f.write(f"iptables -A {chain} -d {ip} -j DROP\n")
        return len(ips)

    def export_firewall_windows_ps1(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        """Exports Windows Defender Firewall enforcement script in PowerShell."""
        ips = self.generate_firewall_ips(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Windows Defender Firewall - Automated Threat Intelligence Blocklist\n")
            f.write("# Run this script in an elevated PowerShell console (Run as Administrator)\n\n")
            f.write("Write-Host '[*] Applying Threat Intelligence Firewall Rules...' -ForegroundColor Cyan\n")
            f.write("Remove-NetFirewallRule -DisplayName 'ThreatIntel-Block-Outbound' -ErrorAction SilentlyContinue\n")
            f.write("Remove-NetFirewallRule -DisplayName 'ThreatIntel-Block-Inbound' -ErrorAction SilentlyContinue\n\n")
            ip_list_str = ", ".join(f"'{ip}'" for ip in sorted(ips) if ":" not in ip)
            f.write(f"$maliciousIPs = @({ip_list_str})\n\n")
            f.write("if ($maliciousIPs.Count -gt 0) {\n")
            f.write("    New-NetFirewallRule -DisplayName 'ThreatIntel-Block-Outbound' -Direction Outbound -Action Block -RemoteAddress $maliciousIPs\n")
            f.write("    New-NetFirewallRule -DisplayName 'ThreatIntel-Block-Inbound' -Direction Inbound -Action Block -RemoteAddress $maliciousIPs\n")
            f.write("    Write-Host ('[+] Successfully blocked ' + $maliciousIPs.Count + ' malicious IPs on Windows Firewall.') -ForegroundColor Green\n")
            f.write("}\n")
        return len(ips)

    # =========================================================================
    # Web Filter & DNS Sinkhole Blocklists
    # =========================================================================

    def generate_webfilter_domains(self, min_severity: Severity = Severity.LOW) -> List[str]:
        """Returns deduplicated list of malicious domains."""
        targets = self.filter_iocs(ioc_types=[IOCType.DOMAIN], min_severity=min_severity)
        return [ioc.value for ioc in targets]

    def export_webfilter_domains_txt(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        domains = self.generate_webfilter_domains(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Threat Intelligence Aggregator - Domain Blocklist\n")
            f.write(f"# Count: {len(domains)} (Min Severity: {min_severity.value})\n")
            for d in sorted(domains):
                f.write(f"{d}\n")
        return len(domains)

    def export_hosts_file(self, output_path: Path, sinkhole_ip: str = "0.0.0.0", min_severity: Severity = Severity.LOW) -> int:
        """Exports in standard /etc/hosts or Pi-hole format."""
        domains = self.generate_webfilter_domains(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Hosts Sinkhole Format - Threat Intelligence Aggregator\n")
            for d in sorted(domains):
                f.write(f"{sinkhole_ip} {d}\n")
        return len(domains)

    def generate_webfilter_urls(self, min_severity: Severity = Severity.LOW) -> List[str]:
        """Returns deduplicated list of malicious URLs for web proxies."""
        targets = self.filter_iocs(ioc_types=[IOCType.URL], min_severity=min_severity)
        return [ioc.value for ioc in targets]

    def export_webfilter_urls_txt(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        urls = self.generate_webfilter_urls(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Threat Intelligence Aggregator - Malicious URL Blocklist\n")
            f.write(f"# Count: {len(urls)} (Min Severity: {min_severity.value})\n")
            for u in sorted(urls):
                f.write(f"{u}\n")
        return len(urls)

    # =========================================================================
    # EDR / AV Hash Blocklists
    # =========================================================================

    def generate_edr_hashes(self, min_severity: Severity = Severity.LOW) -> List[Tuple[str, str]]:
        """Returns list of (hash_type, hash_value)."""
        targets = self.filter_iocs(
            ioc_types=[IOCType.MD5, IOCType.SHA1, IOCType.SHA256],
            min_severity=min_severity
        )
        return [(ioc.ioc_type.value, ioc.value) for ioc in targets]

    def export_edr_hashes_txt(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        hashes = self.generate_edr_hashes(min_severity=min_severity)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Threat Intelligence Aggregator - Malicious Hash Blocklist\n")
            f.write(f"# Count: {len(hashes)} (Min Severity: {min_severity.value})\n")
            for h_type, h_val in sorted(hashes, key=lambda x: (x[0], x[1])):
                f.write(f"{h_val}\n")
        return len(hashes)

    def export_edr_hashes_csv(self, output_path: Path, min_severity: Severity = Severity.LOW) -> int:
        targets = self.filter_iocs(
            ioc_types=[IOCType.MD5, IOCType.SHA1, IOCType.SHA256],
            min_severity=min_severity
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["hash_type", "hash_value", "severity", "confidence", "sources", "tags"])
            for ioc in targets:
                writer.writerow([
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.severity.value,
                    ioc.confidence,
                    ";".join(ioc.sources),
                    ";".join(ioc.tags)
                ])
        return len(targets)

    def export_suricata_rules(self, output_path: Path, min_severity: Severity = Severity.LOW, base_sid: int = 1000000) -> int:
        """
        Exports Suricata IDS/IPS network rules for malicious IPs and domains.
        """
        target_ips = self.filter_iocs(ioc_types=[IOCType.IPV4, IOCType.IPV6], min_severity=min_severity, exclude_bogons=True)
        target_domains = self.filter_iocs(ioc_types=[IOCType.DOMAIN], min_severity=min_severity)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        rule_count = 0
        current_sid = base_sid

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# =========================================================================\n")
            f.write("# Suricata Threat Intelligence Detection Rules\n")
            f.write("# Generated automatically by Threat Intelligence Aggregator (Non-AI)\n")
            f.write("# =========================================================================\n\n")

            for ioc in target_ips:
                sev = ioc.severity.value
                conf = ioc.confidence
                sources = ";".join(ioc.sources)
                f.write(
                    f'alert ip any any -> {ioc.value} any ('
                    f'msg:"THREAT-INTEL [{sev}] Outbound Connection to Malicious IP {ioc.defanged_value}"; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1; '
                    f'metadata:confidence {conf}, sources {sources};)\n'
                )
                current_sid += 1
                rule_count += 1

            for ioc in target_domains:
                sev = ioc.severity.value
                conf = ioc.confidence
                sources = ";".join(ioc.sources)
                f.write(
                    f'alert dns any any -> any 53 ('
                    f'msg:"THREAT-INTEL [{sev}] DNS Query for Malicious Domain {ioc.defanged_value}"; '
                    f'dns.query; content:"{ioc.value}"; nocase; classtype:bad-unknown; '
                    f'sid:{current_sid}; rev:1; metadata:confidence {conf}, sources {sources};)\n'
                )
                current_sid += 1
                rule_count += 1

        return rule_count

    def export_snort_rules(self, output_path: Path, min_severity: Severity = Severity.LOW, base_sid: int = 2000000) -> int:
        """
        Exports Snort 2/3 compatible IDS rules.
        """
        target_ips = self.filter_iocs(ioc_types=[IOCType.IPV4], min_severity=min_severity, exclude_bogons=True)
        target_domains = self.filter_iocs(ioc_types=[IOCType.DOMAIN], min_severity=min_severity)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        rule_count = 0
        current_sid = base_sid

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# =========================================================================\n")
            f.write("# Snort Threat Intelligence Detection Rules\n")
            f.write("# Generated automatically by Threat Intelligence Aggregator (Non-AI)\n")
            f.write("# =========================================================================\n\n")

            for ioc in target_ips:
                sev = ioc.severity.value
                f.write(
                    f'alert ip $HOME_NET any -> {ioc.value} any ('
                    f'msg:"COMMUNITY-THREAT [{sev}] Traffic to Malicious IP {ioc.defanged_value}"; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1;)\n'
                )
                current_sid += 1
                rule_count += 1

            for ioc in target_domains:
                sev = ioc.severity.value
                f.write(
                    f'alert udp $HOME_NET any -> any 53 ('
                    f'msg:"COMMUNITY-THREAT [{sev}] Query for Malicious Domain {ioc.defanged_value}"; '
                    f'content:"{ioc.value}"; nocase; classtype:bad-unknown; sid:{current_sid}; rev:1;)\n'
                )
                current_sid += 1
                rule_count += 1

        return rule_count

    # =========================================================================
    # Export All Standard Blocklists & IDS Rules
    # =========================================================================

    def export_all(self, output_dir: Path, min_severity: Severity = Severity.LOW) -> Dict[str, int]:
        """Convenience method to export all target blocklists and IDS rules."""
        output_dir.mkdir(parents=True, exist_ok=True)
        counts = {
            "firewall_ips_txt": self.export_firewall_txt(output_dir / "firewall_ips.txt", min_severity=min_severity),
            "firewall_iptables": self.export_firewall_iptables(output_dir / "firewall_iptables.sh", min_severity=min_severity),
            "firewall_windows_ps1": self.export_firewall_windows_ps1(output_dir / "firewall_windows.ps1", min_severity=min_severity),
            "webfilter_domains_txt": self.export_webfilter_domains_txt(output_dir / "webfilter_domains.txt", min_severity=min_severity),
            "webfilter_domains_hosts": self.export_hosts_file(output_dir / "webfilter_hosts.txt", min_severity=min_severity),
            "webfilter_urls_txt": self.export_webfilter_urls_txt(output_dir / "webfilter_urls.txt", min_severity=min_severity),
            "edr_hashes_txt": self.export_edr_hashes_txt(output_dir / "edr_hashes.txt", min_severity=min_severity),
            "edr_hashes_csv": self.export_edr_hashes_csv(output_dir / "edr_hashes.csv", min_severity=min_severity),
            "suricata_rules": self.export_suricata_rules(output_dir / "suricata_threat_intel.rules", min_severity=min_severity),
            "snort_rules": self.export_snort_rules(output_dir / "snort_threat_intel.rules", min_severity=min_severity),
        }
        return counts
