# Threat Intelligence Aggregator (Non-AI) - Executive Report

> **Generated UTC:** `2026-11-02T19:09:42.875491+00:00`  

> **Feeds Ingested:** 8 / 9  

> **Unique Normalized Indicators:** 125  

> **Cross-Feed Repetition Rate:** 4.8%

## 1. Indicator Telemetry Breakdown

| Indicator Type | Count | % of Total |
| :--- | :--- | :--- |
| `DOMAIN` | **3** | 2.4% |
| `EMAIL` | **4** | 3.2% |
| `IPV4` | **111** | 88.8% |
| `MD5` | **2** | 1.6% |
| `SHA256` | **1** | 0.8% |
| `URL` | **4** | 3.2% |

## 2. Threat Severity Classification

| Severity Rating | Indicators | Recommended Blue Team Action |
| :--- | :--- | :--- |
| **CRITICAL** | 6 | Immediate automated perimeter & EDR block; triage internal logs |
| **HIGH** | 7 | Block at gateway / firewall; alert SOC on outbound connection |
| **MEDIUM** | 0 | Web proxy / DNS sinkhole inspection; watchlist logging |
| **LOW** | 112 | Passive monitoring & correlation enrichment |

## 3. High-Priority Repeated Indicators (Cross-Source Matches)

Repeated indicators flagged by 2 or more distinct feeds represent high-confidence threats:

| Indicator (Defanged) | Type | Feeds Contributed | Severity | Confidence | Tags |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `45[.]154[.]255[.]89` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, CISA_Advisory_Alerts, Internal_SIEM_Detections (4) | **CRITICAL** | 100 | `abuseipdb, apt, c2, cert_alert, cisa, cobaltstrike, external_osint, internal, internal_edr_c2_alert, otx, scanner, soc_escalation` |
| `185[.]220[.]101[.]5` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, Internal_SIEM_Detections (3) | **CRITICAL** | 90 | `abuseipdb, c2, external_osint, firewall_denied_outbound, internal, otx, scanner, soc_escalation, tor_exit_node` |
| `194[.]26[.]29[.]112` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, CISA_Advisory_Alerts (3) | **CRITICAL** | 90 | `abuseipdb, c2, cert_alert, cisa, exploit, external_osint, otx, ransomware_beacon, scanner` |
| `evil-c2-update[.]top` | domain | AlienVault_OTX, CISA_Advisory_Alerts, Internal_SIEM_Detections (3) | **CRITICAL** | 90 | `apt, apt29, c2, cert_alert, cisa, dns_tunneling_attempt, external_osint, internal, otx, soc_escalation` |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | sha256 | AlienVault_OTX, CISA_Advisory_Alerts, Internal_SIEM_Detections (3) | **CRITICAL** | 90 | `cert_alert, cisa, edr_quarantined_ransomware, external_osint, internal, malicious-activity, otx, ransomware, ransomware_lockbit, soc_escalation` |
| `hxxp://185[.]220[.]101[.]5/payload[.]bin` | url | AlienVault_OTX, URLhaus_Payloads (2) | **CRITICAL** | 72 | `cobaltstrike, dropper, external_osint, malware, otx, payload_delivery, trojan, urlhaus` |

## 4. Ingestion Feed Status

| Feed Name | Format | Status | Ingested Count | Category |
| :--- | :--- | :--- | :--- | :--- |
| **AlienVault_OTX** | `csv` | `SUCCESS` | 9 | commercial_ti |
| **AbuseIPDB_Feed** | `txt` | `SUCCESS` | 8 | community_osint |
| **URLhaus_Payloads** | `json` | `SUCCESS` | 4 | malware_hunting |
| **CISA_Advisory_Alerts** | `stix` | `SUCCESS` | 4 | government_cert |
| **Internal_SIEM_Detections** | `csv` | `SUCCESS` | 6 | internal_telemetry |
| **Live_Feodo_Tracker_C2** | `txt` | `SUCCESS` | 1 | botnet_c2 |
| **Live_URLhaus_Online_URLs** | `txt` | `FAILED` | 0 | external |
| **Live_EmergingThreats_Compromised** | `txt` | `SUCCESS` | 100 | compromised_infrastructure |
| **Custom_SOC_Feed** | `csv` | `SUCCESS` | 5 | incident_response |
