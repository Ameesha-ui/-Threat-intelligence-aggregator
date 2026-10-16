# Threat Intelligence Aggregator (Non-AI) - Executive Report

> **Generated UTC:** `2026-10-16T17:56:57.718491+00:00`  

> **Feeds Ingested:** 9 / 9  

> **Unique Normalized Indicators:** 171  

> **Cross-Feed Repetition Rate:** 3.5%

## 1. Indicator Telemetry Breakdown

| Indicator Type | Count | % of Total |
| :--- | :--- | :--- |
| `DOMAIN` | **3** | 1.8% |
| `EMAIL` | **4** | 2.3% |
| `IPV4` | **107** | 62.6% |
| `MD5` | **2** | 1.2% |
| `SHA256` | **1** | 0.6% |
| `URL` | **54** | 31.6% |

## 2. Threat Severity Classification

| Severity Rating | Indicators | Recommended Blue Team Action |
| :--- | :--- | :--- |
| **CRITICAL** | 6 | Immediate automated perimeter & EDR block; triage internal logs |
| **HIGH** | 56 | Block at gateway / firewall; alert SOC on outbound connection |
| **MEDIUM** | 0 | Web proxy / DNS sinkhole inspection; watchlist logging |
| **LOW** | 109 | Passive monitoring & correlation enrichment |

## 3. High-Priority Repeated Indicators (Cross-Source Matches)

Repeated indicators flagged by 2 or more distinct feeds represent high-confidence threats:

| Indicator (Defanged) | Type | Feeds Contributed | Severity | Confidence | Tags |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `45[.]154[.]255[.]89` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, CISA_Advisory_Alerts, Internal_SIEM_Detections (4) | **CRITICAL** | 100 | `abuseipdb, apt, c2, cert_alert, cisa, cobaltstrike, external_osint, internal, internal_edr_c2_alert, otx, scanner, soc_escalation` |
| `194[.]26[.]29[.]112` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, CISA_Advisory_Alerts, Custom_SOC_Feed (4) | **CRITICAL** | 100 | `abuseipdb, c2, c2_callback_beacon, cert_alert, cisa, custom_investigation, exploit, external_osint, otx, ransomware_beacon, scanner, soc_incident` |
| `185[.]220[.]101[.]5` | ipv4 | AlienVault_OTX, AbuseIPDB_Feed, Internal_SIEM_Detections (3) | **CRITICAL** | 90 | `abuseipdb, c2, external_osint, firewall_denied_outbound, internal, otx, scanner, soc_escalation, tor_exit_node` |
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
| **Live_URLhaus_Online_URLs** | `txt` | `SUCCESS` | 50 | malware_payloads |
| **Live_EmergingThreats_Compromised** | `txt` | `SUCCESS` | 100 | compromised_infrastructure |
| **Custom_SOC_Feed** | `csv` | `SUCCESS` | 5 | incident_response |
