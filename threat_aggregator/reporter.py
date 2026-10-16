"""
Threat Intelligence Reporting Module
Generates comprehensive reports in CLI, Markdown, JSON, and rich standalone HTML formats.
"""

import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from threat_aggregator.models import UnifiedIOC, Severity


class ThreatReporter:
    """
    Synthesizes normalized threat intelligence and correlation metrics into executive and operational reports.
    """

    def __init__(self, iocs: List[UnifiedIOC], feed_audit: Dict[str, Any], correlation_stats: Dict[str, Any]):
        self.iocs = iocs
        self.feed_audit = feed_audit
        self.correlation_stats = correlation_stats

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculates high-level threat telemetry."""
        type_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0
        }

        for ioc in self.iocs:
            t_val = ioc.ioc_type.value
            type_counts[t_val] = type_counts.get(t_val, 0) + 1
            severity_counts[ioc.severity.value] = severity_counts.get(ioc.severity.value, 0) + 1

        total_feeds = len(self.feed_audit)
        successful_feeds = sum(1 for f in self.feed_audit.values() if f.get("status") == "success")

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_iocs": len(self.iocs),
            "total_feeds_configured": total_feeds,
            "successful_feeds": successful_feeds,
            "type_breakdown": type_counts,
            "severity_breakdown": severity_counts,
            "repeated_iocs_count": self.correlation_stats.get("total_repeated_iocs", 0),
            "repetition_ratio": self.correlation_stats.get("repetition_ratio", 0.0)
        }

    def print_cli_summary(self):
        """Prints a structured, formatted cyber telemetry report to standard output."""
        metrics = self.get_summary_metrics()

        print("\n" + "=" * 70)
        print("   CYBER THREAT INTELLIGENCE AGGREGATOR - SUMMARY REPORT")
        print("=" * 70)
        print(f" Generated UTC       : {metrics['timestamp']}")
        print(f" Feeds Processed     : {metrics['successful_feeds']}/{metrics['total_feeds_configured']}")
        print(f" Total Unique IOCs   : {metrics['total_iocs']}")
        print(f" Repeated Indicators : {metrics['repeated_iocs_count']} ({metrics['repetition_ratio'] * 100:.1f}%)")
        print("-" * 70)

        print(" IOC BREAKDOWN BY TYPE:")
        for ioc_type, count in sorted(metrics["type_breakdown"].items()):
            bar = "#" * min(30, int((count / max(1, metrics['total_iocs'])) * 40))
            print(f"  {ioc_type:<10} : {count:<5} | {bar}")

        print("-" * 70)
        print(" SEVERITY DISTRIBUTION:")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            c = metrics["severity_breakdown"].get(sev.value, 0)
            tag = f"[{sev.value}]"
            print(f"  {tag:<12} : {c:<5}")

        print("-" * 70)
        print(" TOP 5 HIGH-PRIORITY REPEATED INDICATORS:")
        top_repeated = self.correlation_stats.get("top_repeated_iocs", [])[:5]
        if not top_repeated:
            print("  (None detected)")
        else:
            for idx, r in enumerate(top_repeated, 1):
                sources_str = ", ".join(r["sources"])
                print(f"  {idx}. [{r['severity']}] {r['defanged_value']}")
                print(f"     Type: {r['ioc_type']} | Feeds ({r['feed_count']}): {sources_str}")

        print("=" * 70 + "\n")

    def export_json(self, output_path: Path):
        """Exports the complete normalized threat intelligence database and metrics to JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "summary": self.get_summary_metrics(),
            "feed_audit": self.feed_audit,
            "correlation_analysis": self.correlation_stats,
            "indicators": [ioc.to_dict() for ioc in self.iocs]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    def export_csv(self, output_path: Path):
        """Exports normalized indicators as a standard CSV dataset."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "ioc_type", "value", "defanged_value", "severity", 
                "confidence", "feed_count", "sources", "tags", "first_seen", "last_seen"
            ])
            for ioc in self.iocs:
                writer.writerow([
                    ioc.id,
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.defanged_value,
                    ioc.severity.value,
                    ioc.confidence,
                    ioc.feed_count,
                    ";".join(ioc.sources),
                    ";".join(ioc.tags),
                    ioc.first_seen,
                    ioc.last_seen
                ])

    def export_markdown(self, output_path: Path):
        """Generates an audit-ready Markdown Threat Intelligence Report."""
        metrics = self.get_summary_metrics()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        md = []
        md.append("# Threat Intelligence Aggregator (Non-AI) - Executive Report\n")
        md.append(f"> **Generated UTC:** `{metrics['timestamp']}`  \n")
        md.append(f"> **Feeds Ingested:** {metrics['successful_feeds']} / {metrics['total_feeds_configured']}  \n")
        md.append(f"> **Unique Normalized Indicators:** {metrics['total_iocs']}  \n")
        md.append(f"> **Cross-Feed Repetition Rate:** {metrics['repetition_ratio'] * 100:.1f}%\n")

        md.append("## 1. Indicator Telemetry Breakdown\n")
        md.append("| Indicator Type | Count | % of Total |")
        md.append("| :--- | :--- | :--- |")
        for ioc_type, count in sorted(metrics["type_breakdown"].items()):
            pct = (count / max(1, metrics['total_iocs'])) * 100
            md.append(f"| `{ioc_type.upper()}` | **{count}** | {pct:.1f}% |")

        md.append("\n## 2. Threat Severity Classification\n")
        md.append("| Severity Rating | Indicators | Recommended Blue Team Action |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **CRITICAL** | {metrics['severity_breakdown']['CRITICAL']} | Immediate automated perimeter & EDR block; triage internal logs |")
        md.append(f"| **HIGH** | {metrics['severity_breakdown']['HIGH']} | Block at gateway / firewall; alert SOC on outbound connection |")
        md.append(f"| **MEDIUM** | {metrics['severity_breakdown']['MEDIUM']} | Web proxy / DNS sinkhole inspection; watchlist logging |")
        md.append(f"| **LOW** | {metrics['severity_breakdown']['LOW']} | Passive monitoring & correlation enrichment |")

        md.append("\n## 3. High-Priority Repeated Indicators (Cross-Source Matches)\n")
        md.append("Repeated indicators flagged by 2 or more distinct feeds represent high-confidence threats:\n")
        md.append("| Indicator (Defanged) | Type | Feeds Contributed | Severity | Confidence | Tags |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        top_repeated = self.correlation_stats.get("top_repeated_iocs", [])
        if not top_repeated:
            md.append("| *None detected* | - | - | - | - | - |")
        else:
            for item in top_repeated[:15]:
                tags_str = ", ".join(item['tags']) or "-"
                sources_str = ", ".join(item['sources'])
                md.append(f"| `{item['defanged_value']}` | {item['ioc_type']} | {sources_str} ({item['feed_count']}) | **{item['severity']}** | {item['confidence']} | `{tags_str}` |")

        md.append("\n## 4. Ingestion Feed Status\n")
        md.append("| Feed Name | Format | Status | Ingested Count | Category |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for fname, fstat in self.feed_audit.items():
            st = fstat.get('status', 'unknown').upper()
            cnt = fstat.get('count', 0)
            fmt = fstat.get('format', '-')
            cat = fstat.get('category', 'external')
            md.append(f"| **{fname}** | `{fmt}` | `{st}` | {cnt} | {cat} |")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")

    def export_html(self, output_path: Path):
        """Generates a standalone, dark-themed SOC Threat Intelligence Dashboard."""
        metrics = self.get_summary_metrics()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        iocs_json = json.dumps([ioc.to_dict() for ioc in self.iocs])
        metrics_json = json.dumps(metrics)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyber Threat Intelligence Aggregator - Executive Report</title>
<style>
:root {{
  --bg-main: #0b0f19;
  --bg-card: #111827;
  --border-color: #1f2937;
  --text-main: #f3f4f6;
  --text-muted: #9ca3af;
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --sev-critical: #ef4444;
  --sev-high: #f97316;
  --sev-medium: #eab308;
  --sev-low: #10b981;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-main);
  padding: 24px;
  line-height: 1.5;
}}
.header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 20px;
  margin-bottom: 24px;
}}
.header h1 {{
  font-size: 24px;
  font-weight: 700;
  color: var(--text-main);
  display: flex;
  align-items: center;
  gap: 10px;
}}
.badge {{
  background: rgba(6, 182, 212, 0.15);
  color: var(--accent-cyan);
  border: 1px solid rgba(6, 182, 212, 0.3);
  padding: 4px 10px;
  border-radius: 9999px;
  font-size: 12px;
  font-weight: 600;
}}
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}
.stat-card {{
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 20px;
  border-radius: 12px;
}}
.stat-title {{
  color: var(--text-muted);
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}}
.stat-value {{
  font-size: 28px;
  font-weight: 700;
  color: var(--text-main);
}}
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
}}
.card h2 {{
  font-size: 18px;
  margin-bottom: 16px;
  color: var(--text-main);
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}}
th, td {{
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
}}
th {{
  color: var(--text-muted);
  font-weight: 600;
  background: rgba(31, 41, 55, 0.4);
}}
tr:hover {{
  background: rgba(255, 255, 255, 0.02);
}}
.sev-tag {{
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}}
.sev-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: var(--sev-critical); border: 1px solid var(--sev-critical); }}
.sev-HIGH {{ background: rgba(249, 115, 22, 0.2); color: var(--sev-high); border: 1px solid var(--sev-high); }}
.sev-MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: var(--sev-medium); border: 1px solid var(--sev-medium); }}
.sev-LOW {{ background: rgba(16, 185, 129, 0.2); color: var(--sev-low); border: 1px solid var(--sev-low); }}
.search-input {{
  width: 100%;
  max-width: 380px;
  padding: 10px 14px;
  background: #1f2937;
  border: 1px solid #374151;
  color: #fff;
  border-radius: 8px;
  margin-bottom: 16px;
  outline: none;
}}
.search-input:focus {{
  border-color: var(--accent-cyan);
}}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background: rgba(255, 255, 255, 0.05);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 13px;
}}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>🛡️ Threat Intelligence Aggregator <span class="badge">Non-AI Defensive Engine</span></h1>
    <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Normalized IOC Database, Cross-Feed Correlation & Automated Defensive Blocklists</p>
  </div>
  <div style="text-align: right; font-size: 13px; color: var(--text-muted);">
    Generated: <strong>{metrics['timestamp'][:19]}Z</strong>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-title">Total Unique IOCs</div>
    <div class="stat-value" style="color: var(--accent-cyan);">{metrics['total_iocs']}</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Repeated Multi-Feed Threats</div>
    <div class="stat-value" style="color: var(--sev-critical);">{metrics['repeated_iocs_count']}</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Active Feeds Ingested</div>
    <div class="stat-value">{metrics['successful_feeds']} / {metrics['total_feeds_configured']}</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Critical & High Threats</div>
    <div class="stat-value" style="color: var(--sev-high);">{metrics['severity_breakdown']['CRITICAL'] + metrics['severity_breakdown']['HIGH']}</div>
  </div>
</div>

<div class="card">
  <h2>🎯 High-Priority Repeated Indicators (Correlated Across Multiple Feeds)</h2>
  <table>
    <thead>
      <tr>
        <th>Indicator (Defanged)</th>
        <th>Type</th>
        <th>Feeds Count</th>
        <th>Sources</th>
        <th>Severity</th>
        <th>Risk Score</th>
        <th>Tags</th>
      </tr>
    </thead>
    <tbody>
"""
        top_repeated = self.correlation_stats.get("top_repeated_iocs", [])
        if not top_repeated:
            html_content += "<tr><td colspan='7'>No multi-feed overlaps detected.</td></tr>"
        else:
            for item in top_repeated:
                tags_str = ", ".join(item['tags']) or "-"
                sources_str = ", ".join(item['sources'])
                sev = item['severity']
                html_content += f"""
      <tr>
        <td><code>{item['defanged_value']}</code></td>
        <td><code>{item['ioc_type']}</code></td>
        <td><strong>{item['feed_count']} feeds</strong></td>
        <td>{sources_str}</td>
        <td><span class="sev-tag sev-{sev}">{sev}</span></td>
        <td><strong>{item['confidence']}</strong> / 100</td>
        <td>{tags_str}</td>
      </tr>"""

        html_content += f"""
    </tbody>
  </table>
</div>

<div class="card">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 12px;">
    <div>
      <h2>📋 Complete Unified IOC Inventory</h2>
      <div id="searchStats" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Showing all indicators</div>
    </div>
    <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
      <input type="text" id="iocSearch" class="search-input" style="margin-bottom: 0;" placeholder="Search indicator, source, type, or tag..." oninput="filterTable()" onkeydown="if(event.key==='Enter'){{ filterTable(); event.preventDefault(); }}">
      <button type="button" id="searchIndicatorBtn" onclick="filterTable()" style="background: var(--accent-blue); color: #fff; border: none; padding: 10px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;">🔍 Search Indicator</button>
      <select id="sevFilter" onchange="filterTable()" style="background: #1f2937; color: #fff; border: 1px solid #374151; padding: 9px 12px; border-radius: 8px; outline: none; font-size: 13px; cursor: pointer;">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <select id="typeFilter" onchange="filterTable()" style="background: #1f2937; color: #fff; border: 1px solid #374151; padding: 9px 12px; border-radius: 8px; outline: none; font-size: 13px; cursor: pointer;">
        <option value="">All Types</option>
        <option value="ipv4">IPv4</option>
        <option value="domain">Domain</option>
        <option value="url">URL</option>
        <option value="sha256">SHA256</option>
        <option value="md5">MD5</option>
        <option value="email">Email</option>
      </select>
      <button type="button" id="clearBtn" onclick="clearSearch()" style="background: #374151; color: #f3f4f6; border: 1px solid #4b5563; padding: 10px 14px; border-radius: 8px; cursor: pointer; font-size: 13px;">Clear</button>
    </div>
  </div>
  <table id="iocTable">
    <thead>
      <tr>
        <th>Indicator</th>
        <th>Type</th>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Feed Sources</th>
        <th>Tags</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
"""
        for ioc in self.iocs:
            sev = ioc.severity.value
            tags_str = ", ".join(ioc.tags) or "-"
            sources_str = ", ".join(ioc.sources)
            html_content += f"""
      <tr>
        <td><code>{ioc.defanged_value}</code></td>
        <td><code>{ioc.ioc_type.value}</code></td>
        <td><span class="sev-tag sev-{sev}">{sev}</span></td>
        <td>{ioc.confidence}</td>
        <td>{sources_str}</td>
        <td>{tags_str}</td>
        <td style="color: var(--text-muted); font-size: 12px;">{ioc.last_seen[:10]}</td>
      </tr>"""

        html_content += """
      <tr id="noResultsRow" style="display: none;">
        <td colspan="7" style="text-align: center; padding: 40px 16px;">
          <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
          <div style="font-size: 16px; font-weight: 700; color: #10b981; margin-bottom: 6px;">Clean / Unflagged Indicator</div>
          <div style="font-size: 14px; color: var(--text-main); margin-bottom: 4px;">No malicious record found for "<span id="noResultsQuery" style="color: var(--accent-cyan); font-weight: 600;"></span>"</div>
          <div style="font-size: 12px; color: var(--text-muted);">This indicator does not appear in any active threat feeds (Safe / Not in Blocklists).</div>
        </td>
      </tr>
    </tbody>
  </table>
</div>

<script>
function filterTable() {
  var input = document.getElementById("iocSearch");
  var rawQuery = (input ? input.value : "").trim().toLowerCase();
  var cleanQuery = rawQuery.replace(/\\[\\.\\]/g, ".").replace(/\\[:\\]/g, ":").replace(/\\[@\\]/g, "@");

  var sevSelect = document.getElementById("sevFilter");
  var selectedSev = (sevSelect ? sevSelect.value : "").trim().toUpperCase();

  var typeSelect = document.getElementById("typeFilter");
  var selectedType = (typeSelect ? typeSelect.value : "").trim().toLowerCase();

  var rows = document.querySelectorAll("#iocTable tbody tr:not(#noResultsRow)");
  var visibleCount = 0;

  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var cells = row.getElementsByTagName("td");
    if (cells.length < 3) continue;

    var iocType = cells[1].textContent.trim().toLowerCase();
    var iocSev = cells[2].textContent.trim().toUpperCase();

    // Severity filter check
    if (selectedSev && iocSev.indexOf(selectedSev) === -1) {
      row.style.display = "none";
      continue;
    }

    // Type filter check
    if (selectedType && iocType !== selectedType) {
      row.style.display = "none";
      continue;
    }

    // Text query check across all row contents
    var rowRawText = (row.textContent || "").toLowerCase();
    var rowCleanText = rowRawText.replace(/\\[\\.\\]/g, ".").replace(/\\[:\\]/g, ":").replace(/\\[@\\]/g, "@");

    if (!rawQuery || rowRawText.indexOf(rawQuery) !== -1 || rowCleanText.indexOf(cleanQuery) !== -1) {
      row.style.display = "";
      visibleCount++;
    } else {
      row.style.display = "none";
    }
  }

  var noResults = document.getElementById("noResultsRow");
  var noResultsQuery = document.getElementById("noResultsQuery");
  if (noResults) {
    if (visibleCount === 0 && (rawQuery || selectedSev || selectedType)) {
      noResults.style.display = "";
      if (noResultsQuery) {
        noResultsQuery.textContent = rawQuery || (selectedSev ? "Severity: " + selectedSev : "") || (selectedType ? "Type: " + selectedType : "");
      }
    } else {
      noResults.style.display = "none";
    }
  }

  var stats = document.getElementById("searchStats");
  if (stats) {
    var filterParts = [];
    if (rawQuery) filterParts.push('query: "' + rawQuery + '"');
    if (selectedSev) filterParts.push('severity: ' + selectedSev);
    if (selectedType) filterParts.push('type: ' + selectedType);

    if (filterParts.length === 0) {
      stats.textContent = "Showing all " + rows.length + " indicators";
    } else {
      stats.textContent = "Showing " + visibleCount + " of " + rows.length + " indicators (" + filterParts.join(", ") + ")";
    }
  }
}

function clearSearch() {
  var input = document.getElementById("iocSearch");
  if (input) input.value = "";
  var sevSelect = document.getElementById("sevFilter");
  if (sevSelect) sevSelect.value = "";
  var typeSelect = document.getElementById("typeFilter");
  if (typeSelect) typeSelect.value = "";
  filterTable();
  if (input) input.focus();
}

function bindSearchEvents() {
  var input = document.getElementById("iocSearch");
  if (input) {
    input.addEventListener("input", filterTable);
    input.addEventListener("keydown", function(e) {
      if (e.key === "Enter") {
        filterTable();
        e.preventDefault();
      }
    });
  }
  var btn = document.getElementById("searchIndicatorBtn");
  if (btn) {
    btn.addEventListener("click", filterTable);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bindSearchEvents);
} else {
  bindSearchEvents();
}
</script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
