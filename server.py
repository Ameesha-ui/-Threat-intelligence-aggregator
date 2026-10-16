"""
Threat Intelligence Aggregator - Local Dashboard Server
Provides a lightweight HTTP server to serve the generated SOC HTML reports and blocklists.
"""

import http.server
import socketserver
import webbrowser
from pathlib import Path


class ThreatReportHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler directing root URL directly to the generated report."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path.cwd()), **kwargs)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            report_file = Path("output/reports/threat_report.html")
            if report_file.exists():
                self.path = "/output/reports/threat_report.html"
        return super().do_GET()


def start_server(port: int = 8080):
    """Starts the local dashboard web server."""
    handler = ThreatReportHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        url = f"http://localhost:{port}/output/reports/threat_report.html"
        print(f"\n[+] Serving Threat Intelligence Dashboard at: {url}")
        print("[*] Press Ctrl+C to terminate the dashboard server.")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Dashboard server stopped.")
