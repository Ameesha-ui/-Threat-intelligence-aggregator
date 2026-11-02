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


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start_server(port: int = 8080, max_retries: int = 10):
    """Starts the local dashboard web server with automatic port fallback if occupied."""
    handler = ThreatReportHandler
    current_port = port
    httpd = None

    for _ in range(max_retries):
        try:
            httpd = ReusableTCPServer(("", current_port), handler)
            break
        except OSError as e:
            # 10048 (Windows), 98 (Linux), 48 (macOS) mean port already in use
            if getattr(e, "winerror", None) == 10048 or getattr(e, "errno", None) in (48, 98, 10048):
                print(f"[!] Port {current_port} is in use. Trying port {current_port + 1}...", flush=True)
                current_port += 1
            else:
                raise

    if not httpd:
        print(f"[!] Could not bind to any port between {port} and {port + max_retries - 1}.", flush=True)
        return

    with httpd:
        url = f"http://localhost:{current_port}/output/reports/threat_report.html"
        print(f"\n[+] Serving Threat Intelligence Dashboard at: {url}", flush=True)
        print("[*] Press Ctrl+C to terminate the dashboard server.", flush=True)
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Dashboard server stopped.")


if __name__ == "__main__":
    start_server()

