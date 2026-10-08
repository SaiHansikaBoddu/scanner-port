"""
Network Security Port Scanner - Web Backend
-------------------------------------------
Built using Python Standard Libraries (http.server, socket, json).
Serves the web frontend and provides the /api/scan endpoint for TCP port scanning.
"""

import http.server
import json
import os
import socket
import sys
import time
from datetime import datetime

# Port mapping for commonly used network services
COMMON_SERVICES = {
    20: "FTP-Data (File Transfer)",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Text)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP (Trivial FTP)",
    80: "HTTP (World Wide Web)",
    110: "POP3 (Post Office Protocol)",
    119: "NNTP (Network News)",
    123: "NTP (Network Time Protocol)",
    135: "MS-RPC (Microsoft RPC)",
    137: "NetBIOS-NS (Name Service)",
    138: "NetBIOS-DGM (Datagram)",
    139: "NetBIOS-SSN (Session Service)",
    143: "IMAP (Internet Message Access)",
    161: "SNMP (Network Management)",
    162: "SNMP-Trap",
    389: "LDAP (Directory Service)",
    443: "HTTPS (Secure Web HTTP)",
    445: "SMB / MS-DS (File Sharing)",
    465: "SMTPS (Secure SMTP)",
    587: "SMTP (Message Submission)",
    636: "LDAPS (Secure LDAP)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle DB",
    2049: "NFS (Network File System)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL (Database)",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis (Key-Value Store)",
    8000: "HTTP-Dev (Web Dev Server)",
    8080: "HTTP-Proxy / Alternate Web",
    8443: "HTTPS-Alt (Secure Web)",
    8888: "HTTP-Alt (Jupyter / App)",
    9000: "HTTP-Alt / SonarQube",
    27017: "MongoDB (Database)"
}

# Resolve path to the frontend folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")


def get_service_name(port):
    """Determine the standard network service name for a given port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        service = socket.getservbyport(port, "tcp")
        return service.upper()
    except (OSError, socket.error):
        return "Unknown"


def scan_port_range(target_ip, start_port, end_port):
    """
    Scans a range of TCP ports on target_ip sequentially.
    Returns list of port result dicts and count of open ports.
    """
    results = []
    open_ports = []

    for port in range(start_port, end_port + 1):
        # Create a standard TCP stream socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)  # Fast responsive timeout

        # connect_ex returns 0 if connection succeeded (Port is OPEN)
        result_code = s.connect_ex((target_ip, port))
        is_open = (result_code == 0)

        status = "OPEN" if is_open else "CLOSED"
        if is_open:
            open_ports.append(port)

        service = get_service_name(port)

        results.append({
            "port": port,
            "status": status,
            "service": service,
            "protocol": "TCP"
        })

        s.close()

    return results, open_ports


class PortScannerHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler for serving frontend and port scanning API."""

    def _send_cors_headers(self):
        """Set Cross-Origin Resource Sharing (CORS) headers."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, status_code, data):
        """Helper to send JSON response."""
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Serve frontend static files (HTML, CSS, JS)."""
        clean_path = self.path.split("?")[0].strip("/")

        if clean_path == "" or clean_path == "index.html":
            file_to_serve = os.path.join(FRONTEND_DIR, "index.html")
            content_type = "text/html; charset=utf-8"
        elif clean_path in ["style.css", "frontend/style.css"]:
            file_to_serve = os.path.join(FRONTEND_DIR, "style.css")
            content_type = "text/css; charset=utf-8"
        elif clean_path in ["script.js", "frontend/script.js"]:
            file_to_serve = os.path.join(FRONTEND_DIR, "script.js")
            content_type = "application/javascript; charset=utf-8"
        else:
            potential_file = os.path.join(FRONTEND_DIR, clean_path)
            if os.path.isfile(potential_file):
                file_to_serve = potential_file
                if clean_path.endswith(".css"):
                    content_type = "text/css; charset=utf-8"
                elif clean_path.endswith(".js"):
                    content_type = "application/javascript; charset=utf-8"
                elif clean_path.endswith(".html"):
                    content_type = "text/html; charset=utf-8"
                elif clean_path.endswith(".png"):
                    content_type = "image/png"
                elif clean_path.endswith(".ico"):
                    content_type = "image/x-icon"
                else:
                    content_type = "application/octet-stream"
            else:
                self.send_error(404, f"File not found: {self.path}")
                return

        if os.path.exists(file_to_serve):
            try:
                with open(file_to_serve, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
        else:
            self.send_error(404, f"File not found: {file_to_serve}")

    def do_POST(self):
        """Handle scanning API requests."""
        if self.path in ["/api/scan", "/api/scan/", "/scan"]:
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._send_json(400, {
                        "success": False,
                        "error": "Empty request body received."
                    })
                    return

                post_data = self.rfile.read(content_length)
                try:
                    payload = json.loads(post_data.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send_json(400, {
                        "success": False,
                        "error": "Invalid JSON format in request."
                    })
                    return

                target = str(payload.get("target", "")).strip()
                start_port = payload.get("start_port")
                end_port = payload.get("end_port")

                # Validate Target
                if not target:
                    self._send_json(400, {
                        "success": False,
                        "error": "Target IP or hostname is required."
                    })
                    return

                # Validate Port Numbers
                try:
                    start_port = int(start_port)
                    end_port = int(end_port)
                except (TypeError, ValueError):
                    self._send_json(400, {
                        "success": False,
                        "error": "Port numbers must be valid integers."
                    })
                    return

                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    self._send_json(400, {
                        "success": False,
                        "error": "Port numbers must be between 1 and 65535."
                    })
                    return

                if start_port > end_port:
                    self._send_json(400, {
                        "success": False,
                        "error": f"Starting port ({start_port}) cannot be greater than ending port ({end_port})."
                    })
                    return

                # Limit maximum range per single scan to prevent excessive browser waiting
                max_port_limit = 1000
                if (end_port - start_port + 1) > max_port_limit:
                    self._send_json(400, {
                        "success": False,
                        "error": f"Port range exceeds safety limit of {max_port_limit} ports per scan."
                    })
                    return

                # Resolve Hostname to IP
                try:
                    target_ip = socket.gethostbyname(target)
                except socket.gaierror:
                    self._send_json(400, {
                        "success": False,
                        "error": f"Could not resolve host '{target}'. Please check hostname or IP."
                    })
                    return

                # Perform the port scan
                start_time = time.time()
                results, open_ports = scan_port_range(target_ip, start_port, end_port)
                duration = round(time.time() - start_time, 2)

                print(f"[+] Scanned {target} ({target_ip}) ports {start_port}-{end_port} | Found {len(open_ports)} open | Time: {duration}s")

                self._send_json(200, {
                    "success": True,
                    "target": target,
                    "target_ip": target_ip,
                    "start_port": start_port,
                    "end_port": end_port,
                    "total_scanned": len(results),
                    "open_count": len(open_ports),
                    "open_ports": open_ports,
                    "duration_seconds": duration,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "results": results
                })

            except Exception as e:
                self._send_json(500, {
                    "success": False,
                    "error": f"Server error during port scan: {str(e)}"
                })
        else:
            self.send_error(404, "Endpoint not found.")

    def log_message(self, format, *args):
        """Custom clean logging to terminal."""
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}\n")


def run_server(host="127.0.0.1", port=8000):
    """Start the HTTP server on specified host and port."""
    server_address = (host, port)
    try:
        httpd = http.server.HTTPServer(server_address, PortScannerHandler)
    except OSError as e:
        if e.errno == 98 or e.errno == 10048:  # Address already in use
            alt_port = 8080
            print(f"[!] Port {port} in use, trying alternate port {alt_port}...")
            server_address = (host, alt_port)
            httpd = http.server.HTTPServer(server_address, PortScannerHandler)
            port = alt_port
        else:
            raise

    print("=" * 65)
    print("      NETWORK SECURITY PORT SCANNER - WEB BACKEND SERVER")
    print("=" * 65)
    print(f" [+] Python Backend running at : http://{host}:{port}")
    print(f" [+] Web Interface URL        : http://localhost:{port}")
    print(f" [+] API Endpoint             : http://{host}:{port}/api/scan")
    print(" [+] Press Ctrl+C in this terminal to stop the server.")
    print("=" * 65 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server. Goodbye!")
        httpd.server_close()
        sys.exit(0)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    run_server(host="0.0.0.0", port=port)
