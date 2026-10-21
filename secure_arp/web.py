import argparse
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .config import load_config, public_settings
from .demo_harness import demo_config, run_demo
from .reports import csv_text, html_report
from .storage import Repository


STATIC = Path(__file__).parent / "static"


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config, demo=False):
        if address[0] not in ("127.0.0.1", "localhost"):
            raise ValueError("Dashboard must bind to the local computer")
        self.config = config
        self.demo = demo
        self.repository = Repository(config.database_path)
        self.csrf_token = secrets.token_urlsafe(32)
        self.demo_lock = threading.Lock()
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SecureARP/2"

    def log_message(self, format, *args):
        return

    def respond(self, status, content, content_type="application/json; charset=utf-8", download=None):
        if isinstance(content, (dict, list)):
            content = json.dumps(content, allow_nan=False).encode()
        elif isinstance(content, str):
            content = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(content)

    def valid_host(self):
        port = self.server.server_port
        if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.respond(403, {"error": "Use the local dashboard address printed by the server"})
            return False
        return True

    def do_GET(self):
        if not self.valid_host():
            return
        try:
            parsed = urlsplit(self.path)
            filters = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
            repository = self.server.repository
            if parsed.path == "/":
                content = (STATIC / "index.html").read_text(encoding="utf-8")
                content = content.replace("__CSRF__", self.server.csrf_token)
                self.respond(200, content, "text/html; charset=utf-8")
            elif parsed.path in ("/app.js", "/style.css"):
                content_type = "text/javascript; charset=utf-8" if parsed.path.endswith(".js") else "text/css; charset=utf-8"
                self.respond(200, (STATIC / parsed.path[1:]).read_bytes(), content_type)
            elif parsed.path == "/api/state":
                limit = max(1, min(int(filters.get("limit", 50)), 100))
                offset = max(0, int(filters.get("offset", 0)))
                cursor = repository.cursor()
                previous = filters.get("since_id")
                state = {
                    "summary": repository.summary(filters),
                    "events": repository.events(filters, limit, offset),
                    "devices": repository.devices(),
                    "cursor": cursor,
                    "notifications": repository.critical_since(int(previous), cursor) if previous else [],
                    "status": repository.status(),
                    "settings": public_settings(self.server.config),
                    "demo": self.server.demo,
                    "limit": limit, "offset": offset,
                }
                self.respond(200, state)
            elif parsed.path == "/api/export.csv":
                self.respond(200, "\ufeff" + csv_text(repository.events(filters, limit=None)),
                             "text/csv; charset=utf-8", "secure_arp_events.csv")
            elif parsed.path == "/api/report.html":
                self.respond(200, html_report(repository.events(filters, limit=None)),
                             "text/html; charset=utf-8", "secure_arp_report.html")
            elif parsed.path == "/favicon.ico":
                self.respond(204, b"", "image/x-icon")
            else:
                self.respond(404, {"error": "Not found"})
        except (ValueError, TypeError) as exc:
            self.respond(400, {"error": str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            self.respond(500, {"error": "The dashboard could not read its data. Check the database and restart."})

    def do_POST(self):
        if not self.valid_host():
            return
        port = self.server.server_port
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self.respond(403, {"error": "Untrusted request origin"})
            return
        token = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, self.server.csrf_token):
            self.respond(403, {"error": "Refresh the dashboard before making changes"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("Invalid request size")
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("Request must contain JSON")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request must be a JSON object")
            path = urlsplit(self.path).path
            repository = self.server.repository
            if path == "/api/devices/approve":
                result = repository.approve(data["ip"], data["mac"], data.get("label", ""))
            elif path == "/api/devices/revoke":
                repository.revoke(data["ip"])
                result = {"ok": True}
            elif path == "/api/devices/rename":
                repository.rename(data["ip"], data.get("label", ""))
                result = {"ok": True}
            elif path == "/api/demo":
                if not self.server.demo:
                    self.respond(403, {"error": "Demo controls are available only in demo mode"})
                    return
                if not self.server.demo_lock.acquire(blocking=False):
                    self.respond(409, {"error": "A demonstration is already running"})
                    return
                try:
                    result = run_demo(self.server.config, repository, write_capture=False)
                finally:
                    self.server.demo_lock.release()
            else:
                self.respond(404, {"error": "Not found"})
                return
            self.respond(200, result)
        except (KeyError, ValueError, TypeError) as exc:
            self.respond(400, {"error": str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            self.respond(500, {"error": "The change could not be saved. Check the database and try again."})


def main():
    parser = argparse.ArgumentParser(description="Run the local Secure ARP dashboard")
    parser.add_argument("--config")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.port is not None:
            config.web_port = args.port
        config.validate()
        if args.demo:
            config = demo_config(config)
        server = DashboardServer(("127.0.0.1", config.web_port), config, args.demo)
        if args.demo and server.repository.summary()["packets"] == 0:
            run_demo(config, server.repository, write_capture=False)
        print(f"Secure ARP {'demo ' if args.demo else ''}dashboard: http://127.0.0.1:{server.server_port}", flush=True)
        print("Press Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard stopped.")
        finally:
            server.server_close()
    except (ValueError, OSError, ImportError) as exc:
        parser.exit(1, f"Dashboard could not start: {exc}\n")


if __name__ == "__main__":
    main()
