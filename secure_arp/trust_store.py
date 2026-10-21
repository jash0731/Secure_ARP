import json
import time
from pathlib import Path

from .models import ARPBinding
from .validation import binding


class TrustStore:
    def __init__(self, static_bindings_path=None, lock_seconds=300):
        self.bindings = {}
        self.lock_seconds = lock_seconds
        if static_bindings_path:
            path = Path(static_bindings_path)
            if not path.exists():
                raise ValueError(f"Trusted bindings file not found: {path}")
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Static bindings must be a JSON object mapping IPv4 addresses to MAC addresses")
            for ip, mac in data.items():
                ip, mac = binding(ip, mac)
                self.bindings[ip] = ARPBinding(ip=ip, mac=mac, static=True)

    def check(self, ip, mac, now=None):
        ip, mac = binding(ip, mac)
        now = time.time() if now is None else now
        existing = self.bindings.get(ip)
        if existing is None:
            self.bindings[ip] = ARPBinding(ip=ip, mac=mac, first_seen=now, last_seen=now)
            return True, None
        if existing.mac == mac:
            existing.last_seen = max(existing.last_seen, now)
            existing.hits += 1
            return True, existing
        return False, existing

    def snapshot(self):
        return [vars(item).copy() for item in self.bindings.values()]
