import math
import time
from collections import OrderedDict, deque

from .models import AttackEvent, AttackType, Severity
from .validation import binding


class SpoofDetector:
    def __init__(self, trust_store, mode="standard", auth=None,
                 flood_window_s=2.0, flood_threshold=8, clock=None):
        if mode not in ("standard", "secure"):
            raise ValueError("mode must be standard or secure")
        if mode == "secure" and auth is None:
            raise ValueError("secure mode requires a SecureARPAuth instance")
        if not math.isfinite(flood_window_s) or flood_window_s <= 0:
            raise ValueError("Flood window must be positive and finite")
        if type(flood_threshold) is not int or flood_threshold < 1:
            raise ValueError("Flood threshold must be a positive integer")
        self.trust_store = trust_store
        self.mode = mode
        self.auth = auth
        self.flood_window_s = flood_window_s
        self.flood_threshold = flood_threshold
        self.clock = clock or time.time
        self._reply_times = OrderedDict()

    def _check_flood(self, src_ip, now):
        if src_ip not in self._reply_times and len(self._reply_times) >= 10000:
            self._reply_times.popitem(last=False)
        times = self._reply_times.setdefault(src_ip, deque(maxlen=self.flood_threshold + 1))
        if times and now < times[-1]:
            times.clear()
        times.append(now)
        while times and now - times[0] > self.flood_window_s:
            times.popleft()
        self._reply_times.move_to_end(src_ip)
        return len(times) > self.flood_threshold

    def process_all(self, psrc, hwsrc, interface, tag_bytes=None, timestamp=None):
        psrc, hwsrc = binding(psrc, hwsrc)
        now = self.clock() if timestamp is None else timestamp
        if not math.isfinite(now):
            raise ValueError("Packet timestamp must be finite")
        flooded = self._check_flood(psrc, now)
        existing = self.trust_store.bindings.get(psrc)
        events = []
        authenticated = True
        if self.mode == "secure":
            authenticated, reason = self.auth.verify(psrc, hwsrc, tag_bytes or b"", now=now)
            if not authenticated:
                events.append(AttackEvent(
                    now, AttackType.REPLAY if reason == "replayed" else AttackType.BAD_SIGNATURE,
                    Severity.CRITICAL, psrc, hwsrc, existing.mac if existing else None, interface,
                    f"Authentication failed ({reason}); application trust table not updated", self.mode))
        if existing and existing.mac != hwsrc:
            state = "approved" if existing.static else (
                "recently learned" if now - existing.first_seen < self.trust_store.lock_seconds else "learned")
            events.append(AttackEvent(
                now, AttackType.MAC_MISMATCH, Severity.CRITICAL, psrc, hwsrc, existing.mac, interface,
                f"{psrc} is {state} as {existing.mac}; change to {hwsrc} needs explicit approval", self.mode))
        elif authenticated:
            self.trust_store.check(psrc, hwsrc, now=now)
        if flooded:
            events.append(AttackEvent(
                now, AttackType.GRATUITOUS_FLOOD, Severity.WARNING, psrc, hwsrc,
                existing.mac if existing else None, interface,
                f"> {self.flood_threshold} ARP replies from {psrc} within {self.flood_window_s}s", self.mode))
        return events

    def process(self, psrc, hwsrc, interface, tag_bytes=None, timestamp=None):
        events = self.process_all(psrc, hwsrc, interface, tag_bytes, timestamp)
        return events[0] if events else None
