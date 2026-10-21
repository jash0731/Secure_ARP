import threading
import time

from .crypto_auth import SecureARPAuth
from .packet_io import decode_ethernet_arp
from .detector import SpoofDetector
from .logger_util import EventLogger
from .trust_store import TrustStore
from .validation import binding


class MonitorEngine:
    def __init__(self, config, repository, mode=None, psk=None, source="live", logger=None):
        self.config = config
        self.repository = repository
        self.mode = mode or config.mode
        self.source = source
        self.logger = logger or EventLogger(config.log_path)
        store = TrustStore(config.static_bindings_path, config.lock_seconds)
        repository.seed_bindings(store.bindings)
        auth = SecureARPAuth(psk, config.max_clock_skew_seconds, config.replay_cache_size, replay_store=repository) if self.mode == "secure" else None
        self.detector = SpoofDetector(store, self.mode, auth, config.flood_window_seconds, config.flood_threshold)
        self._lock = threading.Lock()

    def process(self, ip, mac, interface="demo", tag_bytes=None, timestamp=None):
        ip, mac = binding(ip, mac)
        timestamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            self.detector.trust_store.bindings = self.repository.load_bindings()
            events = self.detector.process_all(ip, mac, interface, tag_bytes, timestamp)
            candidate = self.detector.trust_store.bindings.get(ip)
            rejected = any(event.severity.value == "CRITICAL" for event in events)
            self.repository.record(ip, mac, interface, timestamp, self.source, events,
                                   candidate if candidate and candidate.mac == mac and not rejected else None)
            for event in events:
                self.logger.log(event, self.source)
            return events

    def process_frame(self, frame, interface="capture", timestamp=None):
        reply = decode_ethernet_arp(frame)
        if reply is None:
            return []
        ip, mac, tag = reply
        return self.process(ip, mac, interface, tag, timestamp)

    def process_packet(self, packet, interface="capture", timestamp=None):
        return self.process_frame(bytes(packet), interface, timestamp)
