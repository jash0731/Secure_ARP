import hashlib
import heapq
import hmac
import ipaddress
import math
import secrets
import struct
import threading
import time

from .validation import binding


MAGIC = b"SARP"
VERSION = 1
TAG_LEN = 16
HEADER = struct.Struct(">4sBd16s")
FULL_TAG_LEN = HEADER.size + TAG_LEN


class SecureARPAuth:
    def __init__(self, psk, max_skew_seconds=5.0, replay_cache_size=10000, clock=None, replay_store=None):
        if not isinstance(psk, bytes) or len(psk) < 16:
            raise ValueError("Pre-shared key must contain at least 16 bytes")
        if not math.isfinite(max_skew_seconds) or max_skew_seconds <= 0:
            raise ValueError("Clock tolerance must be positive and finite")
        if type(replay_cache_size) is not int or replay_cache_size < 1:
            raise ValueError("Replay cache size must be a positive integer")
        self.psk = psk
        self.max_skew_seconds = max_skew_seconds
        self.replay_cache_size = replay_cache_size
        self.clock = clock or time.time
        self.replay_store = replay_store
        self._seen = {}
        self._expiry = []
        self._lock = threading.Lock()

    def _mac(self, ip, mac_addr, header):
        ip, mac_addr = binding(ip, mac_addr)
        payload = header + ipaddress.IPv4Address(ip).packed + bytes.fromhex(mac_addr.replace(":", ""))
        return hmac.new(self.psk, payload, hashlib.sha256).digest()[:TAG_LEN]

    def sign(self, ip, mac_addr, timestamp=None):
        timestamp = self.clock() if timestamp is None else timestamp
        if not math.isfinite(timestamp):
            raise ValueError("Timestamp must be finite")
        header = HEADER.pack(MAGIC, VERSION, timestamp, secrets.token_bytes(16))
        return header + self._mac(ip, mac_addr, header)

    def verify(self, ip, mac_addr, tag_bytes, now=None):
        now = self.clock() if now is None else now
        if not tag_bytes:
            return False, "missing"
        if not isinstance(tag_bytes, bytes) or len(tag_bytes) != FULL_TAG_LEN:
            return False, "malformed"
        magic, version, timestamp, nonce = HEADER.unpack(tag_bytes[:HEADER.size])
        if magic != MAGIC or version != VERSION or not math.isfinite(timestamp) or not math.isfinite(now):
            return False, "malformed"
        try:
            expected = self._mac(ip, mac_addr, tag_bytes[:HEADER.size])
        except (TypeError, ValueError):
            return False, "malformed"
        if not hmac.compare_digest(tag_bytes[HEADER.size:], expected):
            return False, "bad_mac"
        if abs(now - timestamp) > self.max_skew_seconds:
            return False, "expired"
        identity = hashlib.sha256(tag_bytes + expected).digest()
        if self.replay_store is not None:
            return self.replay_store.claim_authentication(
                identity, timestamp + self.max_skew_seconds, now, self.replay_cache_size)
        with self._lock:
            while self._expiry and self._expiry[0][0] < now:
                expiry, key = heapq.heappop(self._expiry)
                self._seen.pop(key, None)
            if identity in self._seen:
                return False, "replayed"
            if len(self._seen) >= self.replay_cache_size:
                return False, "replay_cache_full"
            expiry = timestamp + self.max_skew_seconds
            self._seen[identity] = expiry
            heapq.heappush(self._expiry, (expiry, identity))
        return True, "ok"


def extract_tag(arp_packet):
    payload = bytes(arp_packet.payload)
    if not payload:
        return b""
    if payload.startswith(MAGIC) and len(payload) >= FULL_TAG_LEN:
        trailer = payload[FULL_TAG_LEN:]
        if not trailer or not any(trailer):
            return payload[:FULL_TAG_LEN]
    return payload
