import math
import struct

import pytest

from secure_arp.crypto_auth import HEADER, FULL_TAG_LEN, SecureARPAuth
from secure_arp.detector import SpoofDetector
from secure_arp.trust_store import TrustStore

KEY = b"unit-test-shared-key-at-least-32-bytes"
IP = "192.0.2.1"
MAC = "02:00:00:00:00:01"


def test_replay_rejected_inside_freshness_window():
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    tag = auth.sign(IP, MAC)
    assert auth.verify(IP, MAC, tag) == (True, "ok")
    assert auth.verify(IP, MAC, tag) == (False, "replayed")


def test_two_new_messages_at_same_timestamp_are_valid():
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    first, second = auth.sign(IP, MAC), auth.sign(IP, MAC)
    assert first != second
    assert auth.verify(IP, MAC, first)[0]
    assert auth.verify(IP, MAC, second)[0]


@pytest.mark.parametrize("ip,mac", [("192.0.2.2", MAC), (IP, "02:00:00:00:00:02")])
def test_signature_binds_both_sender_fields(ip, mac):
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    assert auth.verify(ip, mac, auth.sign(IP, MAC)) == (False, "bad_mac")


def test_replay_cache_never_evicts_a_fresh_tag_to_accept_another():
    auth = SecureARPAuth(KEY, replay_cache_size=1, clock=lambda: 100)
    first, second = auth.sign(IP, MAC), auth.sign(IP, MAC)
    assert auth.verify(IP, MAC, first)[0]
    assert auth.verify(IP, MAC, second) == (False, "replay_cache_full")
    assert auth.verify(IP, MAC, first) == (False, "replayed")
    later = auth.sign(IP, MAC, timestamp=106)
    assert auth.verify(IP, MAC, later, now=106)[0]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_timestamp_rejected(value):
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    tag = bytearray(auth.sign(IP, MAC))
    tag[5:13] = struct.pack(">d", value)
    assert auth.verify(IP, MAC, bytes(tag)) == (False, "malformed")


def test_bad_signature_does_not_consume_the_original_message():
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    tag = auth.sign(IP, MAC)
    corrupted = tag[:-1] + bytes([tag[-1] ^ 1])
    assert not auth.verify(IP, MAC, corrupted)[0]
    assert auth.verify(IP, MAC, tag)[0]


def test_truncated_and_legacy_tags_fail_closed():
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    assert len(auth.sign(IP, MAC)) == FULL_TAG_LEN
    assert auth.verify(IP, MAC, b"x" * 24) == (False, "malformed")
    assert auth.verify(IP, MAC, b"") == (False, "missing")


def test_flood_does_not_mask_authentication_or_conflict():
    store = TrustStore()
    auth = SecureARPAuth(KEY, clock=lambda: 100)
    detector = SpoofDetector(store, "secure", auth, flood_threshold=1, clock=lambda: 100)
    detector.process(IP, MAC, "test", auth.sign(IP, MAC))
    events = detector.process_all(IP, "02:00:00:00:00:99", "test")
    assert {event.attack_type.value for event in events} == {
        "AUTHENTICATION_FAILURE", "IP-MAC_BINDING_CONFLICT", "ARP_REPLY_FLOOD"}
    assert store.bindings[IP].mac == MAC


def test_mac_change_still_needs_approval_after_learning_window():
    store = TrustStore(lock_seconds=1)
    store.check(IP, MAC, now=100)
    assert not store.check(IP, "02:00:00:00:00:99", now=1000)[0]
    assert store.bindings[IP].mac == MAC


def test_flood_uses_packet_time_and_keeps_memory_bounded():
    detector = SpoofDetector(TrustStore(), flood_window_s=2, flood_threshold=3)
    for timestamp in (100, 103, 106, 109):
        assert detector.process(IP, MAC, "test", timestamp=timestamp) is None
    for index in range(50):
        detector.process(IP, MAC, "test", timestamp=200 + index / 100)
    assert len(detector._reply_times[IP]) == 4


def test_unsigned_unknown_sender_never_becomes_a_trusted_baseline():
    detector = SpoofDetector(TrustStore(), "secure", SecureARPAuth(KEY))
    detector.process(IP, MAC, "test")
    assert IP not in detector.trust_store.bindings
