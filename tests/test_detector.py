"""
Unit tests for the Secure ARP detection pipeline. Run with:  pytest -q
"""
from secure_arp.crypto_auth import SecureARPAuth
from secure_arp.detector import SpoofDetector
from secure_arp.trust_store import TrustStore

PSK = b"unit-test-32-byte-shared-secret!!"


def test_first_sighting_is_trusted():
    ts = TrustStore()
    d = SpoofDetector(ts, mode="standard")
    assert d.process("10.0.0.1", "aa:aa:aa:aa:aa:01", "eth0") is None


def test_conflicting_mac_flagged_in_standard_mode():
    ts = TrustStore()
    d = SpoofDetector(ts, mode="standard")
    assert d.process("10.0.0.1", "aa:aa:aa:aa:aa:01", "eth0") is None
    evt = d.process("10.0.0.1", "bb:bb:bb:bb:bb:02", "eth0")
    assert evt is not None
    assert evt.attack_type.value == "IP-MAC_BINDING_CONFLICT"


def test_static_binding_never_overridden():
    import tempfile, json, os
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"192.168.1.1": "aa:bb:cc:00:00:01"}, f)
        path = f.name
    ts = TrustStore(static_bindings_path=path)
    d = SpoofDetector(ts, mode="standard")
    evt = d.process("192.168.1.1", "de:ad:be:ef:13:37", "eth0")
    os.unlink(path)
    assert evt is not None
    assert evt.trusted_mac == "aa:bb:cc:00:00:01"


def test_secure_mode_rejects_unsigned_reply():
    ts = TrustStore()
    auth = SecureARPAuth(PSK)
    d = SpoofDetector(ts, mode="secure", auth=auth)
    evt = d.process("10.0.0.5", "cc:cc:cc:cc:cc:03", "eth0", tag_bytes=None)
    assert evt is not None
    assert evt.attack_type.value == "AUTHENTICATION_FAILURE"
    # and the trust store must NOT have been updated with the unverified binding
    assert "10.0.0.5" not in ts.bindings


def test_secure_mode_accepts_correctly_signed_reply():
    ts = TrustStore()
    auth = SecureARPAuth(PSK)
    d = SpoofDetector(ts, mode="secure", auth=auth)
    tag = auth.sign("10.0.0.5", "cc:cc:cc:cc:cc:03")
    evt = d.process("10.0.0.5", "cc:cc:cc:cc:cc:03", "eth0", tag_bytes=tag)
    assert evt is None
    assert ts.bindings["10.0.0.5"].mac == "cc:cc:cc:cc:cc:03"


def test_secure_mode_rejects_replayed_tag_after_skew_window():
    import time
    ts = TrustStore()
    auth = SecureARPAuth(PSK, max_skew_seconds=0.01)
    d = SpoofDetector(ts, mode="secure", auth=auth)
    tag = auth.sign("10.0.0.9", "dd:dd:dd:dd:dd:04")
    time.sleep(0.05)
    evt = d.process("10.0.0.9", "dd:dd:dd:dd:dd:04", "eth0", tag_bytes=tag)
    assert evt is not None
    assert "expired" in evt.detail


def test_flood_detection_triggers():
    ts = TrustStore()
    d = SpoofDetector(ts, mode="standard", flood_window_s=1.0, flood_threshold=3)
    events = [d.process("10.0.0.20", "ee:ee:ee:ee:ee:05", "eth0") for _ in range(6)]
    assert any(e and e.attack_type.value == "ARP_REPLY_FLOOD" for e in events)
