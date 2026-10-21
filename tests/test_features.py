import csv
import io
import json
import struct
from dataclasses import replace

import pytest

from secure_arp.config import Config, load_config
from secure_arp.crypto_auth import SecureARPAuth
from secure_arp.demo_harness import PSK, make_packets
from secure_arp.engine import MonitorEngine
from secure_arp.packet_io import decode_ethernet_arp, make_arp_reply, write_pcap
from secure_arp.pcap_analyzer import analyze_capture
from secure_arp.reports import csv_text, html_report
from secure_arp.storage import Repository

IP, MAC = "192.0.2.1", "02:00:00:00:00:01"
BAD = "02:00:00:00:00:99"


@pytest.fixture
def config(tmp_path):
    return Config(database_path=str(tmp_path / "state.sqlite3"),
                  log_path=str(tmp_path / "events.jsonl"), report_dir=str(tmp_path / "reports"))


def test_approval_persists_and_is_observed_by_running_engine(config):
    repository = Repository(config.database_path)
    engine = MonitorEngine(config, repository)
    engine.process(IP, MAC)
    repository.approve(IP, BAD, "Replacement gateway")
    assert engine.process(IP, BAD) == []
    assert engine.process(IP, MAC)[0].attack_type.value == "IP-MAC_BINDING_CONFLICT"
    reopened = Repository(config.database_path)
    assert reopened.load_bindings()[IP].mac == BAD
    assert reopened.load_bindings()[IP].static
    assert any(device["label"] == "Replacement gateway" and device["approved"] for device in reopened.devices())


def test_replay_rejected_after_engine_restart(config):
    repository = Repository(config.database_path)
    tag = SecureARPAuth(PSK).sign(IP, MAC, timestamp=100)
    first = MonitorEngine(config, repository, "secure", PSK)
    assert first.process(IP, MAC, tag_bytes=tag, timestamp=100) == []
    restarted = MonitorEngine(config, Repository(config.database_path), "secure", PSK)
    assert restarted.process(IP, MAC, tag_bytes=tag, timestamp=101)[0].attack_type.value == "REPLAY_SUSPECTED"


def test_revoking_approval_preserves_history_and_baseline(config):
    repository = Repository(config.database_path)
    repository.approve(IP, MAC, "Gateway")
    engine = MonitorEngine(config, repository)
    engine.process(IP, MAC)
    repository.revoke(IP)
    assert not repository.load_bindings()[IP].static
    assert repository.summary()["packets"] == 1
    assert engine.process(IP, BAD)[0].attack_type.value == "IP-MAC_BINDING_CONFLICT"


def test_rejected_sender_visible_but_never_approved(config):
    repository = Repository(config.database_path)
    engine = MonitorEngine(config, repository, "secure", PSK)
    engine.process(IP, BAD)
    assert repository.devices()[0]["mac"] == BAD
    assert not repository.devices()[0]["approved"]
    assert IP not in repository.load_bindings()


def test_filtering_export_and_injection_protection(config):
    repository = Repository(config.database_path)
    engine = MonitorEngine(config, repository)
    engine.process(IP, MAC, timestamp=100)
    engine.process(IP, BAD, timestamp=101)
    assert repository.summary({"q": IP})["events"] == 1
    assert repository.summary({"severity": "WARNING"})["events"] == 0
    assert repository.events({"q": "' OR 1=1 --"}) == []
    with pytest.raises(ValueError):
        repository.events({"from": "2026-01-02", "to": "2026-01-01"})
    event = repository.events()[0]
    event["detail"] = "<script>alert(1)</script>"
    report = html_report([event])
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    event["detail"] = "=HYPERLINK(\"https://example.invalid\")"
    row = list(csv.reader(io.StringIO(csv_text([event]))))[1]
    assert row[-1].startswith("'=")


def test_config_paths_are_relative_to_config_file(tmp_path):
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({"database_path": "state/history.sqlite3"}))
    assert load_config(path).database_path == str(tmp_path / "state/history.sqlite3")


@pytest.mark.parametrize("settings", [
    {"flood_threshold": 0}, {"flood_window_seconds": -1}, {"mode": "wrong"},
    {"web_port": 70000}, {"refresh_seconds": True}, {"unrecognized": 5}
])
def test_invalid_config_is_rejected(tmp_path, settings):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(settings))
    with pytest.raises(ValueError):
        load_config(path)


def test_ethernet_padding_and_vlan_tags():
    frame = make_arp_reply(IP, MAC)
    assert decode_ethernet_arp(frame) == (IP, MAC, b"")
    vlan = frame[:12] + b"\x81\x00\x00\x01" + frame[12:]
    assert decode_ethernet_arp(vlan) == (IP, MAC, b"")
    auth = SecureARPAuth(PSK)
    tag = auth.sign(IP, MAC)
    assert decode_ethernet_arp(make_arp_reply(IP, MAC, tag) + b"\0" * 4)[2] == tag


def test_truncated_frame_rejected():
    with pytest.raises(ValueError):
        decode_ethernet_arp(b"\0" * 8)
    with pytest.raises(ValueError):
        decode_ethernet_arp(make_arp_reply(IP, MAC)[:30])


def test_offline_secure_capture_uses_recorded_time(config, tmp_path):
    capture = tmp_path / "old.pcap"
    auth = SecureARPAuth(PSK)
    tag = auth.sign(IP, MAC, timestamp=100)
    write_pcap(capture, [(100, make_arp_reply(IP, MAC, tag)), (101, make_arp_reply(IP, MAC, tag))])
    result = analyze_capture(capture, config, tmp_path / "analysis", "secure", PSK)
    assert result["packets"] == 2
    assert result["types"] == {"REPLAY_SUSPECTED": 1}
    assert not (tmp_path / "state.sqlite3").exists()
    assert (tmp_path / "analysis/events.csv").is_file()


def test_offline_rate_checks_do_not_treat_fast_file_read_as_flood(config, tmp_path):
    capture = tmp_path / "slow.pcap"
    write_pcap(capture, [(100 + index * 10, make_arp_reply(IP, MAC)) for index in range(20)])
    result = analyze_capture(capture, config, tmp_path / "analysis")
    assert result["packets"] == 20
    assert result["events"] == 0


def test_demo_capture_contains_every_security_category(config, tmp_path):
    capture = tmp_path / "demo.pcap"
    write_pcap(capture, make_packets(config))
    result = analyze_capture(capture, config, tmp_path / "analysis", "secure", PSK)
    assert set(result["types"]) == {
        "IP-MAC_BINDING_CONFLICT", "AUTHENTICATION_FAILURE", "REPLAY_SUSPECTED", "ARP_REPLY_FLOOD"}


def test_analysis_does_not_overwrite_previous_results(config, tmp_path):
    capture = tmp_path / "test.pcap"
    write_pcap(capture, [(100, make_arp_reply(IP, MAC))])
    destination = tmp_path / "analysis"
    analyze_capture(capture, config, destination)
    with pytest.raises(ValueError, match="not overwritten"):
        analyze_capture(capture, config, destination)


def test_pcapng_capture_supported(config, tmp_path):
    frame = make_arp_reply(IP, MAC)
    padded = frame + b"\0" * (-len(frame) % 4)
    def block(kind, body):
        length = len(body) + 12
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packet = block(6, struct.pack("<IIIII", 0, 0, 100_000_000, len(frame), len(frame)) + padded)
    capture = tmp_path / "test.pcapng"
    capture.write_bytes(section + interface + packet)
    result = analyze_capture(capture, config, tmp_path / "analysis")
    assert result["packets"] == 1
    assert result["events"] == 0
