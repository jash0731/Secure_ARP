import argparse
import time
from dataclasses import replace
from pathlib import Path

from .config import ROOT, load_config
from .crypto_auth import SecureARPAuth
from .engine import MonitorEngine
from .logger_util import EventLogger
from .packet_io import make_arp_reply, write_pcap
from .reports import write_reports
from .storage import Repository
from .vanilla_arp import VanillaARPCache


GATEWAY_IP = "192.0.2.1"
GATEWAY_MAC = "02:00:00:00:00:01"
ATTACKER_MAC = "02:00:00:00:00:99"
HOST_IP = "192.0.2.10"
HOST_MAC = "02:00:00:00:00:10"
PSK = b"demo-only-key-not-for-a-real-network"


def demo_config(config):
    directory = Path(config.database_path).parent
    return replace(config, database_path=str(directory / "demo.sqlite3"),
                   log_path=str(Path(config.log_path).parent / "demo_events.jsonl"),
                   report_dir=str(Path(config.report_dir) / "demo"), static_bindings_path=None)


def make_packets(config):
    auth = SecureARPAuth(PSK, config.max_clock_skew_seconds)
    packets = []
    base = time.time() - 4

    def add(ip, mac, offset, tag=None):
        timestamp = base + offset
        frame = make_arp_reply(ip, mac, tag or b"")
        packets.append((timestamp, frame))

    add(GATEWAY_IP, GATEWAY_MAC, 0, auth.sign(GATEWAY_IP, GATEWAY_MAC, base))
    add(HOST_IP, HOST_MAC, 0.2, auth.sign(HOST_IP, HOST_MAC, base + 0.2))
    add(GATEWAY_IP, ATTACKER_MAC, 0.4)
    replay_tag = auth.sign(GATEWAY_IP, GATEWAY_MAC, base + 0.6)
    add(GATEWAY_IP, GATEWAY_MAC, 0.6, replay_tag)
    add(GATEWAY_IP, GATEWAY_MAC, 0.8, replay_tag)
    bad_tag = bytearray(auth.sign(GATEWAY_IP, GATEWAY_MAC, base + 1))
    bad_tag[-1] ^= 1
    add(GATEWAY_IP, GATEWAY_MAC, 1, bytes(bad_tag))
    add(GATEWAY_IP, GATEWAY_MAC, 1.2,
        auth.sign(GATEWAY_IP, GATEWAY_MAC, base - config.max_clock_skew_seconds - 1))
    for index in range(config.flood_threshold + 3):
        offset = 1.5 + index * min(0.03, config.flood_window_seconds / (config.flood_threshold + 5))
        add(HOST_IP, HOST_MAC, offset, auth.sign(HOST_IP, HOST_MAC, base + offset))
    add(HOST_IP, ATTACKER_MAC, offset + 0.01)
    return packets


def run_demo(config, repository=None, write_capture=True):
    repository = repository or Repository(config.database_path)
    repository.approve(GATEWAY_IP, GATEWAY_MAC, "Demo gateway")
    repository.approve(HOST_IP, HOST_MAC, "Demo workstation")
    logger = EventLogger(config.log_path)
    engines = [MonitorEngine(config, repository, mode, PSK if mode == "secure" else None,
                             source="demo", logger=logger) for mode in ("standard", "secure")]
    packets = make_packets(config)
    before = repository.cursor()
    for timestamp, frame in packets:
        for engine in engines:
            engine.process_frame(frame, "demo", timestamp=timestamp)
    if write_capture:
        directory = Path(config.report_dir)
        directory.mkdir(parents=True, exist_ok=True)
        write_pcap(directory / "sample_arp.pcap", packets)
    repository.set_status(last_demo=time.time())
    return {"packets": len(packets), "passes": 2, "new_events": repository.cursor() - before}


def run():
    parser = argparse.ArgumentParser(description="Run an in-memory ARP comparison without sending traffic")
    parser.add_argument("--config")
    args = parser.parse_args()
    config = demo_config(load_config(args.config))
    repository = Repository(config.database_path)
    result = run_demo(config, repository)
    vanilla = VanillaARPCache()
    vanilla.receive_reply(GATEWAY_IP, GATEWAY_MAC)
    vanilla.receive_reply(GATEWAY_IP, ATTACKER_MAC)
    print(f"Plain cache model accepts spoofed MAC: {vanilla.table[GATEWAY_IP]}")
    print("Standard detector reports the binding conflict.")
    print("Secure detector rejects invalid/repeated authentication before updating its application trust table.")
    print("The demo does not send packets or modify the operating system's ARP cache.")
    print(f"Analyzed {result['packets']} synthetic replies in each mode; recorded {result['new_events']} events.")
    report = write_reports(repository.events(limit=None), config.report_dir, "Secure ARP demo comparison")
    from .dashboard import generate_chart, generate_html
    generate_chart(config.log_path, ROOT / "assets/dashboard.png", "(demo)")
    generate_html(config.log_path, ROOT / "assets/dashboard.html")
    print(f"Report: {report}")
    print(f"Sample capture: {Path(config.report_dir) / 'sample_arp.pcap'}")
    print("Open the interactive demo: python -m secure_arp --demo")


if __name__ == "__main__":
    run()
