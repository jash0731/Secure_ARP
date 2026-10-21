import argparse
import math
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import load_config
from .engine import MonitorEngine
from .reports import write_reports
from .storage import Repository


def analyze_capture(capture, config, output_dir, mode="standard", psk=None):
    from scapy.utils import RawPcapReader

    capture = Path(capture)
    if not capture.is_file():
        raise ValueError(f"Capture not found: {capture}")
    output = Path(output_dir)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be new or empty; existing analysis was not overwritten")
    output.mkdir(parents=True, exist_ok=True)
    config = replace(config, database_path=str(output / "analysis.sqlite3"),
                     log_path=str(output / "events.jsonl"), mode=mode)
    repository = Repository(config.database_path)
    engine = MonitorEngine(config, repository, psk=psk, source="pcap")
    seen = skipped = out_of_order = unsupported = 0
    last_time = None
    with RawPcapReader(str(capture)) as packets:
        for frame, metadata in packets:
            seen += 1
            linktype = getattr(metadata, "linktype", getattr(packets, "linktype", None))
            if linktype != 1:
                unsupported += 1
                continue
            if hasattr(metadata, "sec"):
                timestamp = metadata.sec + metadata.usec / (1e9 if packets.nano else 1e6)
            else:
                if metadata.tshigh is None or metadata.tslow is None:
                    skipped += 1
                    continue
                timestamp = ((metadata.tshigh << 32) + metadata.tslow) / metadata.tsresol
            if not math.isfinite(timestamp) or timestamp < 0:
                skipped += 1
                continue
            if last_time is not None and timestamp < last_time:
                out_of_order += 1
            last_time = timestamp
            try:
                engine.process_frame(frame, "pcap", timestamp)
            except (ValueError, TypeError):
                skipped += 1
    summary = repository.summary()
    report = write_reports(repository.events(limit=None), output, f"ARP capture analysis: {capture.name}")
    return dict(summary, capture_packets=seen, malformed_packets=skipped,
                out_of_order_packets=out_of_order, unsupported_packets=unsupported, report=str(report))


def main():
    parser = argparse.ArgumentParser(description="Analyze a saved PCAP/PCAPNG locally without transmitting traffic")
    parser.add_argument("capture")
    parser.add_argument("--config")
    parser.add_argument("--mode", choices=["standard", "secure"], default="standard")
    parser.add_argument("--output-dir")
    parser.add_argument("--static-bindings")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.static_bindings:
            config.static_bindings_path = str(Path(args.static_bindings).resolve())
        psk = os.environ.get(config.psk_env)
        if args.mode == "secure" and not psk:
            raise ValueError(f"Set {config.psk_env} to the capture sender's shared key")
        output = args.output_dir or str(Path(config.report_dir) /
            ("capture-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")))
        result = analyze_capture(args.capture, config, output, args.mode, psk.encode() if psk else None)
        print(f"Read {result['capture_packets']} packets; analyzed {result['packets']} ARP replies.")
        print(f"Events: {result['events']} | Critical: {result['critical']} | Warning: {result['warning']}")
        print(f"Malformed packets skipped: {result['malformed_packets']}")
        print(f"Unsupported link-layer packets skipped: {result['unsupported_packets']}")
        if result["out_of_order_packets"]:
            print(f"Out-of-order timestamps: {result['out_of_order_packets']}; inspect rate results carefully.")
        print(f"Report: {result['report']}")
    except Exception as exc:
        parser.exit(1, f"Capture analysis failed: {exc}\n")


if __name__ == "__main__":
    main()
