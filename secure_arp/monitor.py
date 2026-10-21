import argparse
import os
import time
from collections import deque

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .config import load_config
from .engine import MonitorEngine
from .storage import Repository


console = Console()


def build_table(events, mode):
    table = Table(title=f"Secure ARP monitor · {mode.upper()}", expand=True)
    for name in ("Time", "Severity", "Type", "Source IP", "Claimed MAC", "Baseline MAC"):
        table.add_column(name)
    for event in list(events)[-15:][::-1]:
        table.add_row(time.strftime("%H:%M:%S", time.localtime(event.timestamp)),
                      event.severity.value, event.attack_type.value, event.src_ip,
                      event.claimed_mac, event.trusted_mac or "—")
    return table


def main():
    parser = argparse.ArgumentParser(description="Passively monitor ARP replies and update the local dashboard")
    parser.add_argument("--config")
    parser.add_argument("--iface")
    parser.add_argument("--mode", choices=["standard", "secure"])
    parser.add_argument("--static-bindings")
    parser.add_argument("--psk", help="Legacy key argument; prefer the configured environment variable")
    parser.add_argument("--log")
    parser.add_argument("--lock-seconds", type=float)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        for argument, setting in (("iface", "interface"), ("mode", "mode"), ("static_bindings", "static_bindings_path"),
                                  ("log", "log_path"), ("lock_seconds", "lock_seconds")):
            if getattr(args, argument) is not None:
                setattr(config, setting, getattr(args, argument))
        config.validate()
        psk = args.psk or os.environ.get(config.psk_env)
        if config.mode == "secure" and not psk:
            raise ValueError(f"Secure mode requires a shared key in {config.psk_env}")
        from scapy.all import AsyncSniffer
        repository = Repository(config.database_path)
        engine = MonitorEngine(config, repository, psk=psk.encode() if psk else None)
        events = deque(maxlen=200)
        errors = deque(maxlen=1)
        invalid_packets = 0

        def handle(packet):
            nonlocal invalid_packets
            try:
                events.extend(engine.process_packet(packet, config.interface or "default"))
            except (ValueError, TypeError):
                invalid_packets += 1
            except Exception as exc:
                errors.append(str(exc))

        sniffer = AsyncSniffer(filter="arp", prn=handle, iface=config.interface, store=False)
        repository.set_status(running=True, mode=config.mode, interface=config.interface or "default",
                              heartbeat=time.time())
        console.print(f"Passive capture started. Dashboard: http://127.0.0.1:{config.web_port}")
        console.print("Application trust validation only; no operating-system ARP blocking.")
        try:
            sniffer.start()
            with Live(build_table(events, config.mode), console=console, refresh_per_second=2) as display:
                while True:
                    time.sleep(0.5)
                    if errors:
                        raise RuntimeError(errors[-1])
                    if not sniffer.running:
                        raise RuntimeError(str(getattr(sniffer, "exception", None) or "Packet capture stopped"))
                    repository.set_status(running=True, heartbeat=time.time(), malformed_packets=invalid_packets)
                    display.update(build_table(events, config.mode))
        except KeyboardInterrupt:
            console.print("Monitor stopped.")
        finally:
            if sniffer.running:
                sniffer.stop()
            repository.set_status(running=False, heartbeat=time.time())
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        parser.exit(1, f"Monitor could not start or continue: {exc}\n")


if __name__ == "__main__":
    main()
