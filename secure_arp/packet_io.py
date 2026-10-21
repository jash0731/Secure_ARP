import ipaddress
import struct
from pathlib import Path

from .crypto_auth import FULL_TAG_LEN, MAGIC
from .validation import binding


def decode_ethernet_arp(frame):
    if len(frame) < 14:
        raise ValueError("Truncated Ethernet header")
    protocol = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    for _ in range(4):
        if protocol not in (0x8100, 0x88A8):
            break
        if len(frame) < offset + 4:
            raise ValueError("Truncated VLAN header")
        protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if protocol != 0x0806:
        return None
    if len(frame) < offset + 8:
        raise ValueError("Truncated ARP header")
    hardware, protocol, hlen, plen, operation = struct.unpack("!HHBBH", frame[offset:offset + 8])
    if (hardware, protocol, hlen, plen, operation) != (1, 0x0800, 6, 4, 2):
        return None
    if len(frame) < offset + 28:
        raise ValueError("Truncated ARP reply")
    mac = ":".join(f"{part:02x}" for part in frame[offset + 8:offset + 14])
    ip = str(ipaddress.IPv4Address(frame[offset + 14:offset + 18]))
    payload = frame[offset + 28:]
    if not payload or not any(payload):
        tag = b""
    elif payload.startswith(MAGIC) and len(payload) >= FULL_TAG_LEN and not any(payload[FULL_TAG_LEN:]):
        tag = payload[:FULL_TAG_LEN]
    else:
        tag = payload
    return ip, mac, tag


def make_arp_reply(ip, mac, tag=b""):
    ip, mac = binding(ip, mac)
    hardware = bytes.fromhex(mac.replace(":", ""))
    address = ipaddress.IPv4Address(ip).packed
    ethernet = b"\xff" * 6 + hardware + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + hardware + address + b"\xff" * 6 + address
    return (ethernet + arp + tag).ljust(60, b"\x00")


def write_pcap(path, packets):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as target:
        target.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in packets:
            seconds = int(timestamp)
            fraction = min(999999, int((timestamp - seconds) * 1_000_000))
            target.write(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
            target.write(frame)
