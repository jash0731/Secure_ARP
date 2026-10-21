import ipaddress
import re


def binding(ip, mac):
    address = str(ipaddress.IPv4Address(ip))
    hardware = str(mac).lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", hardware):
        raise ValueError("MAC address must contain six hexadecimal pairs")
    return address, hardware


def label(value):
    if not isinstance(value, str) or len(value) > 80 or any(ord(c) < 32 for c in value):
        raise ValueError("Device name must be text of at most 80 characters")
    return value.strip()
