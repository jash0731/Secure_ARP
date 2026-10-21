from dataclasses import dataclass, field
from enum import Enum
from time import time


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    MAC_MISMATCH = "IP-MAC_BINDING_CONFLICT"
    UNSOLICITED_REPLY = "UNSOLICITED_ARP_REPLY"
    GRATUITOUS_FLOOD = "ARP_REPLY_FLOOD"
    BAD_SIGNATURE = "AUTHENTICATION_FAILURE"
    REPLAY = "REPLAY_SUSPECTED"


@dataclass
class ARPBinding:
    ip: str
    mac: str
    first_seen: float = field(default_factory=time)
    last_seen: float = field(default_factory=time)
    static: bool = False
    hits: int = 1


@dataclass
class AttackEvent:
    timestamp: float
    attack_type: AttackType
    severity: Severity
    src_ip: str
    claimed_mac: str
    trusted_mac: str | None
    interface: str
    detail: str
    mode: str

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "type": self.attack_type.value,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "claimed_mac": self.claimed_mac,
            "trusted_mac": self.trusted_mac,
            "interface": self.interface,
            "detail": self.detail,
            "mode": self.mode,
        }
