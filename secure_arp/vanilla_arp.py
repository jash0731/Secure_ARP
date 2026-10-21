from dataclasses import dataclass, field


@dataclass
class VanillaARPCache:
    table: dict = field(default_factory=dict)

    def receive_reply(self, ip, mac):
        previous = self.table.get(ip)
        self.table[ip] = mac
        if previous is None:
            return f"learned {ip} -> {mac}"
        if previous != mac:
            return f"OVERWROTE {ip}: {previous} -> {mac} (unvalidated teaching model)"
        return f"reconfirmed {ip} -> {mac}"
