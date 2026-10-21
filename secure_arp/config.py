import json
import math
from dataclasses import asdict, dataclass, fields
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Config:
    database_path: str = "data/secure_arp.sqlite3"
    log_path: str = "logs/events.jsonl"
    report_dir: str = "reports"
    static_bindings_path: str | None = None
    interface: str | None = None
    mode: str = "standard"
    lock_seconds: float = 300
    flood_window_seconds: float = 2
    flood_threshold: int = 8
    max_clock_skew_seconds: float = 5
    replay_cache_size: int = 10000
    alert_cooldown_seconds: float = 15
    refresh_seconds: float = 2
    web_port: int = 8765
    psk_env: str = "SECURE_ARP_PSK"

    def validate(self):
        if self.mode not in ("standard", "secure"):
            raise ValueError("mode must be standard or secure")
        for name in ("lock_seconds", "flood_window_seconds", "max_clock_skew_seconds",
                     "alert_cooldown_seconds", "refresh_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        for name in ("flood_threshold", "replay_cache_size", "web_port"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.web_port > 65535:
            raise ValueError("web_port must be between 1 and 65535")
        for name in ("database_path", "log_path", "report_dir", "psk_env"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a nonempty string")
        for name in ("interface", "static_bindings_path"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be null or a nonempty string")
        return self


def load_config(path=None):
    source = Path(path).expanduser().resolve() if path else ROOT / "config.json"
    if path and not source.exists():
        raise ValueError(f"Configuration file not found: {source}")
    data = json.loads(source.read_text(encoding="utf-8")) if source.exists() else {}
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a JSON object")
    unknown = set(data) - {item.name for item in fields(Config)}
    if unknown:
        raise ValueError(f"Unknown configuration setting(s): {', '.join(sorted(unknown))}")
    config = Config(**data).validate()
    for name in ("database_path", "log_path", "report_dir", "static_bindings_path"):
        value = getattr(config, name)
        if value is not None:
            target = Path(value).expanduser()
            setattr(config, name, str(target if target.is_absolute() else source.parent / target))
    return config


def public_settings(config):
    return {key: value for key, value in asdict(config).items()
            if key not in ("database_path", "log_path", "report_dir", "static_bindings_path", "psk_env")}
