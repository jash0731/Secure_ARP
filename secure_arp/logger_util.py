import json
import threading
from pathlib import Path


class EventLogger:
    def __init__(self, log_path="logs/events.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, event, source=None):
        data = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        if source:
            data["source"] = source
        with self._lock, self.log_path.open("a", encoding="utf-8") as target:
            target.write(json.dumps(data) + "\n")

    def read_all(self):
        if not self.log_path.exists():
            return []
        result = []
        with self.log_path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        result.append(value)
                except json.JSONDecodeError:
                    continue
        return result

    def clear(self):
        self.log_path.unlink(missing_ok=True)
