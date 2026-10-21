import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .models import ARPBinding
from .validation import binding, label


EVENT_FIELDS = ("timestamp", "type", "severity", "src_ip", "claimed_mac", "trusted_mac",
                "interface", "detail", "mode", "source")


def parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            from datetime import timezone
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise ValueError("Dates must be valid ISO 8601 timestamps") from None


def event_filter(filters):
    clauses, values = [], []
    filters = filters or {}
    for key in ("severity", "type", "mode", "source"):
        if filters.get(key):
            clauses.append(f"{key} = ?")
            values.append(filters[key])
    if filters.get("q"):
        query = str(filters["q"])[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(src_ip LIKE ? ESCAPE '\\' OR claimed_mac LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')")
        values.extend([f"%{query}%"] * 3)
    start, end = parse_time(filters.get("from")), parse_time(filters.get("to"))
    if start is not None and end is not None and start > end:
        raise ValueError("Start time must be before end time")
    for operator, value in ((">=", start), ("<=", end)):
        if value is not None:
            clauses.append(f"timestamp {operator} ?")
            values.append(value)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), values


class Repository:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
                    src_ip TEXT NOT NULL, claimed_mac TEXT NOT NULL, trusted_mac TEXT,
                    interface TEXT NOT NULL, detail TEXT NOT NULL, mode TEXT NOT NULL, source TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
                CREATE INDEX IF NOT EXISTS events_severity ON events(severity);
                CREATE TABLE IF NOT EXISTS devices(
                    ip TEXT NOT NULL, mac TEXT NOT NULL, first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL, hits INTEGER NOT NULL, interface TEXT NOT NULL,
                    PRIMARY KEY(ip, mac)
                );
                CREATE TABLE IF NOT EXISTS bindings(
                    ip TEXT PRIMARY KEY, mac TEXT NOT NULL, first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL, static INTEGER NOT NULL, hits INTEGER NOT NULL,
                    label TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS counters(
                    source TEXT PRIMARY KEY, packets INTEGER NOT NULL, last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replay_tags(identity TEXT PRIMARY KEY, expiry REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS replay_expiry ON replay_tags(expiry);
            """)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def claim_authentication(self, identity, expiry, now, capacity):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM replay_tags WHERE expiry<?", (now,))
            key = identity.hex()
            if connection.execute("SELECT 1 FROM replay_tags WHERE identity=?", (key,)).fetchone():
                return False, "replayed"
            if connection.execute("SELECT count(*) FROM replay_tags").fetchone()[0] >= capacity:
                return False, "replay_cache_full"
            connection.execute("INSERT INTO replay_tags VALUES(?,?)", (key, expiry))
            return True, "ok"

    def load_bindings(self):
        with self.connect() as connection:
            return {
                row["ip"]: ARPBinding(**{key: bool(row[key]) if key == "static" else row[key]
                                        for key in ("ip", "mac", "first_seen", "last_seen", "static", "hits")})
                for row in connection.execute("SELECT * FROM bindings")
            }

    def seed_bindings(self, bindings):
        with self.connect() as connection:
            for item in bindings.values():
                connection.execute("""
                    INSERT INTO bindings(ip,mac,first_seen,last_seen,static,hits)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO NOTHING
                """, (item.ip, item.mac, item.first_seen, item.last_seen, int(item.static), item.hits))

    def approve(self, ip, mac, name=""):
        ip, mac = binding(ip, mac)
        name = label(name)
        now = time.time()
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO bindings(ip,mac,first_seen,last_seen,static,hits,label)
                VALUES(?,?,?,?,1,0,?)
                ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, static=1,
                    label=excluded.label, first_seen=excluded.first_seen, last_seen=excluded.last_seen, hits=0
            """, (ip, mac, now, now, name))
        return {"ip": ip, "mac": mac, "label": name, "approved": True}

    def revoke(self, ip):
        from ipaddress import IPv4Address
        ip = str(IPv4Address(ip))
        with self.connect() as connection:
            connection.execute("UPDATE bindings SET static=0 WHERE ip=?", (ip,))

    def rename(self, ip, name):
        from ipaddress import IPv4Address
        ip, name = str(IPv4Address(ip)), label(name)
        with self.connect() as connection:
            result = connection.execute("UPDATE bindings SET label=? WHERE ip=?", (name, ip))
            if not result.rowcount:
                raise ValueError("Approve or learn the device before naming it")

    def record(self, ip, mac, interface, timestamp, source, events, accepted_binding=None):
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO devices VALUES(?,?,?,?,1,?)
                ON CONFLICT(ip,mac) DO UPDATE SET
                    first_seen=min(devices.first_seen,excluded.first_seen),
                    last_seen=max(devices.last_seen,excluded.last_seen),
                    hits=devices.hits+1,interface=excluded.interface
            """, (ip, mac, timestamp, timestamp, interface))
            connection.execute("""
                INSERT INTO counters VALUES(?,1,?)
                ON CONFLICT(source) DO UPDATE SET packets=counters.packets+1,
                    last_seen=max(counters.last_seen,excluded.last_seen)
            """, (source, timestamp))
            if accepted_binding:
                item = accepted_binding
                connection.execute("""
                    INSERT INTO bindings(ip,mac,first_seen,last_seen,static,hits)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET
                        last_seen=max(bindings.last_seen,excluded.last_seen),hits=bindings.hits+1
                    WHERE bindings.mac=excluded.mac
                """, (item.ip, item.mac, item.first_seen, item.last_seen, int(item.static), item.hits))
            for event in events:
                data = event.to_dict()
                data["source"] = source
                cursor = connection.execute(
                    f"INSERT INTO events({','.join(EVENT_FIELDS)}) VALUES({','.join('?' for _ in EVENT_FIELDS)})",
                    [data[field] for field in EVENT_FIELDS])
                data["id"] = cursor.lastrowid

    def events(self, filters=None, limit=100, offset=0):
        where, values = event_filter(filters)
        query = "SELECT * FROM events" + where + " ORDER BY timestamp DESC,id DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            values += [max(1, min(int(limit), 500)), max(0, int(offset))]
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(query, values)]

    def devices(self):
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT d.*,b.mac AS baseline_mac,
                       CASE WHEN b.mac=d.mac THEN b.label ELSE '' END AS label,
                       CASE WHEN b.mac=d.mac THEN b.static ELSE 0 END AS approved,
                       CASE WHEN b.mac IS NOT NULL AND b.mac<>d.mac THEN 1 ELSE 0 END AS conflict
                FROM devices d LEFT JOIN bindings b ON b.ip=d.ip
                UNION ALL
                SELECT b.ip,b.mac,b.first_seen,b.last_seen,0,'',b.mac,b.label,b.static,0
                FROM bindings b WHERE NOT EXISTS(SELECT 1 FROM devices d WHERE d.ip=b.ip AND d.mac=b.mac)
                ORDER BY last_seen DESC
            """)
            return [dict(row) for row in rows]

    def summary(self, filters=None):
        where, values = event_filter(filters)
        with self.connect() as connection:
            counts = dict(connection.execute("SELECT severity,count(*) FROM events" + where +
                                             " GROUP BY severity", values).fetchall())
            types = dict(connection.execute("SELECT type,count(*) FROM events" + where +
                                            " GROUP BY type ORDER BY count(*) DESC", values).fetchall())
            timeline = [dict(row) for row in connection.execute(
                "SELECT CAST(timestamp/60 AS INTEGER)*60 AS time,count(*) AS count FROM events" +
                where + " GROUP BY CAST(timestamp/60 AS INTEGER) ORDER BY time DESC LIMIT 20", values)]
            return {
                "events": sum(counts.values()), "critical": counts.get("CRITICAL", 0),
                "warning": counts.get("WARNING", 0), "types": types, "timeline": list(reversed(timeline)),
                "devices": connection.execute("SELECT count(DISTINCT ip) FROM devices").fetchone()[0],
                "approved": connection.execute("SELECT count(*) FROM bindings WHERE static=1").fetchone()[0],
                "packets": connection.execute("SELECT coalesce(sum(packets),0) FROM counters").fetchone()[0],
            }

    def cursor(self):
        with self.connect() as connection:
            return connection.execute("SELECT coalesce(max(id),0) FROM events").fetchone()[0]

    def critical_since(self, cursor, through=None):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE id>? AND id<=? AND severity='CRITICAL' ORDER BY id DESC LIMIT 10",
                (int(cursor), self.cursor() if through is None else through))
            return [dict(row) for row in rows]

    def set_status(self, **values):
        with self.connect() as connection:
            for key, value in values.items():
                connection.execute("INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                   (key, json.dumps(value)))

    def status(self):
        with self.connect() as connection:
            result = {row["key"]: json.loads(row["value"])
                      for row in connection.execute("SELECT * FROM metadata")}
        if time.time() - result.get("heartbeat", 0) > 6:
            result["running"] = False
        return result
