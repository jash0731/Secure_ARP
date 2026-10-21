import csv
import html
import io
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


COLUMNS = ("timestamp_utc", "severity", "type", "src_ip", "claimed_mac",
           "trusted_mac", "interface", "mode", "source", "detail")


def utc(value):
    return datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def csv_text(events):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(COLUMNS)
    for event in events:
        data = dict(event, timestamp_utc=utc(event["timestamp"]))
        values = []
        for key in COLUMNS:
            value = str(data.get(key) or "")
            if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
    return buffer.getvalue()


def html_report(events, title="Secure ARP event report"):
    escape = lambda value: html.escape(str(value if value is not None else "—"), quote=True)
    counts = Counter(event["type"] for event in events)
    critical = sum(event["severity"] == "CRITICAL" for event in events)
    rows = "".join(
        "<tr>" + "".join(f"<td>{escape(value)}</td>" for value in (
            utc(event["timestamp"]), event["severity"], event["type"], event["src_ip"],
            event["claimed_mac"], event.get("trusted_mac"), event["mode"],
            event.get("source", "demo"), event["detail"])) + "</tr>"
        for event in events
    )
    categories = "".join(f"<li>{escape(name)} <b>{count}</b></li>" for name, count in counts.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>
body{{font-family:system-ui,sans-serif;margin:0;background:#f1f5f9;color:#122337}}
main{{max-width:1500px;margin:40px auto;background:white;padding:32px;border-radius:16px}}
h1{{font-size:30px;margin:8px 0}}.eyebrow{{color:#0f766e;letter-spacing:2px;font-size:12px;font-weight:700}}
p{{color:#526278;line-height:1.6}}.cards{{display:flex;gap:16px;margin:28px 0;flex-wrap:wrap}}
.card{{background:#eaf4f3;border-radius:12px;padding:20px;min-width:150px}}.card b{{font-size:28px;display:block}}
table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{padding:12px 9px;text-align:left;border-bottom:1px solid #dce4ee;vertical-align:top}}
th{{background:#f0f5f8}}td{{overflow-wrap:anywhere}}.scroll{{overflow:auto}}li{{padding:6px}}li b{{margin-left:12px}}
@media print{{body{{background:white}}main{{margin:0;padding:0}}table{{font-size:9px}}thead{{display:table-header-group}}tr{{break-inside:avoid}}}}
</style></head><body><main>
<div class="eyebrow">SECURE ARP / EXPORTED REPORT</div><h1>{escape(title)}</h1>
<p>Generated {utc(datetime.now(timezone.utc).timestamp())}. This snapshot includes the selected events.
Monitoring and authentication validate the application's trust table; they do not block changes to the operating system's ARP cache.</p>
<div class="cards"><div class="card"><b>{len(events)}</b>Selected events</div><div class="card"><b>{critical}</b>Critical events</div>
<div class="card"><b>{len(counts)}</b>Event categories</div></div><ul>{categories}</ul>
<div class="scroll"><table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>IP address</th><th>Claimed MAC</th>
<th>Baseline MAC</th><th>Mode</th><th>Source</th><th>Detail</th></tr></thead><tbody>
{rows or '<tr><td colspan="9">No matching events.</td></tr>'}</tbody></table></div></main></body></html>"""


def write_reports(events, directory, title="Secure ARP event report"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "events.csv").write_text(csv_text(events), encoding="utf-8-sig")
    (directory / "report.html").write_text(html_report(events, title), encoding="utf-8")
    return directory / "report.html"
