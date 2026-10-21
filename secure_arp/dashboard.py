from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

from .logger_util import EventLogger
from .reports import html_report


def generate_chart(log_path="logs/events.jsonl", out_png="assets/dashboard.png", title_suffix=""):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    events = EventLogger(log_path).read_all()
    Path(out_png).parent.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    if events:
        minutes = Counter(int(event["timestamp"] // 60) * 60 for event in events)
        times = sorted(minutes)
        axes[0].bar(range(len(times)), [minutes[t] for t in times], color="#0d9488", width=0.55)
        selected = list(range(0, len(times), max(1, len(times) // 8)))
        axes[0].set_xticks(selected, [datetime.fromtimestamp(times[i], timezone.utc).strftime("%H:%M")
                                    for i in selected])
        axes[0].set_xlabel("Active minute (UTC)")
        axes[0].set_ylabel("Events per minute")
        axes[0].yaxis.set_major_locator(MaxNLocator(integer=True))
        axes[0].set_ylim(bottom=0)
        counts = Counter(event["type"].replace("_", " ").replace("-", " ") for event in events)
        axes[1].barh(list(counts), list(counts.values()), color="#0d9488")
        axes[1].set_xlabel("Events")
        axes[1].xaxis.set_major_locator(MaxNLocator(integer=True))
    else:
        for axis in axes:
            axis.text(0.5, 0.5, "No events logged", ha="center", va="center")
    axes[0].set_title(f"Event timeline {title_suffix}")
    axes[1].set_title("Event categories")
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    return str(out_png)


def generate_html(log_path="logs/events.jsonl", out_html="assets/dashboard.html"):
    target = Path(out_html)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html_report(EventLogger(log_path).read_all(), "Secure ARP demonstration"),
                      encoding="utf-8")
    return str(target)
