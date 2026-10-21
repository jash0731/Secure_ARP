from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def generate():
    figure, axis = plt.subplots(figsize=(14, 7.5))
    figure.patch.set_facecolor("#0c1119")
    axis.set_facecolor("#0c1119")
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1)
    axis.axis("off")
    axis.text(.055, .93, "SECURE ARP", color="#70e0c1", fontsize=12, weight="bold", va="top")
    axis.text(.055, .87, "From observation to a reviewed trust table", color="#e1e9f0", fontsize=23, va="top")
    axis.text(.055, .79, "Version 2.0 architecture", color="#8499ae", fontsize=11, va="top")

    def box(x, y, w, h, title, body):
        axis.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.015",
                                      linewidth=1, edgecolor="#304152", facecolor="#121e2b"))
        axis.text(x + .019, y + h - .04, title, color="#70e0c1", fontsize=13, weight="bold", va="top")
        axis.text(x + .019, y + h - .103, body, color="#c2ceda", fontsize=11, va="top", linespacing=1.8)

    def arrow(start, end, connection="arc3,rad=0"):
        axis.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=15,
                                      linewidth=1.5, color="#6a908f", connectionstyle=connection))

    box(.055, .40, .23, .28, "1  Observe", "Passive live ARP capture\nSaved PCAP / PCAPNG\nIn-memory demonstration")
    box(.37, .40, .25, .28, "2  Validate", "Ethernet / ARP parsing\nHMAC + nonce + replay\nBinding conflicts + reply rate")
    box(.705, .43, .24, .25, "3  Save", "SQLite events & devices\nPersistent approved mappings\nJSON-lines event log")
    box(.705, .095, .24, .23, "4  Review", "Local live dashboard\nFilters & device approvals\nCSV / HTML exports")
    arrow((.30, .54), (.35, .54))
    arrow((.635, .54), (.687, .54))
    arrow((.825, .408), (.825, .34))
    arrow((.69, .20), (.52, .382), "arc3,rad=-0.3")
    axis.text(.54, .225, "Approved changes", color="#8da7b8", fontsize=9, rotation=-17)
    box(.055, .095, .395, .21, "Scope", "Validates the application's trust table.\nDoes not block operating-system ARP changes.")
    axis.text(.055, .02, "One workspace per local IP namespace. Demo and live data remain separate.",
              color="#778ca0", fontsize=10)
    output = Path(__file__).resolve().parents[1] / "assets" / "architecture.png"
    figure.savefig(output, dpi=160, bbox_inches="tight", facecolor=figure.get_facecolor())
    plt.close(figure)
    print(output)


if __name__ == "__main__":
    generate()
