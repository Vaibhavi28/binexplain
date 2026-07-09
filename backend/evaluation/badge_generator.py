import json
from pathlib import Path

REPORT_PATH = Path("backend/evaluation/results/evaluation_report.json")
OUTPUT_PATH = Path("backend/evaluation/results/badge_summary.md")

def get_color(value: float) -> str:
    if value >= 0.90: return "brightgreen"
    if value >= 0.80: return "green"
    if value >= 0.70: return "yellow"
    if value >= 0.60: return "orange"
    return "red"

def generate():
    if not REPORT_PATH.exists():
        print("Run evaluator.py first.")
        return

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    metrics = report["metrics"]
    overall = metrics["_overall"]
    accuracy = overall["accuracy"]
    samples = overall["total_samples"]

    color = get_color(accuracy)
    acc_str = f"{accuracy*100:.1f}%25"
    badge_url = (
        f"https://img.shields.io/badge/"
        f"Detection%20Accuracy-{acc_str}-{color}?style=flat-square"
    )

    lines = [
        "## BinExplain Detection Metrics\n",
        f"![Detection Accuracy]({badge_url})\n",
        f"**Overall Accuracy: {accuracy*100:.1f}%** across {samples} labeled binaries\n",
        "### Per-Category F1 Scores\n",
        "| Category | F1 | FPR | FNR |",
        "|---|---|---|---|",
    ]

    for cat, m in sorted(metrics.items()):
        if cat.startswith("_") or m.get("support", 0) == 0:
            continue
        lines.append(
            f"| {cat} | {m['f1']*100:.1f}% | "
            f"{m['fpr']*100:.1f}% | {m['fnr']*100:.1f}% |"
        )

    lines += [
        "\n### Use This in Articles and README\n",
        f"> BinExplain's static analysis pipeline achieves "
        f"**{accuracy*100:.1f}% overall accuracy** in CTF binary exploitation "
        f"category detection across {samples} labeled binaries compiled from "
        f"shellphish/how2heap. Detection uses hybrid string pattern matching, "
        f"checksec analysis, and technique tag scoring with no dynamic execution.",
    ]

    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Badge summary saved: {OUTPUT_PATH}")
    print(f"\nOverall accuracy badge:\n{badge_url}")
    print(f"\nAccuracy: {accuracy*100:.1f}%")

if __name__ == "__main__":
    generate()
