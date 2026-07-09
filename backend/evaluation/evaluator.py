import os
import sys
import json
import csv
import subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

LABEL_FILE = Path(__file__).parent / "ground_truth/labels.json"
BINARY_DIR = Path(__file__).parent / "ground_truth/binaries"
RESULTS_DIR = Path(__file__).parent / "results"

def load_labels() -> dict:
    if not LABEL_FILE.exists():
        raise FileNotFoundError(
            "Labels not found. Run ground_truth_builder.py first."
        )
    return json.loads(LABEL_FILE.read_text(encoding="utf-8"))

def analyze_binary_category(binary_path: Path) -> str:
    """
    Run BinExplain's actual category detection on a binary.
    Uses the real static analysis pipeline from main.py.
    Returns the detected category string.
    """
    try:
        import main as binexplain_main

        # Read binary bytes
        binary_bytes = binary_path.read_bytes()

        # Extract strings
        result = subprocess.run(
            ["strings", str(binary_path)],
            capture_output=True, text=True, timeout=10
        )
        strings_list = []
        if result.returncode == 0:
            strings_list = [s.strip() for s in result.stdout.split("\n")
                           if len(s.strip()) > 3]

        # Run checksec if available
        checksec = {}
        try:
            checksec_result = subprocess.run(
                ["checksec", "--file=" + str(binary_path), "--output=json"],
                capture_output=True, text=True, timeout=10
            )
            if checksec_result.returncode == 0:
                import json as _json
                checksec_data = _json.loads(checksec_result.stdout)
                if str(binary_path) in checksec_data:
                    checksec = checksec_data[str(binary_path)]
        except Exception:
            pass

        # Extract patterns
        patterns = {}
        if hasattr(binexplain_main, 'detect_patterns'):
            patterns = binexplain_main.detect_patterns(strings_list)

        # Extract format string vulnerabilities
        format_string_result = {}
        if hasattr(binexplain_main, 'detect_format_string'):
            format_string_result = binexplain_main.detect_format_string(strings_list, patterns)

        # Find ROP gadgets
        rop_gadgets = []
        if hasattr(binexplain_main, 'find_rop_gadgets'):
            rop_gadgets = binexplain_main.find_rop_gadgets(binary_bytes)

        # Call the actual detection function from main.py
        detect_fn = getattr(binexplain_main, 'detect_ctf_category', None)
        if detect_fn is None:
            # Try alternative names
            for name in ['get_ctf_category', 'classify_binary',
                        'detect_category', 'analyze_ctf_category']:
                detect_fn = getattr(binexplain_main, name, None)
                if detect_fn is not None:
                    break

        if detect_fn is None:
            print(f"[Evaluator] Cannot find category detection function in main.py")
            return "unknown"

        # Call with appropriate parameters
        try:
            result = detect_fn(
                patterns=patterns,
                checksec=checksec,
                strings=strings_list,
                format_string_result=format_string_result,
                rop_gadgets=rop_gadgets
            )
        except TypeError:
            try:
                result = detect_fn(patterns, checksec, strings_list, format_string_result, rop_gadgets)
            except TypeError:
                try:
                    result = detect_fn(strings_list, checksec)
                except Exception as e:
                    print(f"[Evaluator] Function call failed: {e}")
                    return "unknown"

        # Extract category from result
        if isinstance(result, dict):
            return result.get("category", result.get("ctf_category", "unknown"))
        if isinstance(result, str):
            return result
        return "unknown"

    except Exception as e:
        print(f"[Evaluator] Error analyzing {binary_path.name}: {e}")
        return "unknown"

def compute_metrics(true_labels, predicted_labels, categories):
    metrics = {}
    total_correct = sum(1 for t, p in zip(true_labels, predicted_labels) if t == p)
    total = len(true_labels)

    for category in categories:
        tp = sum(1 for t, p in zip(true_labels, predicted_labels)
                 if t == category and p == category)
        fp = sum(1 for t, p in zip(true_labels, predicted_labels)
                 if t != category and p == category)
        fn = sum(1 for t, p in zip(true_labels, predicted_labels)
                 if t == category and p != category)
        tn = sum(1 for t, p in zip(true_labels, predicted_labels)
                 if t != category and p != category)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        support = sum(1 for t in true_labels if t == category)

        metrics[category] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "f1": round(f1, 4),
            "support": support,
        }

    metrics["_overall"] = {
        "accuracy": round(total_correct / total, 4) if total > 0 else 0.0,
        "total_samples": total,
        "total_correct": total_correct,
    }
    return metrics

def save_markdown_report(metrics, sample_details, categories):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    overall = metrics["_overall"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# BinExplain Category Detection Evaluation",
        f"\n**Generated:** {timestamp}",
        f"**Total Samples:** {overall['total_samples']}",
        f"**Overall Accuracy:** {overall['accuracy']*100:.1f}%",
        f"**Correct:** {overall['total_correct']}/{overall['total_samples']}",
        "\n---\n",
        "## Per-Category Metrics\n",
        "| Category | Precision | Recall | FPR | FNR | F1 | Support |",
        "|---|---|---|---|---|---|---|",
    ]

    for cat in sorted(categories):
        if cat not in metrics or metrics[cat]["support"] == 0:
            continue
        m = metrics[cat]
        lines.append(
            f"| {cat} | {m['precision']*100:.1f}% | "
            f"{m['recall']*100:.1f}% | {m['fpr']*100:.1f}% | "
            f"{m['fnr']*100:.1f}% | {m['f1']*100:.1f}% | {m['support']} |"
        )

    lines += [
        "\n---\n",
        "## Sample Results\n",
        "| Binary | True Category | Predicted | Result |",
        "|---|---|---|---|",
    ]
    for s in sample_details:
        result = "✅" if s["correct"] else "❌"
        lines.append(
            f"| {s['binary']} | {s['true_category']} | "
            f"{s['predicted_category']} | {result} |"
        )

    lines += [
        "\n---\n",
        "## Methodology",
        "- Ground truth from shellphish/how2heap (filename = category label)",
        "- Binaries compiled with gcc, standard CTF flags",
        "- Detection uses BinExplain static analysis (no dynamic execution)",
        "- Evaluation: `backend/evaluation/evaluator.py`",
    ]

    md_path = RESULTS_DIR / "evaluation_report.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[Evaluator] Report: {md_path}")
    return md_path

def get_base_category(cat: str) -> str:
    heap_subcategories = {
        "tcache_poisoning", "house_of_spirit", "fastbin_dup",
        "house_of_force", "house_of_orange", "unsorted_bin_attack",
        "use_after_free", "off_by_one", "heap_exploitation",
        "stack_canary_bypass"
    }
    if cat in heap_subcategories:
        return "heap_exploitation"
    return cat

def run_evaluation():
    print("[Evaluator] BinExplain Category Detection Evaluation")
    print("=" * 60)

    labels = load_labels()
    print(f"[Evaluator] {len(labels)} labeled binaries")

    categories = list(set(get_base_category(v["true_category"]) for v in labels.values()))
    true_labels, predicted_labels, sample_details = [], [], []

    for binary_name, label_info in labels.items():
        binary_path = BINARY_DIR / binary_name
        if not binary_path.exists():
            print(f"[Evaluator] Binary missing: {binary_name}")
            continue

        true_cat = get_base_category(label_info["true_category"])
        print(f"[Evaluator] {binary_name} (true: {true_cat})...")

        raw_predicted = analyze_binary_category(binary_path)
        predicted_cat = get_base_category(raw_predicted)
        correct = predicted_cat == true_cat
        mark = "✓" if correct else "✗"
        print(f"  -> {predicted_cat} {mark} (raw: {raw_predicted})")

        true_labels.append(true_cat)
        predicted_labels.append(predicted_cat)
        sample_details.append({
            "binary": binary_name,
            "true_category": true_cat,
            "predicted_category": predicted_cat,
            "correct": correct,
        })

    metrics = compute_metrics(true_labels, predicted_labels, categories)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "evaluation_report.json").write_text(
        json.dumps({"metrics": metrics, "samples": sample_details}, indent=2),
        encoding="utf-8"
    )

    save_markdown_report(metrics, sample_details, categories)

    overall = metrics["_overall"]
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Overall Accuracy: {overall['accuracy']*100:.1f}%")
    print(f"Correct: {overall['total_correct']}/{overall['total_samples']}")
    print()
    print(f"{'Category':<25} {'F1':>6} {'FPR':>6} {'FNR':>6} {'N':>5}")
    print("-" * 50)
    for cat in sorted(categories):
        if cat not in metrics or metrics[cat]["support"] == 0:
            continue
        m = metrics[cat]
        print(f"{cat:<25} {m['f1']*100:>5.1f}% "
              f"{m['fpr']*100:>5.1f}% "
              f"{m['fnr']*100:>5.1f}% "
              f"{m['support']:>5}")

    return metrics

if __name__ == "__main__":
    run_evaluation()
