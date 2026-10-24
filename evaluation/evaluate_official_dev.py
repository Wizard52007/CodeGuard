import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

# Ensure the project root is importable regardless of the working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import evaluate_code


DEV_PATH = (
    Path.home()
    / "AppData"
    / "Local"
    / "Temp"
    / "opencode"
    / "hackathon_ps"
    / "ps3"
    / "Problem Statement 3"
    / "codeguard_dev.jsonl"
)

RESULTS_PATH = PROJECT_ROOT / "evaluation" / "official_dev_results.json"


def load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Official dev dataset not found: {path}")

    records = []

    with path.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on dataset line {line_number}: {exc}"
                ) from exc

            required = {"code", "language", "category", "label", "id"}
            missing = required - record.keys()

            if missing:
                raise ValueError(
                    f"Dataset line {line_number} is missing fields: "
                    f"{sorted(missing)}"
                )

            if record["label"] not in (0, 1):
                raise ValueError(
                    f"Unexpected label on dataset line {line_number}: "
                    f"{record['label']!r}"
                )

            records.append(record)

    if not records:
        raise ValueError("The official dev dataset is empty.")

    return records


def safe_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def main() -> None:
    records = load_dataset(DEV_PATH)

    results = []
    errors = []

    print(f"Dataset: {DEV_PATH}")
    print(f"Loaded {len(records)} examples.")
    print("\nRunning static analysis; submitted code will not be executed.\n")

    for index, record in enumerate(records, start=1):
        code = record["code"]
        expected = "block" if record["label"] == 1 else "allow"

        started = time.perf_counter()

        try:
            # Pass the dataset's language hint explicitly.
            # The detector analyzes code as text; it must not execute it.
            assessment = evaluate_code(
                code,
                language=record["language"],
            )

            elapsed_ms = (time.perf_counter() - started) * 1000

            actual = assessment.get("verdict")
            passed = actual == expected

            result = {
                "id": record["id"],
                "language_expected": record["language"],
                "language_detected": assessment.get("code_language"),
                "category": record["category"],
                "expected_verdict": expected,
                "actual_verdict": actual,
                "correct": passed,
                "risk_score": safe_float(assessment.get("risk_score")),
                "detected_categories": assessment.get("categories", []),
                "vulnerable_lines": assessment.get("vulnerable_lines", []),
                "reason": assessment.get("reason", ""),
                "elapsed_ms": round(elapsed_ms, 4),
                "error": None,
            }

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000

            result = {
                "id": record["id"],
                "language_expected": record["language"],
                "language_detected": None,
                "category": record["category"],
                "expected_verdict": expected,
                "actual_verdict": None,
                "correct": False,
                "risk_score": None,
                "detected_categories": [],
                "vulnerable_lines": [],
                "reason": "",
                "elapsed_ms": round(elapsed_ms, 4),
                "error": f"{type(exc).__name__}: {exc}",
            }

            errors.append(result)

        results.append(result)

        marker = "PASS" if result["correct"] else "FAIL"

        print(
            f"{marker:4} {record['id']:<28} "
            f"language={record['language']:<10} "
            f"category={record['category']:<42} "
            f"expected={expected:<5} "
            f"actual={str(result['actual_verdict']):<5} "
            f"risk={str(result['risk_score']):<6} "
            f"{result['elapsed_ms']:8.3f} ms"
        )

        if result["error"]:
            print(f"     ERROR: {result['error']}")

    # Binary classification metrics.
    tp = sum(
        r["expected_verdict"] == "block"
        and r["actual_verdict"] == "block"
        for r in results
    )
    tn = sum(
        r["expected_verdict"] == "allow"
        and r["actual_verdict"] == "allow"
        for r in results
    )
    fp = sum(
        r["expected_verdict"] == "allow"
        and r["actual_verdict"] == "block"
        for r in results
    )
    fn = sum(
        r["expected_verdict"] == "block"
        and r["actual_verdict"] == "allow"
        for r in results
    )

    total = len(results)
    correct = tp + tn

    accuracy = correct / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    false_positive_rate = (
        fp / (fp + tn) if (fp + tn) else 0.0
    )

    latencies = sorted(r["elapsed_ms"] for r in results)
    mean_latency = sum(latencies) / total if total else 0.0

    # Nearest-rank p95 latency.
    p95_index = max(0, int(0.95 * total + 0.999999) - 1)
    p95_latency = latencies[p95_index] if latencies else 0.0

    # Per-language classification metrics.
    by_language = defaultdict(list)
    for result in results:
        by_language[result["language_expected"]].append(result)

    # Per-category results. Multi-label examples contribute to every
    # category listed in their dataset record.
    by_category = defaultdict(list)
    for record, result in zip(records, results):
        categories = [
            item.strip()
            for item in record["category"].split(",")
            if item.strip()
        ]
        for category in categories:
            by_category[category].append(result)

    def summarize(group: list[dict]) -> dict:
        group_tp = sum(
            r["expected_verdict"] == "block"
            and r["actual_verdict"] == "block"
            for r in group
        )
        group_tn = sum(
            r["expected_verdict"] == "allow"
            and r["actual_verdict"] == "allow"
            for r in group
        )
        group_fp = sum(
            r["expected_verdict"] == "allow"
            and r["actual_verdict"] == "block"
            for r in group
        )
        group_fn = sum(
            r["expected_verdict"] == "block"
            and r["actual_verdict"] == "allow"
            for r in group
        )

        group_total = len(group)
        group_correct = group_tp + group_tn
        group_precision = (
            group_tp / (group_tp + group_fp)
            if group_tp + group_fp else 0.0
        )
        group_recall = (
            group_tp / (group_tp + group_fn)
            if group_tp + group_fn else 0.0
        )
        group_f1 = (
            2 * group_precision * group_recall
            / (group_precision + group_recall)
            if group_precision + group_recall else 0.0
        )

        return {
            "total": group_total,
            "correct": group_correct,
            "accuracy": group_correct / group_total if group_total else 0.0,
            "precision": group_precision,
            "recall": group_recall,
            "f1": group_f1,
            "tp": group_tp,
            "tn": group_tn,
            "fp": group_fp,
            "fn": group_fn,
        }

    summary = {
        "dataset": str(DEV_PATH),
        "total_cases": total,
        "correct": correct,
        "errors": len(errors),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
        "mean_latency_ms": mean_latency,
        "p95_latency_ms": p95_latency,
        "by_language": {
            language: summarize(group)
            for language, group in sorted(by_language.items())
        },
        "by_category": {
            category: summarize(group)
            for category, group in sorted(by_category.items())
        },
        "results": results,
    }

    RESULTS_PATH.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n" + "=" * 72)
    print("OFFICIAL PS3 DEV DATASET — SUMMARY")
    print("=" * 72)
    print(f"Examples:             {total}")
    print(f"Correct:              {correct}/{total}")
    print(f"Execution errors:     {len(errors)}")
    print(f"Accuracy:             {accuracy:.2%}")
    print(f"Precision:            {precision:.2%}")
    print(f"Recall:               {recall:.2%}")
    print(f"F1 score:             {f1:.2%}")
    print(f"False positive rate:  {false_positive_rate:.2%}")
    print(f"TP / TN / FP / FN:    {tp} / {tn} / {fp} / {fn}")
    print(f"Mean latency:         {mean_latency:.3f} ms")
    print(f"P95 latency:          {p95_latency:.3f} ms")

    print("\nBY LANGUAGE")
    for language, metrics in sorted(summary["by_language"].items()):
        print(
            f"{language:<12} "
            f"{metrics['correct']:>2}/{metrics['total']:<2} "
            f"accuracy={metrics['accuracy']:.1%} "
            f"precision={metrics['precision']:.1%} "
            f"recall={metrics['recall']:.1%}"
        )

    print("\nBY CATEGORY")
    for category, metrics in sorted(summary["by_category"].items()):
        print(
            f"{category:<28} "
            f"{metrics['correct']:>2}/{metrics['total']:<2} "
            f"accuracy={metrics['accuracy']:.1%} "
            f"recall={metrics['recall']:.1%}"
        )

    print(f"\nDetailed results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()