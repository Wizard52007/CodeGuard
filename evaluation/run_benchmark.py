"""Run CodeGuard's static detector against a labelled JSON benchmark.

The submitted snippets are analyzed as strings. This script never executes them.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "evaluation" / "benchmark.json"
RESULTS_PATH = ROOT / "evaluation" / "results.json"

sys.path.insert(0, str(ROOT))

from src.detector import evaluate_code  # noqa: E402


def safe_rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    results: list[dict[str, Any]] = []
    counts = defaultdict(int)
    category_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    total_seconds = 0.0

    for case in dataset:
        started = time.perf_counter()

        try:
            # Pass the source as text; never execute or import the submitted code.
            assessment = evaluate_code(case["code"], language=case["language"])
            actual = assessment["verdict"]
            elapsed = time.perf_counter() - started
            error = None
        except Exception as exc:
            elapsed = time.perf_counter() - started
            actual = "error"
            assessment = {}
            error = f"{type(exc).__name__}: {exc}"

        total_seconds += elapsed
        expected = case["expected"]
        category = case["category"]

        if actual == "error":
            outcome = "ERROR"
            counts["errors"] += 1
            category_counts[category]["errors"] += 1
        elif expected == "block" and actual == "block":
            outcome = "TP"
            counts["tp"] += 1
            category_counts[category]["tp"] += 1
        elif expected == "allow" and actual == "allow":
            outcome = "TN"
            counts["tn"] += 1
            category_counts[category]["tn"] += 1
        elif expected == "block" and actual == "allow":
            outcome = "FN"
            counts["fn"] += 1
            category_counts[category]["fn"] += 1
        else:
            outcome = "FP"
            counts["fp"] += 1
            category_counts[category]["fp"] += 1

        result = {
            "id": case["id"],
            "category": category,
            "expected": expected,
            "actual": actual,
            "outcome": outcome,
            "risk_score": assessment.get("risk_score"),
            "detected_categories": assessment.get("categories", []),
            "code_language": assessment.get("code_language"),
            "elapsed_ms": round(elapsed * 1000, 3),
            "error": error,
        }
        results.append(result)

        print(
            f'{case["id"]:5} {category:25} '
            f'expected={expected:5} actual={actual:5} '
            f'{outcome:5} {elapsed * 1000:8.3f} ms'
        )

    total = len(dataset)
    tp, tn = counts["tp"], counts["tn"]
    fp, fn = counts["fp"], counts["fn"]
    errors = counts["errors"]

    # Errors are reported separately and excluded from the metric denominators.
    evaluated = tp + tn + fp + fn
    metrics = {
        "total_cases": total,
        "evaluated_cases": evaluated,
        "errors": errors,
        "accuracy": safe_rate(tp + tn, evaluated),
        "precision": safe_rate(tp, tp + fp),
        "recall": safe_rate(tp, tp + fn),
        "false_positive_rate": safe_rate(fp, fp + tn),
        "mean_latency_ms": safe_rate(total_seconds * 1000, total),
        "total_latency_ms": round(total_seconds * 1000, 3),
    }

    by_category: dict[str, dict[str, Any]] = {}
    for category, values in sorted(category_counts.items()):
        ctp, ctn = values["tp"], values["tn"]
        cfp, cfn = values["fp"], values["fn"]
        category_total = ctp + ctn + cfp + cfn
        by_category[category] = {
            "tp": ctp,
            "tn": ctn,
            "fp": cfp,
            "fn": cfn,
            "errors": values["errors"],
            "precision": safe_rate(ctp, ctp + cfp),
            "recall": safe_rate(ctp, ctp + cfn),
            "accuracy": safe_rate(ctp + ctn, category_total),
        }

    report = {
        "metrics": metrics,
        "by_category": by_category,
        "cases": results,
    }

    RESULTS_PATH.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("\n=== OVERALL METRICS ===")
    for name, value in metrics.items():
        if isinstance(value, float) and name not in {
            "mean_latency_ms",
            "total_latency_ms",
        }:
            print(f"{name:22}: {value:.1%}")
        else:
            print(f"{name:22}: {value}")

    print("\n=== CATEGORY METRICS ===")
    for category, values in by_category.items():
        print(
            f"{category:25} "
            f"precision={values['precision']:.1%} "
            f"recall={values['recall']:.1%} "
            f"FP={values['fp']} FN={values['fn']} "
            f"errors={values['errors']}"
        )

    print(f"\nDetailed results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()