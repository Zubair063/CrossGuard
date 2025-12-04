#!/usr/bin/env python3
"""
Evaluate LLM attack annotations against ground-truth CSV files.

This script compares:
  - Ground truth CSV: function_name + true attack labels
  - LLM output CSV:   function_name + predicted attack labels

and reports:
  - Overall accuracy
  - Per-class precision / recall / F1
  - Confusion matrix

Expected formats
----------------

Ground-truth CSV (one of):
  - function_name,attack_type,language,label
  - function_name,attack_type,language
  - function_name,attack_type

Where:
  - attack_type: either a number 0–5, or a descriptive string
  - label: numeric label 0–5 (if present, this is preferred)

LLM output CSV (from llm_attack_annotator.py):
  - function_name,attack_type
    (attack_type is numeric 0–5)
"""

import argparse
import csv
import os
from collections import Counter, defaultdict
from typing import Dict, Tuple, List, Optional


# Mapping textual descriptions to numeric labels, if needed
ATTACK_TEXT_TO_LABEL = {
    "rust bounds check bypass attack": 1,
    "rust bounds check bypass": 1,
    "bounds check bypass": 1,
    "rust lifetime bypass attack": 2,
    "rust lifetime bypass": 2,
    "lifetime bypass": 2,
    "uaf": 2,
    "use-after-free": 2,
    "double-free": 2,
    "hardening bypass via stack overflow": 3,
    "hardening bypass": 3,
    "c/c++ hardening bypass": 3,
    "dynamic bounds corruption (vec metadata)": 4,
    "dynamic bounds corruption": 4,
    "vec metadata": 4,
    "intended interaction corruption": 5,
    "callback poisoning": 5,
}


def normalize_attack_label(raw: str) -> Optional[int]:
    """
    Convert a raw attack_type string to an integer label 0–5.
    Returns None if it can't be parsed.
    """
    raw = (raw or "").strip()
    if raw == "":
        return None

    # Try numeric directly
    try:
        v = int(raw)
        if 0 <= v <= 5:
            return v
    except ValueError:
        pass

    # Fallback: textual mapping
    key = raw.lower()
    key = key.replace("attack", "").strip()
    if key in ATTACK_TEXT_TO_LABEL:
        return ATTACK_TEXT_TO_LABEL[key]

    # Heuristic matching on keywords
    if "bounds" in key:
        return 1
    if "lifetime" in key or "uaf" in key or "use-after" in key or "double-free" in key:
        return 2
    if "hardening" in key or "shadow" in key or "cfi" in key or "stack" in key:
        return 3
    if "dynamic" in key or "vec" in key or "metadata" in key:
        return 4
    if "intended" in key or "callback" in key or "poison" in key:
        return 5

    # If nothing matches, treat as safe (0)
    return 0


def load_ground_truth(path: str) -> Dict[str, int]:
    """
    Load ground truth labels: function_name -> true_label (0–5).
    Prefers 'label' column if present; otherwise parses from 'attack_type'.
    """
    gt: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fn = (row.get("function_name") or "").strip()
            if not fn:
                continue

            # Prefer explicit numeric label column if present
            label_raw = row.get("label")
            attack_raw = row.get("attack_type")

            label = None
            if label_raw is not None and label_raw.strip() != "":
                try:
                    v = int(label_raw.strip())
                    if 0 <= v <= 5:
                        label = v
                except ValueError:
                    pass

            if label is None:
                label = normalize_attack_label(attack_raw or "")

            gt[fn] = label
    return gt


def load_predictions(path: str) -> Dict[str, int]:
    """
    Load LLM predictions: function_name -> pred_label (0–5).
    """
    preds: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fn = (row.get("function_name") or "").strip()
            if not fn:
                continue
            raw = (row.get("attack_type") or "").strip()
            label = normalize_attack_label(raw)
            if label is None:
                continue
            preds[fn] = label
    return preds


def confusion_counts(
    gt: Dict[str, int], preds: Dict[str, int]
) -> Tuple[Dict[Tuple[int, int], int], int]:
    """
    Build confusion matrix counts and return (counts, n_matched).

    This assumes that gt and preds have already been restricted to
    the **overlapping subset** of function names (i.e., keys match).
    """
    counts: Dict[Tuple[int, int], int] = Counter()
    for fn, true_label in gt.items():
        pred_label = preds[fn]
        counts[(true_label, pred_label)] += 1
    return counts, len(gt)


def compute_metrics(
    counts: Dict[Tuple[int, int], int], n_total: int
) -> Tuple[Dict[int, Dict[str, float]], float]:
    """
    Compute per-class precision/recall/F1 and overall accuracy.
    """
    labels = list(range(0, 6))
    metrics: Dict[int, Dict[str, float]] = {}

    # Overall accuracy
    correct = sum(counts.get((k, k), 0) for k in labels)
    accuracy = correct / n_total if n_total > 0 else 0.0

    # Per-class metrics
    for c in labels:
        tp = counts.get((c, c), 0)
        fp = sum(counts.get((t, p), 0) for (t, p) in counts if p == c and t != c)
        fn = sum(counts.get((t, p), 0) for (t, p) in counts if t == c and p != c)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if prec + rec > 0:
            f1 = 2 * prec * rec / (prec + rec)
        else:
            f1 = 0.0

        metrics[c] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": prec,
            "recall": rec,
            "f1": f1,
        }

    return metrics, accuracy


def print_confusion_matrix(counts: Dict[Tuple[int, int], int]) -> None:
    labels = list(range(0, 6))
    header = "true\\pred".ljust(10) + "".join(f"{c:>8}" for c in labels)
    print("\nConfusion Matrix (rows=true, cols=pred):")
    print(header)
    for t in labels:
        row = f"{t}".ljust(10)
        for p in labels:
            row += f"{counts.get((t, p), 0):>8}"
        print(row)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Evaluate LLM attack annotations against ground truth CSV, "
            "restricted to only the functions that have predictions."
        )
    )
    ap.add_argument(
        "--ground-truth",
        required=True,
        help="Path to ground truth CSV (e.g., ground_truth_attacks.csv)",
    )
    ap.add_argument(
        "--predictions",
        required=True,
        help="Path to LLM predictions CSV (e.g., llm_output/all_attacks_annotations.csv)",
    )
    ap.add_argument(
        "--save-subset",
        default=None,
        help="Optional path to save the filtered ground truth subset used for evaluation.",
    )
    args = ap.parse_args()

    if not os.path.exists(args.ground_truth):
        print(f"Error: ground truth file not found: {args.ground_truth}")
        return 1
    if not os.path.exists(args.predictions):
        print(f"Error: predictions file not found: {args.predictions}")
        return 1

    print(f"Loading ground truth: {args.ground_truth}")
    gt_full = load_ground_truth(args.ground_truth)
    print(f"  Loaded {len(gt_full)} functions from ground truth.")

    print(f"Loading predictions: {args.predictions}")
    preds_full = load_predictions(args.predictions)
    print(f"  Loaded {len(preds_full)} functions with predictions.")

    # Restrict evaluation to overlapping function names
    common_funcs = sorted(set(gt_full.keys()) & set(preds_full.keys()))
    print(f"\nFunctions in both predictions and ground truth: {len(common_funcs)}")

    if not common_funcs:
        print("No overlapping functions between predictions and ground truth. Nothing to evaluate.")
        return 0

    gt = {fn: gt_full[fn] for fn in common_funcs}
    preds = {fn: preds_full[fn] for fn in common_funcs}

    # Optionally save the ground-truth subset used for evaluation
    if args.save_subset:
        print(f"Saving ground truth subset to: {args.save_subset}")
        with open(args.ground_truth, "r", encoding="utf-8") as f_in, open(
            args.save_subset, "w", encoding="utf-8", newline=""
        ) as f_out:
            reader = csv.DictReader(f_in)
            fieldnames = reader.fieldnames
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            kept = 0
            for row in reader:
                fn = (row.get("function_name") or "").strip()
                if fn in common_funcs:
                    writer.writerow(row)
                    kept += 1
        print(f"  Wrote {kept} rows to {args.save_subset}")

    counts, n_total = confusion_counts(gt, preds)
    metrics, accuracy = compute_metrics(counts, n_total)

    print("\n==================== EVALUATION SUMMARY ====================")
    print(f"Total functions evaluated (overlap subset): {n_total}")
    print(f"Overall accuracy: {accuracy*100:.2f}%")

    print("\nPer-class metrics (label: 0=Safe, 1–5=attacks):")
    for c in sorted(metrics.keys()):
        m = metrics[c]
        print(
            f"  Class {c}: "
            f"TP={m['tp']}, FP={m['fp']}, FN={m['fn']}, "
            f"Prec={m['precision']:.3f}, Rec={m['recall']:.3f}, F1={m['f1']:.3f}"
        )

    print_confusion_matrix(counts)
    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



