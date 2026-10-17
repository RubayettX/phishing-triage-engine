"""
Runs the full pipeline against the labeled benchmark dataset and reports
precision, recall, F1, and a confusion matrix.

A Gemini verdict of SUSPICIOUS or MALICIOUS counts as "flagged as phishing".
A verdict of CLEAN counts as "not flagged".

Usage:
    python run_benchmark.py
"""

import os
import time

from benchmark_dataset import all_samples
from step3_combined_report import build_report
from step4_llm_analysis import analyze_with_gemini


def run():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: Set the GEMINI_API_KEY environment variable first.")
        raise SystemExit(1)

    samples = all_samples()
    results = []

    print(f"Running benchmark on {len(samples)} labeled emails...\n")

    for i, (raw_email, true_label) in enumerate(samples, start=1):
        report = build_report(raw_email)

        try:
            verdict = analyze_with_gemini(report, api_key)
        except Exception as e:
            print(f"  [{i}/{len(samples)}] ERROR calling Gemini: {e}")
            continue

        predicted_flagged = verdict.get("verdict") in ("SUSPICIOUS", "MALICIOUS")
        true_flagged = true_label == "phishing"

        results.append({
            "true_label": true_label,
            "predicted_verdict": verdict.get("verdict"),
            "predicted_flagged": predicted_flagged,
            "true_flagged": true_flagged,
            "risk_score": verdict.get("risk_score"),
        })

        correct = "OK" if predicted_flagged == true_flagged else "WRONG"
        print(f"  [{i}/{len(samples)}] true={true_label:<9} "
              f"predicted={verdict.get('verdict'):<11} "
              f"risk={verdict.get('risk_score'):<4} [{correct}]")

        # Small delay to be polite to the API and avoid rate limits
        time.sleep(1)

    # --- Compute confusion matrix ---
    tp = sum(1 for r in results if r["true_flagged"] and r["predicted_flagged"])
    fp = sum(1 for r in results if not r["true_flagged"] and r["predicted_flagged"])
    fn = sum(1 for r in results if r["true_flagged"] and not r["predicted_flagged"])
    tn = sum(1 for r in results if not r["true_flagged"] and not r["predicted_flagged"])

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
    accuracy = (tp + tn) / len(results) if results else 0

    print("\n" + "=" * 50)
    print("BENCHMARK RESULTS")
    print("=" * 50)
    print(f"Total samples evaluated: {len(results)}")
    print(f"True Positives  (phishing correctly flagged): {tp}")
    print(f"False Positives (legit wrongly flagged):       {fp}")
    print(f"False Negatives (phishing missed):             {fn}")
    print(f"True Negatives  (legit correctly left alone):  {tn}")
    print("-" * 50)
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1 score:  {f1:.2%}")
    print(f"Accuracy:  {accuracy:.2%}")
    print("=" * 50)


if __name__ == "__main__":
    run()