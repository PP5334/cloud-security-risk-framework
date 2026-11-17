"""
Ablation study on the n=100 evidential batch (same batch, same seed, same
ML model as evaluate_batch.py). Reruns the correlation engine three times,
each time with exactly one of the three detection signals withheld (its
findings list replaced with an empty list before correlate() sees it),
to show what the framework's own metrics would look like if it had been
built on only two of the three signal types instead of all three.

Ground truth and the correlation-correctness definition are identical to
evaluate_batch.py's: correlation_correct means len(signals_triggered) ==
the true number of signals actually injected into that case (0-3), even
under ablation, so a case where the withheld signal was the only one
injected is correctly counted as a miss. This is deliberate: it is exactly
what "losing a signal type" should look like.
"""

from config_scanner import scan_resources
from behavioral_rules import scan_behavior
from ml_anomaly import build_baseline_dataset, extract_session_features, fit_isolation_forest, scan_ml_anomaly
from correlation_engine import correlate
from remediation_advisor import advise
from scenario_generator import generate_batch
from evaluate_batch import sessions_for_ml, rate


def run_condition(label, cases, ground_truth, n, config_findings, behavioral_findings, ml_findings):
    results = correlate(cases, config_findings, behavioral_findings, ml_findings)

    correct = 0
    escalated = 0
    for r in results:
        gt = ground_truth[r.case_id]
        triggered = set(r.signals_triggered)
        if len(triggered) == gt["count"]:
            correct += 1
        if r.severity in ("HIGH", "CRITICAL"):
            escalated += 1

    accuracy = rate(correct, n)
    print(f"{label:<28}correlation_accuracy={accuracy*100:5.1f}%   escalated={escalated}/{n}")
    return accuracy, escalated


def main(n=100, seed=7):
    batch = generate_batch(n=n, seed=seed)
    cases, ground_truth = batch["cases"], batch["ground_truth"]

    config_findings = scan_resources(batch["resource_snapshot"])
    behavioral_findings = scan_behavior(
        batch["events"],
        known_access_keys=batch["known_access_keys"],
        known_regions_by_identity=batch["known_regions_by_identity"],
    )
    baseline_matrix = build_baseline_dataset(n=200, random_state=42)
    model = fit_isolation_forest(baseline_matrix, contamination=0.1, random_state=42)
    ml_findings = scan_ml_anomaly(
        sessions_for_ml(batch["events"], batch["known_source_ips_by_identity"]), model=model,
    )

    empty = []
    print(f"Ablation on the same n={n} labeled batch used for Table II (seed={seed})\n")
    print(f"{'Condition':<28}{'Metric'}")
    print("-" * 62)

    run_condition("All 3 signals (baseline)", cases, ground_truth, n, config_findings, behavioral_findings, ml_findings)
    run_condition("config + behavioral only", cases, ground_truth, n, config_findings, behavioral_findings, empty)
    run_condition("config + ml only", cases, ground_truth, n, config_findings, empty, ml_findings)
    run_condition("behavioral + ml only", cases, ground_truth, n, empty, behavioral_findings, ml_findings)


if __name__ == "__main__":
    main()
