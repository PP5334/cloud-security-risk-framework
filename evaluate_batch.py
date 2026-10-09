"""
Runs the full pipeline (config scanner, behavioral rules, ML anomaly
scorer, correlation engine) over the n=100 labeled synthetic batch and
scores the output against ground truth. This is the evidential basis
for the Results-section numbers; the 4 cases in run_scenarios.py remain
illustrative only and are not re-used as evidence here.
"""

from config_scanner import scan_resources
from behavioral_rules import scan_behavior
from ml_anomaly import build_baseline_dataset, extract_session_features, fit_isolation_forest, scan_ml_anomaly
from correlation_engine import correlate
from remediation_advisor import advise
from scenario_generator import generate_batch


def sessions_for_ml(events, known_source_ips_by_identity):
    by_identity = {}
    for event in events:
        by_identity.setdefault(event["identity"], []).append(event)

    sessions = []
    for identity, identity_events in by_identity.items():
        known_ips = known_source_ips_by_identity.get(identity, set())
        features = extract_session_features(identity, identity_events, known_ips)
        if features:
            sessions.append(features)
    return sessions


def rate(numerator, denominator):
    return (numerator / denominator) if denominator else float("nan")


def evaluate(n=100, seed=7):
    batch = generate_batch(n=n, seed=seed)

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

    results = correlate(batch["cases"], config_findings, behavioral_findings, ml_findings)

    counts = {
        "config_tp": 0, "config_fn": 0, "config_fp": 0, "config_tn": 0,
        "behavioral_tp": 0, "behavioral_fn": 0, "behavioral_fp": 0, "behavioral_tn": 0,
        "ml_tp": 0, "ml_fn": 0, "ml_fp": 0, "ml_tn": 0,
        "correlation_correct": 0,
        "escalated_cases": 0, "auto_remediated_actions": 0, "human_approval_actions": 0,
    }

    per_case_rows = []
    for r in results:
        gt = batch["ground_truth"][r.case_id]
        triggered = set(r.signals_triggered)

        for signal, gt_key in (("config", "config"), ("behavioral", "behavioral"), ("ml_anomaly", "ml")):
            was_injected = gt[gt_key]
            was_triggered = signal in triggered
            prefix = "ml" if gt_key == "ml" else gt_key
            if was_injected and was_triggered:
                counts[f"{prefix}_tp"] += 1
            elif was_injected and not was_triggered:
                counts[f"{prefix}_fn"] += 1
            elif not was_injected and was_triggered:
                counts[f"{prefix}_fp"] += 1
            else:
                counts[f"{prefix}_tn"] += 1

        correlation_correct = len(triggered) == gt["count"]
        counts["correlation_correct"] += int(correlation_correct)

        actions = advise(r)
        if r.severity in ("HIGH", "CRITICAL"):
            counts["escalated_cases"] += 1
        for a in actions:
            if a.mode == "auto_remediated":
                counts["auto_remediated_actions"] += 1
            else:
                counts["human_approval_actions"] += 1

        per_case_rows.append({
            "case_id": r.case_id, "ground_truth_count": gt["count"], "triggered_count": len(triggered),
            "severity": r.severity, "correlation_correct": correlation_correct,
        })

    metrics = {
        "config_detection_rate": rate(counts["config_tp"], counts["config_tp"] + counts["config_fn"]),
        "config_false_positive_rate": rate(counts["config_fp"], counts["config_fp"] + counts["config_tn"]),
        "behavioral_detection_rate": rate(counts["behavioral_tp"], counts["behavioral_tp"] + counts["behavioral_fn"]),
        "behavioral_false_positive_rate": rate(counts["behavioral_fp"], counts["behavioral_fp"] + counts["behavioral_tn"]),
        "ml_detection_rate": rate(counts["ml_tp"], counts["ml_tp"] + counts["ml_fn"]),
        "ml_false_positive_rate": rate(counts["ml_fp"], counts["ml_fp"] + counts["ml_tn"]),
        "correlation_accuracy": rate(counts["correlation_correct"], n),
    }

    return metrics, counts, per_case_rows


def print_report(n=100, seed=7):
    metrics, counts, rows = evaluate(n=n, seed=seed)

    print(f"Evaluation batch: n={n} labeled synthetic cases (stratified 25/25/25/25 across 0-3 injected signals)\n")
    print(f"{'Metric':<32}{'Value'}")
    print("-" * 50)
    for name, value in metrics.items():
        print(f"{name:<32}{value * 100:.1f}%")

    print("\nRaw confusion counts:")
    for key in ("config", "behavioral", "ml"):
        print(f"  {key}: TP={counts[f'{key}_tp']} FN={counts[f'{key}_fn']} FP={counts[f'{key}_fp']} TN={counts[f'{key}_tn']}")
    print(f"  correlation_correct = {counts['correlation_correct']} / {n}")

    print("\nRemediation advisor:")
    print(f"  escalated cases (HIGH/CRITICAL, acted on) = {counts['escalated_cases']} / {n}")
    print(f"  auto-remediated config actions = {counts['auto_remediated_actions']}")
    print(f"  human-approval recommendations = {counts['human_approval_actions']}")

    return metrics, counts, rows


if __name__ == "__main__":
    print_report()
