"""
Wall-clock timing of the pipeline on the same n=100 batch used elsewhere,
split into a one-time setup cost (building the synthetic ML baseline and
fitting the Isolation Forest, which happens once at startup, not per
scan) and the per-case processing cost (config scan, behavioral scan, ML
feature extraction + scoring with the already-fitted model, correlation,
and remediation advice for all 100 cases).

The per-case figure is measured over multiple repeated passes over the
same batch and reported as a mean, since a single wall-clock run is noisy
on its own; this is a measurement of this implementation on this machine,
not a formal complexity claim.
"""

import time

from config_scanner import scan_resources
from behavioral_rules import scan_behavior
from ml_anomaly import build_baseline_dataset, extract_session_features, fit_isolation_forest, scan_ml_anomaly
from correlation_engine import correlate
from remediation_advisor import advise
from scenario_generator import generate_batch
from evaluate_batch import sessions_for_ml


def time_setup(repeats=5):
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        baseline_matrix = build_baseline_dataset(n=200, random_state=42)
        fit_isolation_forest(baseline_matrix, contamination=0.1, random_state=42)
        times.append(time.perf_counter() - t0)
    return times


def time_pipeline(batch, model, repeats=20):
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()

        config_findings = scan_resources(batch["resource_snapshot"])
        behavioral_findings = scan_behavior(
            batch["events"],
            known_access_keys=batch["known_access_keys"],
            known_regions_by_identity=batch["known_regions_by_identity"],
        )
        ml_findings = scan_ml_anomaly(
            sessions_for_ml(batch["events"], batch["known_source_ips_by_identity"]), model=model,
        )
        results = correlate(batch["cases"], config_findings, behavioral_findings, ml_findings)
        for r in results:
            advise(r)

        times.append(time.perf_counter() - t0)
    return times


def main(n=100, seed=7):
    batch = generate_batch(n=n, seed=seed)
    baseline_matrix = build_baseline_dataset(n=200, random_state=42)
    model = fit_isolation_forest(baseline_matrix, contamination=0.1, random_state=42)

    setup_times = time_setup()
    pipeline_times = time_pipeline(batch, model)

    mean_setup = sum(setup_times) / len(setup_times)
    mean_pipeline = sum(pipeline_times) / len(pipeline_times)
    min_pipeline = min(pipeline_times)

    print(f"One-time ML baseline build + Isolation Forest fit, mean over {len(setup_times)} runs:")
    print(f"  {mean_setup*1000:.1f} ms (happens once at startup, not per scan)\n")

    print(f"Full pipeline over n={n} cases (config + behavioral + ML scan, correlation, advisory),")
    print(f"mean over {len(pipeline_times)} runs:")
    print(f"  total:      {mean_pipeline*1000:.1f} ms  (min observed: {min_pipeline*1000:.1f} ms)")
    print(f"  per case:   {mean_pipeline*1000/n:.2f} ms")
    print(f"  throughput: {n/mean_pipeline:.0f} cases/sec")


if __name__ == "__main__":
    main()
