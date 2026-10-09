"""
Cross-domain component — lightweight, unsupervised ML anomaly scorer.

Isolation Forest over CloudTrail activity features. Deliberately
independent of behavioral_rules.py: this is an additional, distinct
signal, not a replacement for the rule-based detector. No labeled
dataset or train/test split — the model learns "normal" from a
synthetic baseline of ordinary sessions, then scores new sessions
against it, which is what unsupervised anomaly detection is for.

Features per session: api_call_frequency, time_of_day, source_ip_novelty,
distinct_actions_per_session.
"""

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = (
    "api_call_frequency",
    "time_of_day",
    "source_ip_novelty",
    "distinct_actions_per_session",
)


@dataclass
class MlFinding:
    identity: str
    issue: str
    detail: str
    anomaly_score: float


def extract_session_features(identity, events, known_source_ips):
    """
    events: CloudTrail-shaped events for one identity/session, each with
            event_time, event_name, source_ip.
    known_source_ips: set of source IPs already seen for this identity
                       before this session (the baseline).
    """
    if not events:
        return None

    duration_minutes = max(
        (max(e["event_time"] for e in events) - min(e["event_time"] for e in events)).total_seconds() / 60,
        1.0,
    )
    api_call_frequency = len(events) / duration_minutes

    hours = [e["event_time"].hour for e in events]
    time_of_day = sum(hours) / len(hours)

    session_ips = {e.get("source_ip") for e in events if e.get("source_ip")}
    new_ips = session_ips - known_source_ips
    source_ip_novelty = len(new_ips) / max(len(session_ips), 1)

    distinct_actions_per_session = len({e["event_name"] for e in events})

    return {
        "identity": identity,
        "api_call_frequency": api_call_frequency,
        "time_of_day": time_of_day,
        "source_ip_novelty": source_ip_novelty,
        "distinct_actions_per_session": distinct_actions_per_session,
    }


def build_baseline_dataset(n=200, random_state=42):
    """
    Synthetic baseline of ordinary working-hours sessions, used only to
    give Isolation Forest a notion of "normal" to learn from. Illustrative,
    not a labeled ground-truth dataset — consistent with the checklist's
    proof-of-concept framing for this component.
    """
    rng = np.random.default_rng(random_state)
    api_call_frequency = rng.normal(loc=4.0, scale=1.5, size=n).clip(min=0.1)
    time_of_day = rng.normal(loc=14.0, scale=3.0, size=n).clip(min=0, max=23.99)
    source_ip_novelty = rng.beta(a=1, b=12, size=n)
    distinct_actions_per_session = rng.normal(loc=3.0, scale=1.2, size=n).clip(min=1).round()

    return np.column_stack([
        api_call_frequency, time_of_day, source_ip_novelty, distinct_actions_per_session,
    ])


def fit_isolation_forest(baseline_matrix, contamination=0.05, random_state=42):
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(baseline_matrix)
    return model


def _to_matrix(session_features_list):
    return np.array([[sf[name] for name in FEATURE_NAMES] for sf in session_features_list])


def scan_ml_anomaly(session_features_list, model=None, baseline_matrix=None):
    """
    session_features_list: list of dicts from extract_session_features().
    Returns one MlFinding per session flagged as an anomaly (predict() == -1).
    """
    if not session_features_list:
        return []

    if model is None:
        baseline_matrix = baseline_matrix if baseline_matrix is not None else build_baseline_dataset()
        model = fit_isolation_forest(baseline_matrix)

    matrix = _to_matrix(session_features_list)
    predictions = model.predict(matrix)
    scores = model.decision_function(matrix)

    findings = []
    for sf, prediction, score in zip(session_features_list, predictions, scores):
        if prediction == -1:
            findings.append(MlFinding(
                identity=sf["identity"],
                issue="ml_anomaly",
                detail=(
                    f"Isolation Forest flagged session as anomalous "
                    f"(score={score:.3f}; freq={sf['api_call_frequency']:.1f}/min, "
                    f"hour={sf['time_of_day']:.1f}, "
                    f"ip_novelty={sf['source_ip_novelty']:.2f}, "
                    f"distinct_actions={sf['distinct_actions_per_session']:.0f})"
                ),
                anomaly_score=float(score),
            ))

    return findings
