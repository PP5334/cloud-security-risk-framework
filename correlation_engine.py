"""
Objective 4 — correlation / risk-scoring engine.

Combines all three detection signals (config misconfiguration, rule-based
behavioral flag, ML anomaly flag) per case (identity + the resources it
touches) into a single severity tier. Severity is driven purely by how
many of the three signal types fired for that case, not by signal type —
this is what lets the framework assign higher severity to resources with
multiple concurrent risk indicators, as described in the abstract.
"""

from dataclasses import dataclass, field

SEVERITY_BY_SIGNAL_COUNT = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}


@dataclass
class CorrelatedResult:
    case_id: str
    identity: str
    resources: list
    signals_triggered: list
    severity: str
    findings: list = field(default_factory=list)


def correlate(cases, config_findings, behavioral_findings, ml_findings):
    """
    cases: list of {"case_id": str, "identity": str, "resources": [str, ...]}
           — the known mapping of which resources a given identity's
           activity in this test run relates to.
    *_findings: flat lists from scan_resources() / scan_behavior() /
                scan_ml_anomaly(), matched back onto cases by resource
                name (config) or identity (behavioral, ml).
    """
    results = []

    for case in cases:
        case_resources = set(case["resources"])
        identity = case["identity"]

        matched_config = [f for f in config_findings if f.resource in case_resources]
        matched_behavioral = [f for f in behavioral_findings if f.identity == identity]
        matched_ml = [f for f in ml_findings if f.identity == identity]

        signals_triggered = []
        if matched_config:
            signals_triggered.append("config")
        if matched_behavioral:
            signals_triggered.append("behavioral")
        if matched_ml:
            signals_triggered.append("ml_anomaly")

        severity = SEVERITY_BY_SIGNAL_COUNT[len(signals_triggered)]

        results.append(CorrelatedResult(
            case_id=case["case_id"],
            identity=identity,
            resources=sorted(case_resources),
            signals_triggered=signals_triggered,
            severity=severity,
            findings=matched_config + matched_behavioral + matched_ml,
        ))

    return results
