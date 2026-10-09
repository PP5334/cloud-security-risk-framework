"""
Objective 3 — rule-based behavioral detector.

Deliberately not ML: each rule is a named, human-readable condition over
CloudTrail-shaped events, kept as the primary detection mechanism. The
Isolation Forest component in ml_anomaly.py sits alongside this, not in
place of it.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta


@dataclass
class BehavioralFinding:
    identity: str
    issue: str
    detail: str


def _event_time(event):
    return event["event_time"]


def check_new_access_key(events, known_access_keys):
    """
    known_access_keys: set of access key ids already known/trusted for the
    identity before this batch of events (the "baseline").
    """
    findings = []
    for event in events:
        if event.get("event_name") != "CreateAccessKey":
            continue
        new_key = event.get("response_access_key_id")
        if new_key and new_key not in known_access_keys:
            findings.append(BehavioralFinding(
                identity=event["identity"],
                issue="new_access_key",
                detail=f"New access key {new_key} created, not in known baseline",
            ))
    return findings


def check_new_region_login(events, known_regions_by_identity):
    findings = []
    for event in events:
        if event.get("event_name") not in ("ConsoleLogin", "AssumeRole", "GetSessionToken"):
            continue
        identity = event["identity"]
        region = event.get("aws_region")
        baseline = known_regions_by_identity.get(identity, set())
        if region and region not in baseline:
            findings.append(BehavioralFinding(
                identity=identity,
                issue="new_region_login",
                detail=f"Login/assume-role from region '{region}', outside known baseline {sorted(baseline)}",
            ))
    return findings


def check_api_call_spike(events, window=timedelta(minutes=5), threshold=20):
    """
    Flags an identity if it issues more than `threshold` API calls inside
    any `window`-sized sliding window within the given events.
    """
    findings = []
    by_identity = defaultdict(list)
    for event in events:
        by_identity[event["identity"]].append(_event_time(event))

    for identity, times in by_identity.items():
        times = sorted(times)
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            count = right - left + 1
            if count > threshold:
                findings.append(BehavioralFinding(
                    identity=identity,
                    issue="api_call_spike",
                    detail=f"{count} API calls within a {window} window (threshold {threshold})",
                ))
                break

    return findings


def scan_behavior(events, known_access_keys=None, known_regions_by_identity=None,
                   spike_window=timedelta(minutes=5), spike_threshold=20):
    known_access_keys = known_access_keys or set()
    known_regions_by_identity = known_regions_by_identity or {}

    findings = []
    findings.extend(check_new_access_key(events, known_access_keys))
    findings.extend(check_new_region_login(events, known_regions_by_identity))
    findings.extend(check_api_call_spike(events, spike_window, spike_threshold))
    return findings
