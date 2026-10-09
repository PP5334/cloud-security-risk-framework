"""
Objective 6 — staged test scenarios.

Four illustrative cases, proof-of-concept scale (not a large empirical
study, stated honestly): one fully compromised identity (all three
signals fire -> CRITICAL), one behavior-only compromise with no
config issue (-> HIGH), one config-only issue with otherwise normal
behavior (-> MEDIUM), and one clean baseline to confirm the framework
doesn't cry wolf on ordinary activity (-> LOW).

Each case is deliberately constructed test data, not a real AWS
account snapshot or real CloudTrail export.
"""

from datetime import datetime, timedelta

from config_scanner import scan_resources
from behavioral_rules import scan_behavior
from ml_anomaly import build_baseline_dataset, extract_session_features, fit_isolation_forest, scan_ml_anomaly
from correlation_engine import correlate
from remediation_advisor import advise

BASE_TIME = datetime(2026, 10, 6, 3, 0, 0)

KNOWN_ACCESS_KEYS = {"AKIA_DEVOPS_ORIGINAL", "AKIA_ANALYST_ORIGINAL", "AKIA_CONTRACTOR_ORIGINAL", "AKIA_READER_ORIGINAL"}

KNOWN_REGIONS_BY_IDENTITY = {
    "iam-user-devops-01": {"us-east-1"},
    "iam-user-analyst-02": {"us-east-1"},
    "iam-user-contractor-03": {"us-east-1"},
    "iam-user-reader-04": {"us-east-1"},
}

KNOWN_SOURCE_IPS_BY_IDENTITY = {
    "iam-user-devops-01": {"10.0.1.15"},
    "iam-user-analyst-02": {"10.0.1.20"},
    "iam-user-contractor-03": {"203.0.113.9"},
    "iam-user-reader-04": {"10.0.1.30"},
}


def resource_snapshot():
    return {
        "s3_buckets": [
            {
                "name": "s3-bucket-uploads-prod",
                "acl_grants": [
                    {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"},
                ],
                "policy_statements": [],
            },
            {
                "name": "s3-bucket-public-docs",
                "acl_grants": [],
                "policy_statements": [],
            },
        ],
        "iam_policies": [
            {
                "name": "contractor-full-admin",
                "attached_identity": "iam-user-contractor-03",
                "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        ],
        "security_groups": [
            {
                "group_id": "sg-prod-app",
                "group_name": "prod-app-sg",
                "ip_permissions": [
                    {"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
            },
        ],
    }


def make_events(identity, source_ip, region, start, names_and_offsets, access_key_id=None):
    events = []
    for name, offset_minutes in names_and_offsets:
        event = {
            "identity": identity,
            "event_name": name,
            "event_time": start + timedelta(minutes=offset_minutes),
            "aws_region": region,
            "source_ip": source_ip,
        }
        if name == "CreateAccessKey":
            event["response_access_key_id"] = access_key_id
        events.append(event)
    return events


def cloudtrail_events():
    events = []

    events += make_events(
        "iam-user-devops-01", "198.51.100.77", "us-east-1", BASE_TIME,
        [("CreateAccessKey", 0.0)],
        access_key_id="AKIA_NEW_UNKNOWN_1",
    )
    spike_names = ["ListBuckets", "GetObject", "PutObject", "DeleteObject", "ListObjects",
                    "GetBucketPolicy", "PutBucketAcl", "ListUsers"]
    events += make_events(
        "iam-user-devops-01", "198.51.100.77", "us-east-1", BASE_TIME,
        [(spike_names[i % len(spike_names)], 0.2 * (i + 1)) for i in range(25)],
    )

    events += make_events(
        "iam-user-analyst-02", "203.0.113.200", "ap-southeast-2", BASE_TIME,
        [("AssumeRole", 0.0), ("ListBuckets", 1.0)],
    )

    normal_names = ["DescribeInstances", "ListObjects", "GetObject"]
    events += make_events(
        "iam-user-contractor-03", "203.0.113.9", "us-east-1", BASE_TIME.replace(hour=14),
        [(normal_names[i % len(normal_names)], 0.3 * i) for i in range(12)],
    )

    events += make_events(
        "iam-user-reader-04", "10.0.1.30", "us-east-1", BASE_TIME.replace(hour=14),
        [(normal_names[i % len(normal_names)], 0.3 * i) for i in range(12)],
    )

    return events


def sessions_for_ml(events):
    by_identity = {}
    for event in events:
        by_identity.setdefault(event["identity"], []).append(event)

    sessions = []
    for identity, identity_events in by_identity.items():
        known_ips = KNOWN_SOURCE_IPS_BY_IDENTITY.get(identity, set())
        features = extract_session_features(identity, identity_events, known_ips)
        if features:
            sessions.append(features)
    return sessions


def cases():
    return [
        {"case_id": "case-1-fully-compromised", "identity": "iam-user-devops-01",
         "resources": ["s3-bucket-uploads-prod"]},
        {"case_id": "case-2-behavior-only", "identity": "iam-user-analyst-02",
         "resources": ["sg-prod-app"]},
        {"case_id": "case-3-config-only", "identity": "iam-user-contractor-03",
         "resources": ["contractor-full-admin"]},
        {"case_id": "case-4-clean-baseline", "identity": "iam-user-reader-04",
         "resources": ["s3-bucket-public-docs"]},
    ]


def run():
    config_findings = scan_resources(resource_snapshot())

    events = cloudtrail_events()
    behavioral_findings = scan_behavior(
        events,
        known_access_keys=KNOWN_ACCESS_KEYS,
        known_regions_by_identity=KNOWN_REGIONS_BY_IDENTITY,
        spike_window=timedelta(minutes=5),
        spike_threshold=20,
    )

    baseline_matrix = build_baseline_dataset(n=200, random_state=42)
    model = fit_isolation_forest(baseline_matrix, contamination=0.1, random_state=42)
    ml_findings = scan_ml_anomaly(sessions_for_ml(events), model=model)

    results = correlate(cases(), config_findings, behavioral_findings, ml_findings)

    print(f"{'Case':<28} {'Identity':<24} {'Signals triggered':<30} {'Severity'}")
    print("-" * 100)
    for r in results:
        print(f"{r.case_id:<28} {r.identity:<24} {', '.join(r.signals_triggered) or '(none)':<30} {r.severity}")

    print("\nDetail:\n")
    for r in results:
        print(f"[{r.severity}] {r.case_id} - {r.identity}")
        if not r.findings:
            print("    No findings on any signal.")
        for f in r.findings:
            print(f"    - ({f.issue}) {f.detail}")

        actions = advise(r)
        if not actions:
            print("    Remediation: none - below the HIGH/CRITICAL escalation gate, dashboard-only.")
        for a in actions:
            print(f"    Remediation [{a.mode}]: {a.description}")
        print()
        print()

    return results


if __name__ == "__main__":
    run()
