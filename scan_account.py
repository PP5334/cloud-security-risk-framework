"""
CLI entry point for scanning a real AWS account.

    python scan_account.py --config config.yaml
    python scan_account.py --config config.yaml --cloudtrail-hours 6
    python scan_account.py --config config.yaml --skip-cloudtrail

Everything account-specific (which profile/region to use, which access
keys/regions/IPs count as "known" for which identity, which identity owns
which resource) comes from the config file — see config.example.yaml.
Nothing account-specific is hardcoded here.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone

import boto3

from behavioral_rules import scan_behavior
from config_loader import ConfigError, load_config
from config_scanner import scan_live_account
from correlation_engine import correlate
from ml_anomaly import build_baseline_dataset, extract_session_features, fit_isolation_forest, scan_ml_anomaly
from remediation_advisor import advise


def fetch_recent_cloudtrail_events(session, hours=24):
    """
    Pulls from CloudTrail Event History — the free, built-in 90-day
    history every AWS account already has, no custom Trail/S3 setup
    needed. Note: this has an indexing delay of up to ~15 minutes, so
    very recent activity may not be queryable yet.
    """
    client = session.client("cloudtrail")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    events = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start_time, EndTime=end_time):
        for raw in page.get("Events", []):
            detail = json.loads(raw.get("CloudTrailEvent", "{}"))
            identity = raw.get("Username") or detail.get("userIdentity", {}).get("arn", "unknown")
            event = {
                "identity": identity,
                "event_name": raw.get("EventName"),
                "event_time": raw["EventTime"],
                "aws_region": detail.get("awsRegion", raw.get("AwsRegion")),
                "source_ip": detail.get("sourceIPAddress"),
            }
            if raw.get("EventName") == "CreateAccessKey":
                response_elements = detail.get("responseElements") or {}
                event["response_access_key_id"] = (response_elements.get("accessKey") or {}).get("accessKeyId")
            events.append(event)
    return events


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


def build_cases(config_findings, identities_seen, resource_ownership):
    """
    Builds one correlation case per identity in resource_ownership (config
    finding + behavioral/ML finding merged), plus one per leftover resource
    or identity that isn't in the ownership mapping (reported on its own,
    since there's no way to merge it without knowing who owns what).
    """
    cases = []
    claimed_resources = set()

    for identity, resources in resource_ownership.items():
        cases.append({"case_id": identity, "identity": identity, "resources": list(resources)})
        claimed_resources.update(resources)

    for f in config_findings:
        if f.resource not in claimed_resources:
            cases.append({"case_id": f.resource, "identity": f.resource, "resources": [f.resource]})
            claimed_resources.add(f.resource)

    for identity in identities_seen:
        if identity not in resource_ownership:
            cases.append({"case_id": identity, "identity": identity, "resources": []})

    return cases


def main():
    parser = argparse.ArgumentParser(description="Scan a real AWS account for config/behavioral/ML risk signals.")
    parser.add_argument("--config", default=None, help="Path to config.yaml (default: ./config.yaml, or $CLOUDSEC_CONFIG)")
    parser.add_argument("--cloudtrail-hours", type=int, default=24, help="How far back to pull CloudTrail activity")
    parser.add_argument("--skip-cloudtrail", action="store_true", help="Only run the configuration scan")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as e:
        raise SystemExit(f"Configuration error: {e}")

    session = boto3.Session(profile_name=config["aws_profile"], region_name=config["aws_region"])

    print(f"Scanning via profile={config['aws_profile'] or '(default)'}, region={config['aws_region']} ...")
    config_findings = scan_live_account(session)

    behavioral_findings, ml_findings, identities_seen = [], [], set()

    if not args.skip_cloudtrail:
        events = fetch_recent_cloudtrail_events(session, hours=args.cloudtrail_hours)
        identities_seen = {e["identity"] for e in events}

        behavioral_findings = scan_behavior(
            events,
            known_access_keys=config["known_access_keys"],
            known_regions_by_identity=config["known_regions_by_identity"],
            spike_window=timedelta(minutes=config["spike_window_minutes"]),
            spike_threshold=config["spike_threshold"],
        )

        baseline_matrix = build_baseline_dataset(n=200, random_state=42)
        model = fit_isolation_forest(baseline_matrix, contamination=config["contamination"], random_state=42)
        ml_findings = scan_ml_anomaly(sessions_for_ml(events, config["known_source_ips_by_identity"]), model=model)

    if not config["resource_ownership"] and not args.skip_cloudtrail:
        print(
            "Note: no resource_ownership configured, so config findings and behavioral/ML "
            "findings below are reported separately rather than merged into one case.\n"
        )

    cases = build_cases(config_findings, identities_seen, config["resource_ownership"])
    results = correlate(cases, config_findings, behavioral_findings, ml_findings)

    print(f"{'Case':<40} {'Signals triggered':<30} {'Severity'}")
    print("-" * 90)
    for r in results:
        print(f"{r.case_id:<40} {', '.join(r.signals_triggered) or '(none)':<30} {r.severity}")

    print("\nDetail:\n")
    for r in results:
        if not r.findings:
            continue
        print(f"[{r.severity}] {r.case_id}")
        for issue, items in _group_by_issue(r.findings):
            if len(items) == 1:
                print(f"    - ({issue}) {items[0].detail}")
            else:
                print(f"    - ({issue}) x{len(items)}, e.g.: {items[0].detail}")
        for a in advise(r):
            print(f"    Remediation [{a.mode}]: {a.description}")
        print()


def _group_by_issue(findings):
    """Real CloudTrail activity can repeat the same rule match many times
    in one window (e.g. 30 logins from an unrecognized region) -- collapse
    those into one line with a count instead of printing each one."""
    order = []
    groups = {}
    for f in findings:
        if f.issue not in groups:
            groups[f.issue] = []
            order.append(f.issue)
        groups[f.issue].append(f)
    return [(issue, groups[issue]) for issue in order]


if __name__ == "__main__":
    main()
