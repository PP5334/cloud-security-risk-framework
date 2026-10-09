"""
Generates a larger, labeled synthetic batch (default n=100) for computing
real detection-rate / correlation-accuracy numbers, as opposed to the 4
hand-built illustrative cases in run_scenarios.py (which stay in the paper
as worked examples, not as the evidential basis for any percentage).

Each case carries a ground-truth record of which of the 3 signal types
were deliberately injected, so results can be scored against a known
answer rather than eyeballed.
"""

import itertools
import random
from datetime import datetime, timedelta

CONFIG_TYPES = ("s3", "iam_policy", "security_group", "ec2_instance")
BEHAVIORAL_TYPES = ("new_access_key", "new_region_login", "api_call_spike")
SIGNAL_NAMES = ("config", "behavioral", "ml")

ML_ANOMALOUS_ACTIONS = ["ListBuckets", "GetObject", "PutObject", "DeleteObject", "ListObjects",
                        "GetBucketPolicy", "PutBucketAcl", "ListUsers"]
ML_NORMAL_ACTIONS = ["DescribeInstances", "ListObjects", "GetObject"]

BASE_TIME = datetime(2026, 10, 7, 0, 0, 0)


def _signal_count_plan(n):
    """Stratifies n cases evenly across ground-truth signal counts 0-3,
    and within each count, evenly across which combination of signals
    is injected (e.g. count=1 cycles config-only, behavioral-only, ml-only)."""
    per_count = n // 4
    plan = []
    for count in (0, 1, 2, 3):
        combos = list(itertools.combinations(SIGNAL_NAMES, count)) or [()]
        for i in range(per_count):
            plan.append(combos[i % len(combos)])
    while len(plan) < n:
        plan.append(plan[len(plan) % len(plan)] if plan else ())
    return plan[:n]


def _config_resource(case_idx, dirty, config_type, identity):
    name = f"res-{case_idx:03d}-{config_type}"
    if config_type == "s3":
        grants = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}] if dirty else []
        return "s3_buckets", {"name": name, "acl_grants": grants, "policy_statements": []}, name
    if config_type == "iam_policy":
        statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}] if dirty else \
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::scoped/*"}]
        return "iam_policies", {"name": name, "attached_identity": identity, "statements": statements}, name
    if config_type == "security_group":
        ip_permissions = [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}] if dirty else \
            [{"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        return "security_groups", {"group_id": name, "group_name": name, "ip_permissions": ip_permissions}, name

    instance = {
        "instance_id": name,
        "public_ip": f"203.0.113.{(case_idx % 250) + 1}" if dirty else None,
        "has_open_sensitive_sg": dirty,
        "http_tokens": "optional" if dirty else "required",
    }
    return "ec2_instances", instance, name


def _case_events(rng, case_idx, identity, ml_injected, behavioral_injected, behavioral_type, known_ip):
    """
    Feature values are drawn from a distribution around each class's
    center, not fixed at two maximally-separated extremes — so some
    ml_injected=True sessions land close to normal (and may be missed)
    and some ml_injected=False sessions drift slightly (and may trigger
    a false positive). A detector that's never wrong on data built to be
    cleanly separable isn't evidence of anything; this is.
    """
    spike_injected = behavioral_injected and behavioral_type == "api_call_spike"

    if ml_injected:
        hour = max(0, min(23, round(rng.gauss(6, 4))))
        ip_is_novel = rng.random() < rng.uniform(0.5, 1.0)
        count_multiplier = rng.uniform(1.1, 1.5)  # kept under the api_call_spike threshold (20/5min) unless spike is deliberately injected
        pool_size = rng.randint(4, 8)
        action_pool = ML_ANOMALOUS_ACTIONS[:pool_size]
    else:
        hour = max(0, min(23, round(rng.gauss(14, 2))))
        ip_is_novel = rng.random() < 0.12
        count_multiplier = rng.uniform(0.9, 1.3)
        action_pool = ML_NORMAL_ACTIONS

    source_ip = f"198.51.100.{(case_idx % 250) + 1}" if ip_is_novel else known_ip
    count = max(4, round(12 * count_multiplier))
    if spike_injected:
        count = max(count, 25)
    spacing = 5.0 / max(count - 1, 1)

    start = BASE_TIME.replace(hour=hour)
    events = [{
        "identity": identity,
        "event_name": action_pool[i % len(action_pool)],
        "event_time": start + timedelta(minutes=spacing * i),
        "aws_region": "us-east-1",
        "source_ip": source_ip,
    } for i in range(count)]

    if behavioral_injected and behavioral_type == "new_access_key":
        events.append({
            "identity": identity, "event_name": "CreateAccessKey", "event_time": start,
            "aws_region": "us-east-1", "source_ip": source_ip,
            "response_access_key_id": f"AKIA_NEW_{case_idx:03d}",
        })
    elif behavioral_injected and behavioral_type == "new_region_login":
        events.append({
            "identity": identity, "event_name": "AssumeRole", "event_time": start,
            "aws_region": "ap-southeast-2", "source_ip": source_ip,
        })

    return events


def generate_batch(n=100, seed=7):
    rng = random.Random(seed)
    plan = _signal_count_plan(n)
    rng.shuffle(plan)

    resource_snapshot = {"s3_buckets": [], "iam_policies": [], "security_groups": [], "ec2_instances": []}
    all_events = []
    cases = []
    ground_truth = {}
    known_access_keys = set()
    known_regions_by_identity = {}
    known_source_ips_by_identity = {}

    behavioral_type_cycle = itertools.cycle(BEHAVIORAL_TYPES)
    config_type_cycle = itertools.cycle(CONFIG_TYPES)

    for idx, injected_signals in enumerate(plan):
        case_id = f"case-{idx:03d}"
        identity = f"identity-{idx:03d}"
        config_injected = "config" in injected_signals
        behavioral_injected = "behavioral" in injected_signals
        ml_injected = "ml" in injected_signals
        behavioral_type = next(behavioral_type_cycle) if behavioral_injected else None
        config_type = next(config_type_cycle)

        known_access_keys.add(f"AKIA_BASE_{idx:03d}")
        known_regions_by_identity[identity] = {"us-east-1"}
        known_ip = f"10.0.{(idx // 250) + 1}.{(idx % 250) + 1}"
        known_source_ips_by_identity[identity] = {known_ip}

        bucket_key, resource, resource_name = _config_resource(idx, config_injected, config_type, identity)
        resource_snapshot[bucket_key].append(resource)

        all_events.extend(_case_events(rng, idx, identity, ml_injected, behavioral_injected, behavioral_type, known_ip))

        cases.append({"case_id": case_id, "identity": identity, "resources": [resource_name]})
        ground_truth[case_id] = {
            "config": config_injected, "behavioral": behavioral_injected, "ml": ml_injected,
            "count": len(injected_signals), "behavioral_type": behavioral_type, "config_type": config_type,
        }

    return {
        "resource_snapshot": resource_snapshot,
        "events": all_events,
        "cases": cases,
        "ground_truth": ground_truth,
        "known_access_keys": known_access_keys,
        "known_regions_by_identity": known_regions_by_identity,
        "known_source_ips_by_identity": known_source_ips_by_identity,
    }
