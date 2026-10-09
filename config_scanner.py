"""
Objective 2 — AWS configuration risk scanner.

Checks a resource snapshot for four misconfiguration classes: public S3
buckets, overly permissive IAM policies, open SSH/RDP security groups,
and exposed EC2 instances. Works on plain dicts shaped like the boto3
responses listed next to each function, so the same check runs unchanged
whether the snapshot came from a live account or a staged test scenario.
"""

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}


def _has_open_sensitive_port(ip_permissions):
    """Shared by check_open_security_group and check_ec2_instance_exposure
    so both agree on what 'open to the world on a sensitive port' means."""
    for rule in ip_permissions or []:
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        open_to_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
        if not open_to_world:
            continue
        for port in SENSITIVE_PORTS:
            if from_port is not None and to_port is not None and from_port <= port <= to_port:
                return True
    return False

from dataclasses import dataclass, field


@dataclass
class ConfigFinding:
    resource: str
    resource_type: str
    issue: str
    detail: str


def check_public_s3_bucket(bucket_name, acl_grants, policy_statements=None):
    """
    acl_grants: list of grants as returned by s3.get_bucket_acl()['Grants'],
                e.g. [{"Grantee": {"URI": ".../AllUsers"}, "Permission": "READ"}]
    policy_statements: optional list of bucket policy statements
                        (Statement entries from get_bucket_policy())
    """
    findings = []
    public_group_uris = (
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    )

    for grant in acl_grants or []:
        uri = grant.get("Grantee", {}).get("URI", "")
        if uri in public_group_uris:
            findings.append(ConfigFinding(
                resource=bucket_name,
                resource_type="s3_bucket",
                issue="public_acl",
                detail=f"ACL grants {grant.get('Permission')} to {uri.rsplit('/', 1)[-1]}",
            ))

    for statement in policy_statements or []:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        is_wildcard_principal = principal == "*" or principal == {"AWS": "*"}
        if is_wildcard_principal:
            findings.append(ConfigFinding(
                resource=bucket_name,
                resource_type="s3_bucket",
                issue="public_policy",
                detail=f"Bucket policy allows Principal '*' for action(s) {statement.get('Action')}",
            ))

    return findings


def check_permissive_iam_policy(policy_name, statements, attached_identity=None):
    """
    statements: list of policy statement dicts (the Statement list inside
                an IAM policy document, as returned by
                iam.get_policy_version()['PolicyVersion']['Document']['Statement'])

    `resource` on the returned findings is always the policy name, so
    config findings can be matched back to a case/resource consistently.
    attached_identity, if given, is folded into the detail text only.
    """
    findings = []
    identity_note = f" (attached to {attached_identity})" if attached_identity else ""

    for statement in statements or []:
        if statement.get("Effect") != "Allow":
            continue
        action = statement.get("Action")
        resource = statement.get("Resource")
        action_is_wildcard = action == "*" or action == ["*"]
        resource_is_wildcard = resource == "*" or resource == ["*"]

        if action_is_wildcard and resource_is_wildcard:
            findings.append(ConfigFinding(
                resource=policy_name,
                resource_type="iam_policy",
                issue="full_admin_wildcard",
                detail=f"Policy '{policy_name}' grants Action:* on Resource:*{identity_note}",
            ))
        elif action_is_wildcard:
            findings.append(ConfigFinding(
                resource=policy_name,
                resource_type="iam_policy",
                issue="wildcard_action",
                detail=f"Policy '{policy_name}' grants Action:* on {resource}{identity_note}",
            ))

    return findings


def check_open_security_group(group_id, group_name, ip_permissions):
    """
    ip_permissions: list of inbound rules as returned by
                    ec2.describe_security_groups()['SecurityGroups'][*]['IpPermissions']
    """
    findings = []

    for rule in ip_permissions or []:
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        open_to_world = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
        )
        if not open_to_world:
            continue

        for port, label in SENSITIVE_PORTS.items():
            if from_port is not None and to_port is not None and from_port <= port <= to_port:
                findings.append(ConfigFinding(
                    resource=group_id,
                    resource_type="security_group",
                    issue="open_sensitive_port",
                    detail=f"{label} (port {port}) open to 0.0.0.0/0 on {group_name} ({group_id})",
                ))

    return findings


def check_ec2_instance_exposure(instance_id, public_ip, has_open_sensitive_sg, http_tokens):
    """
    public_ip: the instance's public IPv4 address, or None/"" if it has none.
    has_open_sensitive_sg: bool — whether any security group attached to
                            this instance allows SSH/RDP from 0.0.0.0/0
                            (compute with _has_open_sensitive_port on the
                            instance's attached groups' IpPermissions).
    http_tokens: instance's MetadataOptions.HttpTokens
                 ("required" enforces IMDSv2; "optional" still allows IMDSv1).
    """
    findings = []

    if public_ip and has_open_sensitive_sg:
        findings.append(ConfigFinding(
            resource=instance_id,
            resource_type="ec2_instance",
            issue="public_instance_open_port",
            detail=f"Instance has public IP {public_ip} and an attached security group allows SSH/RDP from 0.0.0.0/0",
        ))

    if http_tokens != "required":
        findings.append(ConfigFinding(
            resource=instance_id,
            resource_type="ec2_instance",
            issue="imdsv1_allowed",
            detail=f"MetadataOptions.HttpTokens='{http_tokens}' - IMDSv1 still allowed (should be 'required' to enforce IMDSv2)",
        ))

    return findings


def scan_resources(resource_snapshot):
    """
    resource_snapshot: {
        "s3_buckets": [{"name": ..., "acl_grants": [...], "policy_statements": [...]}],
        "iam_policies": [{"name": ..., "statements": [...], "attached_identity": ...}],
        "security_groups": [{"group_id": ..., "group_name": ..., "ip_permissions": [...]}],
        "ec2_instances": [{"instance_id": ..., "public_ip": ..., "has_open_sensitive_sg": ..., "http_tokens": ...}],
    }
    Returns a flat list of ConfigFinding, which is what the correlation
    engine consumes.
    """
    findings = []

    for bucket in resource_snapshot.get("s3_buckets", []):
        findings.extend(check_public_s3_bucket(
            bucket["name"], bucket.get("acl_grants"), bucket.get("policy_statements")
        ))

    for policy in resource_snapshot.get("iam_policies", []):
        findings.extend(check_permissive_iam_policy(
            policy["name"], policy.get("statements"), policy.get("attached_identity")
        ))

    for sg in resource_snapshot.get("security_groups", []):
        findings.extend(check_open_security_group(
            sg["group_id"], sg.get("group_name", sg["group_id"]), sg.get("ip_permissions")
        ))

    for instance in resource_snapshot.get("ec2_instances", []):
        findings.extend(check_ec2_instance_exposure(
            instance["instance_id"], instance.get("public_ip"),
            instance.get("has_open_sensitive_sg", False), instance.get("http_tokens", "optional"),
        ))

    return findings


def scan_live_account(session):
    """
    Optional live path. Pulls the same four resource types via boto3 and
    runs them through the same checks used for the staged scenarios.
    Not required for the proof-of-concept test runs — only used if a real
    AWS session is passed in.
    """
    s3 = session.client("s3")
    iam = session.client("iam")
    ec2 = session.client("ec2")

    snapshot = {"s3_buckets": [], "iam_policies": [], "security_groups": [], "ec2_instances": []}

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        acl_grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            import json
            statements = json.loads(policy["Policy"]).get("Statement", [])
        except Exception:
            statements = []
        snapshot["s3_buckets"].append({
            "name": name, "acl_grants": acl_grants, "policy_statements": statements,
        })

    for policy in iam.list_policies(Scope="Local").get("Policies", []):
        version = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        statements = version["PolicyVersion"]["Document"].get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        snapshot["iam_policies"].append({
            "name": policy["PolicyName"], "statements": statements,
            "attached_identity": policy["Arn"],
        })

    security_groups = ec2.describe_security_groups().get("SecurityGroups", [])
    for sg in security_groups:
        snapshot["security_groups"].append({
            "group_id": sg["GroupId"], "group_name": sg.get("GroupName", sg["GroupId"]),
            "ip_permissions": sg.get("IpPermissions", []),
        })
    sg_open_by_id = {sg["GroupId"]: _has_open_sensitive_port(sg.get("IpPermissions", [])) for sg in security_groups}

    reservations = ec2.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") == "terminated":
                continue
            attached_sg_ids = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
            snapshot["ec2_instances"].append({
                "instance_id": instance["InstanceId"],
                "public_ip": instance.get("PublicIpAddress"),
                "has_open_sensitive_sg": any(sg_open_by_id.get(gid, False) for gid in attached_sg_ids),
                "http_tokens": instance.get("MetadataOptions", {}).get("HttpTokens", "optional"),
            })

    return scan_resources(snapshot)
