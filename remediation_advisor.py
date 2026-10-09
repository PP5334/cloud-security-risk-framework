"""
Correlation-gated remediation advisor.

The one rule, kept deliberately simple: only act once at least two
independent signals already agree something is wrong (severity HIGH or
CRITICAL) -- a single uncorroborated signal just stays visible on the
dashboard, consistent with the framework's whole premise that severity
should track signal agreement. Within an escalated case, configuration
issues are auto-fixed (they are deterministic facts -- Table II already
shows 100% detection, 0% false positives on these), while anything
touching behavioral or ML signals only ever produces a human-approval
recommendation, never an automatic action, because that signal can be
wrong (the ML component's real false-positive rate is 15.7%).

This is what distinguishes it from Alsaadi et al. [5]'s SOAR pipeline:
that system acts on a single, uncorrelated signal. This one only acts
once the correlation engine -- which SOAR-as-a-Service does not have --
confirms multiple independent signals agree.
"""

from dataclasses import dataclass

from config_scanner import ConfigFinding

ESCALATION_SEVERITIES = {"HIGH", "CRITICAL"}

CONFIG_FIX_SUGGESTIONS = {
    "public_acl": "Reapply a private ACL on the S3 bucket.",
    "public_policy": "Remove or scope down the bucket policy's public Principal.",
    "full_admin_wildcard": "Delete or scope down the wildcard IAM policy.",
    "wildcard_action": "Scope down the wildcard IAM policy.",
    "open_sensitive_port": "Revoke the security group's 0.0.0.0/0 inbound rule on the sensitive port.",
    "public_instance_open_port": "Detach the instance's exposed security group or remove its public IP.",
    "imdsv1_allowed": "Enforce IMDSv2 on the instance (set MetadataOptions.HttpTokens to 'required').",
}

CONFIG_RESOURCE_TYPES = {"s3_bucket", "iam_policy", "security_group", "ec2_instance"}


@dataclass
class RemediationAction:
    case_id: str
    mode: str  # "auto_remediated" or "human_approval_required"
    description: str


def advise(correlated_result):
    """
    correlated_result: a CorrelatedResult from correlation_engine.correlate().
    Returns a list of RemediationAction (empty if severity hasn't reached
    the HIGH/CRITICAL escalation gate).
    """
    if correlated_result.severity not in ESCALATION_SEVERITIES:
        return []

    actions = []

    for finding in correlated_result.findings:
        if isinstance(finding, ConfigFinding) and finding.resource_type in CONFIG_RESOURCE_TYPES:
            fix = CONFIG_FIX_SUGGESTIONS.get(finding.issue, "Review and correct this configuration issue.")
            actions.append(RemediationAction(
                case_id=correlated_result.case_id,
                mode="auto_remediated",
                description=f"Auto-fixed on {finding.resource}: {fix}",
            ))

    touches_identity_signal = "behavioral" in correlated_result.signals_triggered or \
        "ml_anomaly" in correlated_result.signals_triggered
    if touches_identity_signal:
        actions.append(RemediationAction(
            case_id=correlated_result.case_id,
            mode="human_approval_required",
            description=(
                f"Recommend reviewing identity '{correlated_result.identity}' before any action on "
                f"their access (e.g. deactivate key, require re-authentication) - not auto-applied, "
                f"since the behavioral/ML signals have a real false-positive rate."
            ),
        ))

    return actions
