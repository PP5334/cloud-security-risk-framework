"""
Runtime configuration loading.

Account-specific details (which AWS profile/region to use, which access
keys/regions/IPs count as "known" for which identity) are never hardcoded
in source — they're supplied via a YAML file at runtime, resolved in this
order: an explicit --config path, the CLOUDSEC_CONFIG environment
variable, or ./config.yaml in the current directory.
"""

import os

import yaml

DEFAULT_CONFIG_PATH = "config.yaml"
EXAMPLE_CONFIG_PATH = "config.example.yaml"


class ConfigError(Exception):
    pass


def resolve_config_path(explicit_path=None):
    if explicit_path:
        return explicit_path
    if os.environ.get("CLOUDSEC_CONFIG"):
        return os.environ["CLOUDSEC_CONFIG"]
    return DEFAULT_CONFIG_PATH


def load_config(explicit_path=None):
    path = resolve_config_path(explicit_path)

    if not os.path.exists(path):
        raise ConfigError(
            f"Config file not found: '{path}'. Copy {EXAMPLE_CONFIG_PATH} to {DEFAULT_CONFIG_PATH} "
            f"and fill in your own account details, or pass --config <path> / set CLOUDSEC_CONFIG."
        )

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    aws = raw.get("aws", {})
    behavioral = raw.get("behavioral_baseline", {})
    ml = raw.get("ml_baseline", {})

    return {
        "aws_profile": aws.get("profile"),
        "aws_region": aws.get("region", "us-east-1"),
        "known_access_keys": set(behavioral.get("known_access_keys", [])),
        "known_regions_by_identity": {
            identity: set(regions)
            for identity, regions in behavioral.get("known_regions_by_identity", {}).items()
        },
        "spike_window_minutes": behavioral.get("spike_window_minutes", 5),
        "spike_threshold": behavioral.get("spike_threshold", 20),
        "known_source_ips_by_identity": {
            identity: set(ips)
            for identity, ips in ml.get("known_source_ips_by_identity", {}).items()
        },
        "contamination": ml.get("contamination", 0.1),
        "resource_ownership": raw.get("resource_ownership", {}),
    }
