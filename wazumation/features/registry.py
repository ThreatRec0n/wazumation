"""Feature registry (extensible)."""

from __future__ import annotations

from typing import Dict, List

from wazumation.features.models import Feature


def get_feature_registry() -> Dict[str, Feature]:
    """
    Returns a dict of feature_id -> Feature.

    These are safe-by-default and only change local config when explicitly enabled
    and applied with approval.
    """
    features: List[Feature] = [
        Feature(
            feature_id="fim-enhanced",
            title="File Integrity Monitoring enhancements",
            description="Enable common syscheck hardening options (whodata, scan_on_start, etc.)",
            actions=[
                {
                    "section": "syscheck",
                    "desired": {
                        "scan_on_start": "yes",
                        "whodata": "yes",
                    },
                }
            ],
        ),
        Feature(
            feature_id="auditd-monitoring",
            title="Auditd monitoring (Linux)",
            description="Enable auditd localfile ingestion template (requires auditd logs present).",
            actions=[
                {
                    "section": "localfile",
                    "ensure_instance": {
                        "log_format": "audit",
                        "location": "/var/log/audit/audit.log",
                    },
                }
            ],
        ),
        Feature(
            feature_id="vuln-detector",
            title="Vulnerability detector enablement",
            description="Enable vulnerability-detection section (safe defaults).",
            actions=[
                {
                    "section": "vulnerability-detection",
                    "desired": {
                        "enabled": "yes",
                    },
                }
            ],
        ),
        Feature(
            feature_id="sca-cis",
            title="CIS hardening / SCA enablement",
            description="Enable SCA module (policy selection remains Wazuh-managed).",
            actions=[
                {
                    "section": "sca",
                    "desired": {
                        "enabled": "yes",
                    },
                }
            ],
        ),
        Feature(
            feature_id="localfile-nginx",
            title="Nginx access log ingestion",
            description="Add localfile template for /var/log/nginx/access.log",
            actions=[
                {
                    "section": "localfile",
                    "ensure_instance": {
                        "log_format": "apache",
                        "location": "/var/log/nginx/access.log",
                    },
                }
            ],
        ),
        Feature(
            feature_id="email-alerts",
            title="Email alerts",
            description="Enable email alerts (prompts for SMTP settings when enabled).",
            requires_secrets=True,
            actions=[
                {
                    "section": "global",
                    "desired_from_prompts": {
                        "email_notification": {"prompt": "Enable email notifications (yes/no)", "default": "yes"},
                        "smtp_server": {"prompt": "SMTP server hostname", "required": True},
                        "email_from": {"prompt": "From email address", "required": True},
                        "email_to": {"prompt": "To email address", "required": True},
                    },
                }
            ],
        ),
    ]

    return {f.feature_id: f for f in features}


