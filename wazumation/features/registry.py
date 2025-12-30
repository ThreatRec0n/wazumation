"""Feature registry (extensible)."""

from __future__ import annotations

from typing import Dict, List

from wazumation.features.models import FeatureSpec, FieldSpec


def get_feature_registry() -> Dict[str, FeatureSpec]:
    """
    Returns a dict of feature_id -> Feature.

    These are safe-by-default and only change local config when explicitly enabled
    and applied with approval.
    """
    features: List[FeatureSpec] = [
        FeatureSpec(
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
        FeatureSpec(
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
        FeatureSpec(
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
        FeatureSpec(
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
        FeatureSpec(
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
        FeatureSpec(
            feature_id="email-alerts",
            title="Email alerts",
            description="Enable email alerts (SMTP settings and recipients).",
            requires_secrets=True,
            config_schema=[
                FieldSpec(
                    name="email_notification",
                    field_type="bool",
                    default=True,
                    required=True,
                    help_text="Enable email notifications in Wazuh (<global><email_notification>).",
                    ossec_section="global",
                    ossec_key="email_notification",
                ),
                FieldSpec(
                    name="smtp_server",
                    field_type="string",
                    required=True,
                    placeholder="smtp.example.com",
                    help_text="SMTP server hostname (<global><smtp_server>).",
                    ossec_section="global",
                    ossec_key="smtp_server",
                ),
                FieldSpec(
                    name="smtp_port",
                    field_type="int",
                    default=25,
                    required=False,
                    placeholder="587",
                    help_text="SMTP port (<global><smtp_port>).",
                    ossec_section="global",
                    ossec_key="smtp_port",
                ),
                FieldSpec(
                    name="email_from",
                    field_type="email",
                    required=True,
                    placeholder="wazuh@example.com",
                    help_text="From email address (<global><email_from>).",
                    ossec_section="global",
                    ossec_key="email_from",
                ),
                FieldSpec(
                    name="email_to",
                    field_type="list[string]",
                    required=True,
                    placeholder="soc@example.com,secops@example.com",
                    help_text="Recipients (<global><email_to>) (comma-separated).",
                    ossec_section="global",
                    ossec_key="email_to",
                ),
            ],
            actions=[
                {
                    "section": "global",
                    "desired_from_values": {
                        "email_notification": "email_notification",
                        "smtp_server": "smtp_server",
                        "smtp_port": "smtp_port",
                        "email_from": "email_from",
                        "email_to": "email_to",
                    },
                }
            ],
        ),
    ]

    return {f.feature_id: f for f in features}


