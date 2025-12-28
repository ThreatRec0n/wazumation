"""Auto-generated plugin wrapper for `wodle name="azure-logs"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleAzureLogsPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="azure-logs"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'azure-logs'} or None)
