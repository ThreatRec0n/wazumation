"""Auto-generated plugin wrapper for `agent-upgrade`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class AgentUpgradePlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='agent-upgrade', section_tag='agent-upgrade', supported_installations=['manager', 'agent'], selector_attributes={} or None)
