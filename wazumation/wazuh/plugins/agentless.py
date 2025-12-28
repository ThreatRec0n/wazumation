"""Auto-generated plugin wrapper for `agentless`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class AgentlessPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='agentless', section_tag='agentless', supported_installations=['manager', 'agent'], selector_attributes={} or None)
