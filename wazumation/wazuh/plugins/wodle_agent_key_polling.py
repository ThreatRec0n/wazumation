"""Auto-generated plugin wrapper for `wodle name="agent-key-polling"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleAgentKeyPollingPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="agent-key-polling"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'agent-key-polling'} or None)
