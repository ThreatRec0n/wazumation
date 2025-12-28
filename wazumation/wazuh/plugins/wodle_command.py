"""Auto-generated plugin wrapper for `wodle name="command"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleCommandPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="command"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'command'} or None)
