"""Auto-generated plugin wrapper for `wodle name="syscollector"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleSyscollectorPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="syscollector"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'syscollector'} or None)
