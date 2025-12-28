"""Auto-generated plugin wrapper for `anti_tampering`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class AntiTamperingPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='anti_tampering', section_tag='anti_tampering', supported_installations=['manager', 'agent'], selector_attributes={} or None)
