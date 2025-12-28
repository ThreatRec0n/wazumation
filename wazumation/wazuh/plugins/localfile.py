"""Auto-generated plugin wrapper for `localfile`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class LocalfilePlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='localfile', section_tag='localfile', supported_installations=['manager', 'agent'], selector_attributes={} or None)
