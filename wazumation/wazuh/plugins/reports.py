"""Auto-generated plugin wrapper for `reports`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class ReportsPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='reports', section_tag='reports', supported_installations=['manager', 'agent'], selector_attributes={} or None)
