"""Auto-generated plugin wrapper for `labels`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class LabelsPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='labels', section_tag='labels', supported_installations=['manager', 'agent'], selector_attributes={} or None)
