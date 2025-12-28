"""Auto-generated plugin wrapper for `office365`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class Office365Plugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='office365', section_tag='office365', supported_installations=['manager', 'agent'], selector_attributes={} or None)
