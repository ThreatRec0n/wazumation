"""Auto-generated plugin wrapper for `ms-graph`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class MsGraphPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='ms-graph', section_tag='ms-graph', supported_installations=['manager', 'agent'], selector_attributes={} or None)
