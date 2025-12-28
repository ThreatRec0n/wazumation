"""Auto-generated plugin wrapper for `integration`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class IntegrationPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='integration', section_tag='integration', supported_installations=['manager', 'agent'], selector_attributes={} or None)
