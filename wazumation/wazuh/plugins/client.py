"""Auto-generated plugin wrapper for `client`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class ClientPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='client', section_tag='client', supported_installations=['manager', 'agent'], selector_attributes={} or None)
