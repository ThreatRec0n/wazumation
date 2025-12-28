"""Auto-generated plugin wrapper for `client_buffer`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class ClientBufferPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='client_buffer', section_tag='client_buffer', supported_installations=['manager', 'agent'], selector_attributes={} or None)
