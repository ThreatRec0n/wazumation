"""Auto-generated plugin wrapper for `gcp-pubsub`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class GcpPubsubPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='gcp-pubsub', section_tag='gcp-pubsub', supported_installations=['manager', 'agent'], selector_attributes={} or None)
