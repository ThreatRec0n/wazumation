"""Auto-generated plugin wrapper for `gcp-bucket`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class GcpBucketPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='gcp-bucket', section_tag='gcp-bucket', supported_installations=['manager', 'agent'], selector_attributes={} or None)
