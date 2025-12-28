"""Auto-generated plugin wrapper for `remote`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class RemotePlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='remote', section_tag='remote', supported_installations=['manager', 'agent'], selector_attributes={} or None)
