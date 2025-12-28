"""Auto-generated plugin wrapper for `cluster`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class ClusterPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='cluster', section_tag='cluster', supported_installations=['manager', 'agent'], selector_attributes={} or None)
