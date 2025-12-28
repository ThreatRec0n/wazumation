"""Auto-generated plugin wrapper for `indexer`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class IndexerPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='indexer', section_tag='indexer', supported_installations=['manager', 'agent'], selector_attributes={} or None)
