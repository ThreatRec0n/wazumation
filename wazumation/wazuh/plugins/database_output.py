"""Auto-generated plugin wrapper for `database_output`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class DatabaseOutputPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='database_output', section_tag='database_output', supported_installations=['manager', 'agent'], selector_attributes={} or None)
