"""Auto-generated plugin wrapper for `logging`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class LoggingPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='logging', section_tag='logging', supported_installations=['manager', 'agent'], selector_attributes={} or None)
