"""Auto-generated plugin wrapper for `command`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class CommandPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='command', section_tag='command', supported_installations=['manager', 'agent'], selector_attributes={} or None)
