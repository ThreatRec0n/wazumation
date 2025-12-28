"""Auto-generated plugin wrapper for `syscheck`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class SyscheckPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='syscheck', section_tag='syscheck', supported_installations=['manager', 'agent'], selector_attributes={} or None)
