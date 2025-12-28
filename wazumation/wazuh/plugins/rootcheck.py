"""Auto-generated plugin wrapper for `rootcheck`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class RootcheckPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='rootcheck', section_tag='rootcheck', supported_installations=['manager', 'agent'], selector_attributes={} or None)
