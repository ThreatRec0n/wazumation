"""Auto-generated plugin wrapper for `sca`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class ScaPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='sca', section_tag='sca', supported_installations=['manager', 'agent'], selector_attributes={} or None)
