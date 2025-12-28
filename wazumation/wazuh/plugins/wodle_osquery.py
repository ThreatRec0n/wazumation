"""Auto-generated plugin wrapper for `wodle name="osquery"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleOsqueryPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="osquery"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'osquery'} or None)
