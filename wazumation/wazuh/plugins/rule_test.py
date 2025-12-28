"""Auto-generated plugin wrapper for `rule_test`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class RuleTestPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='rule_test', section_tag='rule_test', supported_installations=['manager', 'agent'], selector_attributes={} or None)
