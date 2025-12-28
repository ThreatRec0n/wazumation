"""Auto-generated plugin wrapper for `ruleset`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class RulesetPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='ruleset', section_tag='ruleset', supported_installations=['manager', 'agent'], selector_attributes={} or None)
