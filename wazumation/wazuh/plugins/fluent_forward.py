"""Auto-generated plugin wrapper for `fluent-forward`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class FluentForwardPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='fluent-forward', section_tag='fluent-forward', supported_installations=['manager', 'agent'], selector_attributes={} or None)
