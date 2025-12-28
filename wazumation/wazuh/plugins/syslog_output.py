"""Auto-generated plugin wrapper for `syslog_output`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class SyslogOutputPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='syslog_output', section_tag='syslog_output', supported_installations=['manager', 'agent'], selector_attributes={} or None)
