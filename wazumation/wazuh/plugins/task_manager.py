"""Auto-generated plugin wrapper for `task-manager`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class TaskManagerPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='task-manager', section_tag='task-manager', supported_installations=['manager', 'agent'], selector_attributes={} or None)
