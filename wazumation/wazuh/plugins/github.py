"""Auto-generated plugin wrapper for `github`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class GithubPlugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='github', section_tag='github', supported_installations=['manager', 'agent'], selector_attributes={} or None)
