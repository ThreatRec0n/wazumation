"""Auto-generated plugin wrapper for `wodle name="aws-s3"`."""

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


class WodleAwsS3Plugin(DocDrivenSectionPlugin):
    """Doc-driven plugin for this Wazuh section."""

    def __init__(self):
        super().__init__(identifier='wodle name="aws-s3"', section_tag='wodle', supported_installations=['manager', 'agent'], selector_attributes={'name': 'aws-s3'} or None)
