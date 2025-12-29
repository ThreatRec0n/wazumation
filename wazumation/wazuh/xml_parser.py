"""XML parsing and writing utilities for Wazuh configuration files."""

from pathlib import Path
from typing import Dict, Any, List, Optional
from lxml import etree
import xml.dom.minidom

from wazumation.wazuh.xml_sanitize import extract_first_ossec_config


class WazuhXMLParser:
    """Parser for Wazuh XML configuration files."""

    def __init__(self, config_path: Path):
        """Initialize parser."""
        self.config_path = config_path
        self.tree: Optional[etree.ElementTree] = None
        self.root: Optional[etree.Element] = None

    def parse(self) -> Dict[str, Any]:
        """Parse XML file and return structured data."""
        if not self.config_path.exists():
            return {"sections": {}}

        # Read raw file, sanitize to the first complete <ossec_config> block, then parse from memory.
        raw_text = self.config_path.read_text(encoding="utf-8", errors="replace")
        xml_text = extract_first_ossec_config(raw_text)

        # Defensive parsing: ignore comments and processing instructions, and only treat true
        # element nodes as sections/children.
        parser = etree.XMLParser(
            remove_blank_text=False,
            strip_cdata=False,
            remove_comments=True,
            remove_pis=True,
        )
        self.root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
        self.tree = etree.ElementTree(self.root)

        sections: Dict[str, Any] = {}
        for child in self.root:
            if not isinstance(child.tag, str):
                continue
            section_name = child.tag
            value = self._element_to_dict(child)
            # Preserve repeated sections (e.g., multiple <localfile> blocks) deterministically.
            if section_name in sections:
                if not isinstance(sections[section_name], list):
                    sections[section_name] = [sections[section_name]]
                sections[section_name].append(value)
            else:
                sections[section_name] = value

        return {"sections": sections, "root_attrs": dict(self.root.attrib) if self.root.attrib else {}}

    def get_section(self, section_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific section."""
        data = self.parse()
        return data["sections"].get(section_name)

    def _element_to_dict(self, element: etree.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        if element.attrib:
            result["attributes"] = dict(element.attrib)

        # Handle text content
        if element.text and element.text.strip():
            result["text"] = element.text.strip()

        # Handle children
        children = {}
        for child in element:
            if not isinstance(child.tag, str):
                continue
            child_name = child.tag
            if child_name in children:
                # Multiple children with same name -> make it a list
                if not isinstance(children[child_name], list):
                    children[child_name] = [children[child_name]]
                children[child_name].append(self._element_to_dict(child))
            else:
                children[child_name] = self._element_to_dict(child)

        if children:
            result["children"] = children

        # Handle tail text (rare but possible)
        if element.tail and element.tail.strip():
            result["tail"] = element.tail.strip()

        return result


class WazuhXMLWriter:
    """Writer for Wazuh XML configuration files."""

    def __init__(self, config_path: Path):
        """Initialize writer."""
        self.config_path = config_path

    def write(self, data: Dict[str, Any], preserve_formatting: bool = True) -> str:
        """
        Write configuration data to XML.

        Args:
            data: Dictionary with 'sections' and optionally 'root_attrs'
            preserve_formatting: Attempt to preserve original formatting (if file exists)

        Returns:
            XML content as string
        """
        root = etree.Element("ossec_config")
        if "root_attrs" in data:
            for key, value in data["root_attrs"].items():
                root.set(key, value)

        if "sections" in data:
            for section_name, section_data in data["sections"].items():
                # Support repeated sections: value may be a list of dicts.
                if isinstance(section_data, list):
                    for item in section_data:
                        section_elem = self._dict_to_element(section_name, item)
                        root.append(section_elem)
                else:
                    section_elem = self._dict_to_element(section_name, section_data)
                    root.append(section_elem)

        # Format XML nicely
        xml_string = etree.tostring(root, encoding="unicode", pretty_print=True)
        
        # Use minidom for additional formatting
        dom = xml.dom.minidom.parseString(xml_string)
        formatted_xml = dom.toprettyxml(indent="  ", encoding=None)

        # Remove empty lines
        lines = [line for line in formatted_xml.split("\n") if line.strip()]
        return "\n".join(lines)

    def _dict_to_element(self, tag: str, data: Dict[str, Any]) -> etree.Element:
        """Convert dictionary to XML element."""
        element = etree.Element(tag)

        # Set attributes
        if "attributes" in data:
            for key, value in data["attributes"].items():
                element.set(key, str(value))

        # Set text content
        if "text" in data:
            element.text = data["text"]

        # Add children
        if "children" in data:
            for child_name, child_data in data["children"].items():
                if isinstance(child_data, list):
                    for item in child_data:
                        child_elem = self._dict_to_element(child_name, item)
                        element.append(child_elem)
                else:
                    child_elem = self._dict_to_element(child_name, child_data)
                    element.append(child_elem)

        # Set tail (rare)
        if "tail" in data:
            element.tail = data["tail"]

        return element

    def update_section(self, section_name: str, section_data: Dict[str, Any]) -> str:
        """Update a single section in existing config."""
        parser = WazuhXMLParser(self.config_path)
        full_data = parser.parse()
        full_data["sections"][section_name] = section_data
        return self.write(full_data)


