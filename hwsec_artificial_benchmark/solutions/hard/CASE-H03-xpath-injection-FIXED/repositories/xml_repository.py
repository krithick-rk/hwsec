from lxml import etree


class XMLRepository:
    def __init__(self, xml_path):
        self.tree = etree.parse(xml_path)
        self.root = self.tree.getroot()

    def find_by_field(self, field_name, value):
        for user_elem in self.root.findall('.//user'):
            field_elem = user_elem.find(field_name)
            if field_elem is not None and field_elem.text == value:
                return self._element_to_dict(user_elem)
        return None

    def find_by_id(self, user_id):
        user_elem = self.root.find(f'.//user[@id="{int(user_id)}"]')
        if user_elem is not None:
            return self._element_to_dict(user_elem)
        return None

    def find_all(self):
        elements = self.root.findall('.//user')
        return [self._element_to_dict(e) for e in elements]

    def _element_to_dict(self, element):
        data = {}
        for child in element:
            data[child.tag] = child.text
        data['id'] = element.get('id')
        return data
