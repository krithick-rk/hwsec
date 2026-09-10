from lxml import etree


class XMLRepository:
    def __init__(self, xml_path):
        self.tree = etree.parse(xml_path)
        self.root = self.tree.getroot()

    def find_single(self, xpath):
        results = self.root.xpath(xpath)
        if results:
            return self._element_to_dict(results[0])
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
