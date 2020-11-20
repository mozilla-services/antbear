from typing import Iterable, Tuple

import html.parser
import urllib.parse


class ElementAttrParser(html.parser.HTMLParser):
    def __init__(self, element_name: str, attrs_to_save: set[str]):
        super().__init__()

        self.element_name = element_name
        self.attrs_to_save = attrs_to_save
        self.element_attrs = []

    def handle_starttag(self, tag: str, attrs: Iterable[Tuple[str, str]]):
        if tag != self.element_name:
            return None

        self.element_attrs.append(
            {
                attr_name: attr_value
                for (attr_name, attr_value) in attrs
                if attr_name in self.attrs_to_save
            }
        )


def get_element_attrs(
    html_document: str, element: str, attrs: set[str]
) -> Iterable[dict[str, str]]:
    parser = ElementAttrParser(element, attrs_to_save=attrs)
    parser.feed(str(html_document))
    return parser.element_attrs


def is_external_url(src: str) -> bool:
    scheme, netloc, *_ = urllib.parse.urlsplit(src)
    if src.startswith("//") or netloc:
        return True
    else:
        return False
