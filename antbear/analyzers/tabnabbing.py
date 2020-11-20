from typing import Iterable, Optional, Union

from antbear.html import get_element_attrs, is_external_url
from antbear.http import (
    HTTPExchange,
)


class ExternalLinkMissingTabnabbingAttrs(Exception):
    pass


def sets_noopener_noreferrer_attrs_for_target_blank_external_links(
    exchange: HTTPExchange,
) -> Union[Exception, Iterable[dict[str, str]]]:
    """verifies the web checklist item:

    * Do not use `target="_blank"` in external links unless you also
      use `rel="noopener noreferrer"` (to prevent [Reverse
      Tabnabbing](https://www.owasp.org/index.php/Reverse_Tabnabbing))

    Returns a list of dicts of anchor element href, rel, and target integrity attributes:

    >>> from antbear.http import Request, Response
    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 94\\r\\n\\r\\n<!doctype html><a target="_blank" href="https://example.com/" rel="noopener noreferrer">hi</a>')))
    [{'target': '_blank', 'href': 'https://example.com/', 'rel': 'noopener noreferrer'}]

    Ignores anchor tag with non-_blank target:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 93\\r\\n\\r\\n<!doctype html><a target="_self" href="https://example.com/" rel="noopener noreferrer">hi</a>')))
    [{'target': '_self', 'href': 'https://example.com/', 'rel': 'noopener noreferrer'}]

    Ignores anchor tag without a target:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 78\\r\\n\\r\\n<!doctype html><a href="https://example.com/" rel="noopener noreferrer">hi</a>')))
    [{'href': 'https://example.com/', 'rel': 'noopener noreferrer'}]

    Ignores anchor tag with a relative href:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 83\\r\\n\\r\\n<!doctype html><a href="/foo.html" target="_blank" rel="noopener noreferrer">hi</a>')))
    [{'href': '/foo.html', 'target': '_blank', 'rel': 'noopener noreferrer'}]

    Ignores anchor tag without an href:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 66\\r\\n\\r\\n<!doctype html><a target="_blank" rel="noopener noreferrer">hi</a>')))
    [{'target': '_blank', 'rel': 'noopener noreferrer'}]

    Returns a ExternalLinkMissingTabnabbingAttrs exception for external links with missing noopener:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 79\\r\\n\\r\\n<!doctype html><a href="//example.com/" target="_blank" rel="noreferrer">hi</a>')))
    ExternalLinkMissingTabnabbingAttrs()

    Returns a ExternalLinkMissingTabnabbingAttrs exception for external links with missing noreferrer:

    >>> sets_noopener_noreferrer_attrs_for_target_blank_external_links((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 76\\r\\n\\r\\n<!doctype html><a href="//example.com/" target="_blank" rel="noopener">hi</a>')))
    ExternalLinkMissingTabnabbingAttrs()

    """
    _, res = exchange
    link_attrs = get_element_attrs(res.body, "a", {"href", "target", "rel"})

    for attrs in link_attrs:
        target = attrs.get("target", None)
        if target != "_blank":  # ignore links that don't open a new tab
            continue
        rel = attrs.get("rel", None)
        rel = set(rel.split()) if rel else set()

        href = attrs.get("href", None)
        if href and is_external_url(href):
            if "noopener" not in rel:
                return ExternalLinkMissingTabnabbingAttrs()  # href, attrs
            if "noreferrer" not in rel:
                return ExternalLinkMissingTabnabbingAttrs()  # href, attrs

    return link_attrs
