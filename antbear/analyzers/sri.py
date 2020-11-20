from typing import Iterable, Optional, Union

from antbear.html import get_element_attrs, is_external_url
from antbear.http import (
    HTTPExchange,
)


class MissingSubresourceIntegrityForThirdPartyScript(Exception):
    """"""

    pass


def pins_third_party_js_with_subresource_integrity(
    exchange: HTTPExchange,
) -> Union[Exception, Iterable[dict[str, str]]]:
    """verifies the web checklist item:

    * third-party javascript MUST be pinned to specific versions using [Subresource Integrity (SRI)](https://infosec.mozilla.org/guidelines/web_security#subresource-integrity)

    Returns a list of dicts of third party script src and integrity attributes:

    >>> from antbear.http import Request, Response
    >>> pins_third_party_js_with_subresource_integrity((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 154\\r\\n\\r\\n<!doctype html><script src="https://example.com/example-framework.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC">')))
    [{'src': 'https://example.com/example-framework.js', 'integrity': 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'}]

    Ignores inline scripts:

    >>> pins_third_party_js_with_subresource_integrity((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 32\\r\\n\\r\\n<!doctype html><script></script>')))
    [{}]

    Ignores first-party scripts:

    >>> pins_third_party_js_with_subresource_integrity((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 54\\r\\n\\r\\n<!doctype html><script src="/static/site.js"></script>')))
    [{'src': '/static/site.js'}]

    Returns a MissingSubresourceIntegrityForThirdPartyScript exception
    for missing SRI attr on third-party scripts:

    >>> pins_third_party_js_with_subresource_integrity((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 72\\r\\n\\r\\n<!doctype html><script src="http://example.com/static/site.js"></script>')))
    MissingSubresourceIntegrityForThirdPartyScript()

    Returns a MissingSubresourceIntegrityForThirdPartyScript exception
    for missing SRI attr on third-party scripts with implicit schema:

    >>> pins_third_party_js_with_subresource_integrity((Request(b"GET /api/v1 HTTP/1.1"), Response(b'HTTP/1.1 200 OK\\r\\nContent-Length: 67\\r\\n\\r\\n<!doctype html><script src="//example.com/static/site.js"></script>')))
    MissingSubresourceIntegrityForThirdPartyScript()

    """
    _, res = exchange
    scripts_attrs = get_element_attrs(res.body, "script", {"src", "integrity"})
    for attrs in scripts_attrs:
        src = attrs.get("src", None)
        if src is None:  # ignore inline scripts
            continue

        if attrs.get("integrity", None) is None and is_external_url(src):
            return MissingSubresourceIntegrityForThirdPartyScript()  # src=src

    return scripts_attrs
