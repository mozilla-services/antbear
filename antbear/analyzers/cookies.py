"""
websec checklist items for
[Cookies](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies)
"""

from typing import Iterable, Optional, Union

from antbear.http import HTTPExchange, cookie_has_flag, cookie_has_prefix


class MissingCookieFlag(Exception):
    def __init__(self, description: str = ""):
        self.description = description


class MissingCookiePrefix(Exception):
    def __init__(self, description: str = ""):
        self.description = description


def sets_secure_flag_on_cookies(
    exchange: HTTPExchange,
) -> Union[Exception, Iterable[dict[str, str]]]:
    """verifies the web checklist item for [Cookies](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies):

    * MUST set the Secure flag

    >>> from antbear.http import Request, Response
    >>> sets_secure_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8; Secure')))
    [MultiDict([('sessionId', '38afes7a8'), ('Secure', '')])]

    >>> sets_secure_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8; secure')))
    MissingCookieFlag()

    >>> sets_secure_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8; Insecure')))
    MissingCookieFlag()

    >>> sets_secure_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8')))
    MissingCookieFlag()

    """
    _, res = exchange
    insecure_cookies = [
        cookie for cookie in res.cookies() if not cookie_has_flag(cookie, {"Secure"})
    ]
    if insecure_cookies:
        return MissingCookieFlag()  # flag_name="Secure", insecure_cookies

    return res.cookies()


def sets_httponly_flag_on_cookies(exchange: HTTPExchange) -> Union[Exception, str]:
    """verifies the web checklist item for [Cookies](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies):

    * MUST set the HTTPOnly flag

    >>> from antbear.http import Request, Response
    >>> sets_httponly_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8; HttpOnly')))
    [MultiDict([('sessionId', '38afes7a8'), ('HttpOnly', '')])]

    >>> sets_httponly_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8; httponly')))
    MissingCookieFlag()

    >>> sets_httponly_flag_on_cookies((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8')))
    MissingCookieFlag()

    """
    _, res = exchange
    non_http_cookies = [
        cookie for cookie in res.cookies() if not cookie_has_flag(cookie, {"HttpOnly"})
    ]
    if non_http_cookies:
        return MissingCookieFlag()  # flag_name="HttpOnly", non_http_cookies

    return res.cookies()


def sets_cookies_with_host_prefix_name(exchange: HTTPExchange) -> Union[Exception, str]:
    """verifies the web checklist item for [Cookies](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies):

    * MUST use the prefix `__Host-` for the cookie name


    >>> from antbear.http import Request, Response
    >>> sets_cookies_with_host_prefix_name((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: __Host-sessionId=38afes7a8')))
    [MultiDict([('__Host-sessionId', '38afes7a8')])]

    >>> sets_cookies_with_host_prefix_name((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: __host-sessionId=38afes7a8')))
    MissingCookiePrefix()

    >>> sets_cookies_with_host_prefix_name((Request(), Response(b'HTTP/1.1 200 OK\\r\\nSet-Cookie: sessionId=38afes7a8')))
    MissingCookiePrefix()

    """
    _, res = exchange
    non_host_cookies = [
        cookie for cookie in res.cookies() if not cookie_has_prefix(cookie, "__Host-")
    ]
    if non_host_cookies:
        return MissingCookiePrefix()  # prefix=__Host-, cookies

    return res.cookies()
