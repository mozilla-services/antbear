from typing import Any, Dict, Generator, Iterable, Optional, Tuple, Union
import logging

import dpkt
import dpkt.http
import werkzeug.http


log = logging.getLogger(__name__)


class AuthMixin:
    def authorization(self) -> Optional[Tuple[str, str]]:
        for header_key, header_value in self.headers.items():
            if header_key.lower() == "authorization":
                try:
                    auth_type, auth_info = header_value.split(None, 1)
                    auth_type = auth_type.lower()
                except ValueError:
                    return None
                return auth_type, auth_info
        return None


class CookiesMixin:
    def cookies(self) -> Iterable[werkzeug.datastructures.MultiDict[str, str]]:
        return [
            werkzeug.http.parse_cookie(header_value)
            for (header_name, header_value) in self.headers.items()
            if header_name.lower() == "set-cookie"
        ]


class Request(AuthMixin, CookiesMixin, dpkt.http.Request):
    __slots__ = ("fragment", "packets")


class Response(AuthMixin, CookiesMixin, dpkt.http.Response):
    __slots__ = ("answers", "packets")


# types


HTTPMessage = Union[Request, Response]
HTTPExchange = Tuple[Request, Response]


# helpers


def response_with_answer(request: Request, response: Response):
    response.answers = request
    return response


def get_downcased_headers(http_packet: HTTPMessage) -> dpkt.http.OrderedDict:
    return dpkt.http.OrderedDict(
        [(key.lower(), value) for key, value in http_packet.headers.items()]
    )


def has_unique_header_keys(http_packet: HTTPMessage) -> Optional[Exception]:
    # exclude duplicate headers with various or mixed cases
    # TODO: extract to separate check with exceptions
    # TODO: check header sizes match (i.e. don't combine things in headers)
    assert len(http_packet.headers.keys()) == len(set(http_packet.headers.keys()))
    assert len(http_packet.headers.keys()) == len(get_downcased_headers(http_packet))
    return None


def get_normalized_content_type(http_packet: HTTPMessage) -> Optional[str]:
    # TODO: subclass dpkt and more to a subclass of it
    # TODO: use werkzeug.http.parse_options_header e.g.
    # >>> parse_options_header('text/html; charset=utf8')
    # ('text/html', {'charset': 'utf8'})

    downcased_headers = get_downcased_headers(http_packet)
    content_type = downcased_headers.get("content-type", None)
    assert isinstance(content_type, str) or content_type is None
    return content_type


def cookie_has_flag(
    cookie: werkzeug.datastructures.MultiDict[str, str], flag_values=Iterable[str]
) -> bool:
    return any(flag_value in cookie for flag_value in flag_values)


def cookie_has_prefix(
    cookie: werkzeug.datastructures.MultiDict[str, str], prefix=str
) -> bool:
    return next(cookie.items())[0].startswith(prefix)


def get_requst_src_dest(request: Request) -> Optional[Tuple[str, str]]:
    src = request.headers.get("Origin", None)
    if src is None:
        log.info(f"could not find an origin for HTTP Request {request}")
        return None
    dest = request.headers.get("Host", None)
    if dest is None:
        log.info(f"could not find an destination host for HTTP Request {request}")
        return None
    return src, dest
