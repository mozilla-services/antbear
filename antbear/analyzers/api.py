import re
from typing import Optional, Tuple, Union

from antbear.analyzers.base import BaseAnalyzer
from antbear.http import (
    Request,
    Response,
    get_normalized_content_type,
    has_unique_header_keys,
)


class MissingContentTypeHeader(Exception):
    """"""

    pass


class HTMLContentTypeHeader(Exception):
    """"""

    # def __init__(self, content_type: str) -> None:
    #     super().__init__(self)
    #     self.content_type = content_type

    pass


class InvalidOpenAPISpec(Exception):
    """"""

    pass


class OpenAPISpecErrored(Exception):
    """"""

    pass


class MissingAuthHeader(Exception):
    """"""

    pass


class NonBearerAuthHeader(Exception):
    """"""

    pass


class NonScannableAuthToken(Exception):
    """"""

    # def __init__(self, token: str) -> None:
    #     super().__init__(self)
    #     self.token = token

    pass


InvalidAPIContentType = Union[MissingContentTypeHeader, HTMLContentTypeHeader]

AuthHeaderException = Union[
    MissingAuthHeader,
    NonBearerAuthHeader,
]


class NonHTMLHTTPResponseContentType(BaseAnalyzer):
    r"""
    verifies the web checklist item for APIs:

    * MUST set a non-HTML or XHTML content-type on all responses, including 300s, 400s and 500s

    >>> from antbear.http import Request, Response, response_with_answer
    >>> analyzer = NonHTMLHTTPResponseContentType({"api_uri": "/api"})

    Requires a response answering a request to the API URI:

    >>> analyzer.can_analyze(Response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json"))
    False
    >>> analyzer.can_analyze(response_with_answer(Request(b"GET /not-api HTTP/1.1"), Response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json")))
    False
    >>> analyzer.can_analyze(response_with_answer(Request(b"GET /api/v1 HTTP/1.1"), Response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json")))
    True

    Returns the valid non-HTML or XHTML content-type:

    >>> analyzer.analyze(response_with_answer(Request(b"GET /api/v1 HTTP/1.1"), Response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json")))
    'application/json'

    Returns a MissingContentTypeHeader exception when a content type header isn't found:

    >>> analyzer.analyze(response_with_answer(Response(b"HTTP/1.1 200 OK"), Request(b"GET /api/v1 HTTP/1.1")))
    MissingContentTypeHeader()

    Returns an HTMLContentTypeHeader exception for invalid HTML content types:

    >>> analyzer.analyze(response_with_answer(Request(b"GET /api/v1 HTTP/1.1"), Response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html")))
    HTMLContentTypeHeader()

    >>> analyzer.analyze(response_with_answer(Request(b"GET /api/v1 HTTP/1.1"), Response(b"HTTP/1.1 200 OK\r\nContent-Type: application/xhtml+xml")))
    HTMLContentTypeHeader()
    """

    input_type = Response
    output_types = [str, MissingContentTypeHeader, HTMLContentTypeHeader]

    def __init__(self, config):
        self.api_uri = config["api_uri"]

    def __str__(self) -> str:
        return "API responses set non-HTML Content-Type header"

    def can_analyze(self, data) -> bool:
        return (
            isinstance(data, Response)
            and hasattr(data, "answers")
            and data.answers.uri.startswith(self.api_uri)
        )

    def analyze(
        self,
        response: Response,
    ) -> Union[InvalidAPIContentType, str]:
        has_unique_header_keys(response)
        content_type = get_normalized_content_type(response)
        if content_type is None:
            return MissingContentTypeHeader()

        elif content_type.startswith("text/html") or content_type.startswith(
            "application/xhtml+xml"
        ):
            return HTMLContentTypeHeader()  # content_type=content_type)
        return content_type


class ScannableAuthorizationHeaderBearerToken(BaseAnalyzer):
    r"""
    verifies the web checklist item for APIs:

    * SHOULD use authentication tokens with a unique pattern which is easily parsed with a regexp. This should allow inclusion into a token scanning service in the future. (E.g. prefix `mgp-` + 20 hex digits would match the regexp `\bmgp-[0-9A-Fa-f]{20}\b`)

    >>> from antbear.http import Request, Response, response_with_answer

    >>> uses_scannable_authentication_token((Request(b"GET /"), Response()), r"^foo-[0-9]{1,10}$")
    MissingAuthHeader()

    >>> uses_scannable_authentication_token(
    ...     (Request(b'GET / HTTP/1.1\r\nAuthorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'), Response()),
    ...     r"^foo-[0-9]{1,10}$"
    ... )
    NonBearerAuthHeader()

    >>> uses_scannable_authentication_token(
    ...     (Request(b'GET / HTTP/1.1\r\nAuthorization: Bearer 3'), Response()),
    ...     r"^foo-[0-9]{1,10}$"
    ... )
    NonScannableAuthToken()

    >>> uses_scannable_authentication_token(
    ...     (Request(b'GET / HTTP/1.1\r\nAuthorization: Bearer foo-3'), Response()),
    ...     r"^foo-[0-9]{1,10}$"
    ... )
    'foo-3'
    """

    input_type = Request
    output_types = [str, MissingAuthHeader, NonBearerAuthHeader, NonScannableAuthToken]

    def __init__(self, config):
        self.token_regex = config["token_regex"]

    def __str__(self) -> str:
        return "API requests use a scannable bearer Authorization header"

    def can_analyze(self, data) -> bool:
        return isinstance(data, Request)

    def analyze(
        self,
        request: Request,
    ) -> Union[AuthHeaderException, str]:
        has_unique_header_keys(request)
        auth = request.authorization()
        # NB: returns None for authorization without a type too
        if auth is None:
            return MissingAuthHeader()

        auth_type, auth_info = auth
        if auth_type != "bearer":
            return NonBearerAuthHeader()

        bearer_token = auth_info
        if not re.fullmatch(self.token_regex, bearer_token):
            return NonScannableAuthToken()  # token=bearer_token)
        return bearer_token


class ReturnsOpenAPISpec(BaseAnalyzer):
    """verifies the web checklist item for APIs:

    * SHOULD export an OpenAPI (Swagger) to facilitate automated vulnerability tests

    Does not parse or validate the spec.

    Returns the HTTP exchange when an openapi_uri is provided and an
    request to the openapi URI receives an HTTP 2XX response:

    >>> from antbear.http import Request, Response

    >>> returns_an_openapi_spec((Request(b"GET /api/spec HTTP/1.1"), Response(b"HTTP/1.1 200 OK")), "/api/spec")
    (Request(version='1.1', method='GET', uri='/api/spec', headers=OrderedDict(), body=b'', data=b''), Response(version='1.1', status='200', reason='OK', headers=OrderedDict(), body=b'', data=b''))

    Returns an InvalidOpenAPISpec exception when the HTTP exchange does not match the openapi_uri:

    >>> returns_an_openapi_spec((Request(b"GET /api/not-spec"), Response(b"HTTP/1.1 400 BAD REQUEST")), "/api/spec")
    InvalidOpenAPISpec()

    Returns an OpenAPISpecErrored exception when the openapi_uri receives an error HTTP status:

    >>> returns_an_openapi_spec((Request(b"GET /api/spec"), Response(b"HTTP/1.1 400 BAD REQUEST")), "/api/spec")
    OpenAPISpecErrored()

    """

    input_type = Response
    output_types = [Response, OpenAPISpecErrored, InvalidOpenAPISpec]

    def __init__(self, config):
        self.api_uri = config["api_uri"]

    def __str__(self) -> str:
        return "API exports an OpenAPI (Swagger) spec"

    def can_analyze(self, data) -> bool:
        return (
            isinstance(data, Response)
            and hasattr(data, "answers")
            and data.answers.uri.startswith(self.api_uri)
        )

    def analyze(
        response: Response,
        openapi_uri: Optional[str],
    ) -> Union[Exception, Response]:
        request = response.answers

        if request.uri != openapi_uri:
            return InvalidOpenAPISpec()

        if 200 < int(response.status) or int(response.status) >= 300:
            return OpenAPISpecErrored()
        return response
