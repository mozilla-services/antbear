from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterable, Set, Tuple
import json
from urllib.parse import urlsplit
import logging

from antbear.readers.base import BaseReader
from antbear.http import Request, Response, HTTPExchange, HTTPMessage

log = logging.getLogger(__name__)


def read_har_file(path: str) -> Any:
    with open(path, "rb") as fin:
        return json.load(fin)


def get_har_log_entries(har_json: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """
    Returns the .log.entries field of tracked requests in a HAR

    http://www.softwareishard.com/blog/har-12-spec/
    """
    return har_json["log"]["entries"]


def http_from_har_entry(cls, entry) -> HTTPMessage:
    if type(cls()) is Request:
        http_packet = har_request_to_http_req(entry["request"])
    elif type(cls()) is Response:
        http_packet = har_response_to_http_res(entry["response"])
    else:
        raise NotImplementedError()

    return http_packet


def har_request_to_http_req(har_json: Dict[str, Any]) -> Request:
    """
    Convert a HAR log entry request object into an http.Request

    >>>
    """
    # TODO: set cookies and body
    # body=bytes()

    split_url = urlsplit(har_json["url"])

    req = Request(
        method=har_json["method"],
        version=har_json["httpVersion"],
        uri=split_url.path,
        queryString=split_url.query,
    )
    for header in har_json["headers"]:
        req.headers[header["name"]] = header["value"]

    # fragment is not transmitted, so we won't have it for pcaps
    req.fragment = split_url.fragment

    # TODO: add 'serverIPAddress' and 'connection' to IP layer
    return req


def har_response_to_http_res(har_json: Dict[str, Any]) -> Response:
    """
    Convert a HAR log entry request object into an http.Response

    """
    # TODO: set cookies
    req = Response(
        status=har_json["status"],
        version=har_json["httpVersion"],
        body=har_json["content"]["text"] if "text" in har_json["content"] else None,
    )
    for header in har_json["headers"]:
        req.headers[header["name"]] = header["value"]

    # TODO: add 'serverIPAddress' and 'connection' to IP layer
    return req


class HARReader(BaseReader):
    """
    Reader for HTTP Archive files

    https://en.wikipedia.org/wiki/HAR_(file_format)
    http://www.softwareishard.com/blog/har-12-spec/
    """

    @staticmethod
    def file_suffixes() -> Set[str]:
        return {"har"}

    @staticmethod
    def read_path(
        file_path: str,
    ) -> Generator[Tuple[datetime, HTTPMessage], None, None]:
        """
        Loads a HAR file, parses a JSON dict from it, and returns http
        messages from the log entries

        """
        log.debug(f"reading {file_path}")
        for entry in get_har_log_entries(read_har_file(file_path)):
            start_time = datetime.fromisoformat(entry["startedDateTime"]).astimezone(
                timezone.utc
            )
            req = http_from_har_entry(Request, entry)
            res = http_from_har_entry(Response, entry)
            res.answers = req
            yield start_time, req
            yield start_time, res

    @staticmethod
    def can_convert(input_type: Any, output_type: Any) -> bool:
        return False
