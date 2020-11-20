import io
import re
import struct
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Generator, Iterable, Optional, Set, Tuple, Union
import logging

import dpkt
import scapy
import scapy.plist
import scapy.sendrecv
from scapy.all import sniff
import scapy.layers.inet
import scapy.packet

from antbear.readers.base import BaseReader
from antbear.http import Request, Response, HTTPExchange, HTTPMessage

import logging


log = logging.getLogger(__name__)


r"""
HTTP <=1.1 layer.

>>> from scapy.compat import raw

# >>> Request(b'GET /bar')
# <Request  method='GET' uri='/bar' version='0.9' |>
# >>> Request(b'GET /bar HTTP/1.0')
# <Request  method='GET' uri='/bar' version='1.0' |>
# >>> Request(b'GET /bar HTTP/1.1')
# <Request  method='GET' uri='/bar' version='1.1' |>
# >>> Request(b'GET /bar HTTP/1.1\r\nAuthorization: foo').headers
# OrderedDict([('authorization', 'foo')])

>>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_parse_request
>>> s = b'''POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\nReferer: http://www.email.com/login/snap/login.jhtml\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\nHost: ltd.snap.com\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\nContent-type: application/x-www-form-urlencoded\r\nContent-length: 61\r\n\r\nsn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'''
# >>> r = Request(s)
# >>> r.method
# b'POST'
# >>> r.uri
# b'/main/redirect/ab/1,295,,00.html'
# >>> r.body
# b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
# >>> r.headers['content-type']
# 'application/x-www-form-urlencoded'

# >>> Response(b'')
# <Response  |>
# >>> r = Response(b'HTTP/1.1 200 OK\r\n')
# >>> r
# <Response  version='1.1' status='200' reason='OK' |>
# >>> r.version
# b'1.1'
# >>> r.status
# b'200'
# >>> r.reason
# b'OK'

# >>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_noreason_response
# >>> r = Response(b'''HTTP/1.1 200 \r\n\r\n''')
# >>> r
# <Response  version='1.1' status='200' reason='' |>
# >>> r.reason
# b''

# >>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_response_with_body
# >>> r = Response(b'HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nfoo')
# >>> r.body
# b'foo'

# >>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_multicookie_response
# >>> s = b'''HTTP/1.x 200 OK\r\nSet-Cookie: first_cookie=cookie1; path=/; domain=.example.com\r\nSet-Cookie: second_cookie=cookie2; path=/; domain=.example.com\r\nContent-Length: 0\r\n\r\n'''
# >>> r = Response(s)
# >>> type(r.headers['set-cookie'])
# <class 'list'>
# >>> len(r.headers['set-cookie'])
# 2

# >>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_body_forbidden_response
# >>> s = b'HTTP/1.1 304 Not Modified\r\n'\
# ...         b'Content-Type: text/css\r\n'\
# ...         b'Last-Modified: Wed, 14 Jan 2009 16:42:11 GMT\r\n'\
# ...         b'ETag: "3a7-496e15e3"\r\n'\
# ...         b'Cache-Control: private, max-age=414295\r\n'\
# ...         b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
# ...         b'Connection: keep-alive\r\n'\
# ...         b'Vary: Accept-Encoding\r\n\r\n'\
# ...         b'HTTP/1.1 200 OK\r\n'\
# ...         b'Server: Sun-ONE-Web-Server/6.1\r\n'\
# ...         b'Content-length: 257\r\n'\
# ...         b'Content-Type: application/x-javascript\r\n'\
# ...         b'Last-Modified: Wed, 06 Jan 2010 19:34:06 GMT\r\n'\
# ...         b'ETag: "101-4b44e5ae"\r\n'\
# ...         b'Accept-Ranges: bytes\r\n'\
# ...         b'Content-Encoding: gzip\r\n'\
# ...         b'Cache-Control: private, max-age=439726\r\n'\
# ...         b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
# ...         b'Connection: keep-alive\r\n'\
# ...         b'Vary: Accept-Encoding\r\n'
# >>> result = []
# >>> msg = Response(s)
# >>> s = msg.data
# >>> result.append(msg)
# >>>
# >>> # the second HTTP response should be an standalone message
# >>> assert len(result) == 2

# >>> # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html#test_chunked_response
# >>> s = b'''HTTP/1.1 200 OK\r\nCache-control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/javascript; charset=utf-8\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nSet-Cookie: S=gmail=agg:gmail_yj=v2s:gmproxy=JkU; Domain=.google.com; Path=/\r\nServer: GFE/1.3\r\nDate: Mon, 12 Dec 2005 22:33:23 GMT\r\n\r\na\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00\r\n152\r\nm\x91MO\xc4 \x10\x86\xef\xfe\n\x82\xc9\x9eXJK\xe9\xb6\xee\xc1\xe8\x1e6\x9e4\xf1\xe0a5\x86R\xda\x12Yh\x80\xba\xfa\xef\x85\xee\x1a/\xf21\x99\x0c\xef0<\xc3\x81\xa0\xc3\x01\xe6\x10\xc1<\xa7eYT5\xa1\xa4\xac\xe1\xdb\x15:\xa4\x9d\x0c\xfa5K\x00\xf6.\xaa\xeb\x86\xd5y\xcdHY\x954\x8e\xbc*h\x8c\x8e!L7Y\xe6\'\xeb\x82WZ\xcf>8\x1ed\x87\x851X\xd8c\xe6\xbc\x17Z\x89\x8f\xac \x84e\xde\n!]\x96\x17i\xb5\x02{{\xc2z0\x1e\x0f#7\x9cw3v\x992\x9d\xfc\xc2c8\xea[/EP\xd6\xbc\xce\x84\xd0\xce\xab\xf7`\'\x1f\xacS\xd2\xc7\xd2\xfb\x94\x02N\xdc\x04\x0f\xee\xba\x19X\x03TtW\xd7\xb4\xd9\x92\n\xbcX\xa7;\xb0\x9b\'\x10$?F\xfd\xf3CzPt\x8aU\xef\xb8\xc8\x8b-\x18\xed\xec<\xe0\x83\x85\x08!\xf8"[\xb0\xd3j\x82h\x93\xb8\xcf\xd8\x9b\xba\xda\xd0\x92\x14\xa4a\rc\reM\xfd\x87=X;h\xd9j;\xe0db\x17\xc2\x02\xbd\xb0F\xc2in#\xfb:\xb6\xc4x\x15\xd6\x9f\x8a\xaf\xcf)\x0b^\xbc\xe7i\x11\x80\x8b\x00D\x01\xd8/\x82x\xf6\xd8\xf7J(\xae/\x11p\x1f+\xc4p\t:\xfe\xfd\xdf\xa3Y\xfa\xae4\x7f\x00\xc5\xa5\x95\xa1\xe2\x01\x00\x00\r\n0\r\n\r\n'''
# >>> r = Response(s)
# <Response  |>

"""


class HTTP(scapy.packet.Packet):
    """
    General HTTP class + TCP session defragmentation
    """

    name = "HTTP 1"
    fields_desc = []
    show_indent = 0

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        """
        Used by TCPSession in session.py to defragment HTTP requests and
        responses from TCP sessions
        """
        # dpkt.http expects a io.BytesIO file interface, but doesn't reconstruct TCP sessions

        # TODO: remove http1.Request and Response instead pass to dpkt.http to produce HTTP packets

        # Since HTTP messages can span multiple packets, we won't turn http1.Request into http.Request, Response

        # assert isinstance(metadata['pay_class'], HTTP)
        # f = io.BytesIO(s)

        # dpkt.UnpackError
        log.warn(f"guessing {type(http_packet.payload)} for\n{data}")
        raise Exception()

        # http_packet.payload
        return HTTP(data)

        if not detect_end or is_unknown:
            metadata["detect_unknown"] = False
            http_packet = HTTP(data)

    def guess_payload_class(self, payload):
        """Decides if the payload is an HTTP Request or Response, or something else."""
        try:
            prog = re.compile(
                br"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                br"(?:.+?) "
                br"HTTP/\d\.\d$"
            )
            crlfIndex = payload.index(b"\r\n")
            req = payload[:crlfIndex]
            result = prog.match(req)
            if result:
                return Request
            else:
                prog = re.compile(br"^HTTP/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return Response
        except ValueError:
            # Anything that isn't HTTP but on port 80
            pass
        return scapy.packet.Raw


class PCAPReader(BaseReader):
    """
    Reader for packet capture files

    https://en.wikipedia.org/wiki/Pcap
    """

    @staticmethod
    def file_suffixes() -> Set[str]:
        return {"pcap"}

    @staticmethod
    def read_path(
        file_path: str,
    ) -> Generator[Tuple[datetime, scapy.plist.PacketList], None, None]:
        """
        Loads a packet capture from a pcap file path and returns the scapy
        PacketList with TCP sessions
        """
        log.debug(f"reading {file_path}")
        # scapy.packet.bind_layers(scapy.layers.inet.TCP, HTTP)
        for packet in scapy.sendrecv.sniff(
            offline=file_path, session=scapy.sessions.TCPSession
        ):
            # breakpoint()
            # layers = packet.layers()
            # if not len(layers):
            #     return Exception("Packet has no layers")

            # highest_layer = layers[-1]
            # print("read packet type {packet} with layer {highest_layer}")
            # # NB: we just have recv times https://wiki.wireshark.org/Timestamps
            yield datetime.fromtimestamp(packet.time, tz=timezone.utc), packet

    @staticmethod
    def can_convert(input_type: Any, output_type: Any) -> bool:
        if issubclass(input_type, scapy.plist.Packet) and output_type in [
            Request,
            Response,
        ]:
            return True

        log.warn(f"PCAPReader cannot convert a {input_type} to a {output_type}")
        return False

    @staticmethod
    def convert(packet, data_type) -> Union[HTTPMessage, Exception]:
        layers = packet.layers()
        if not len(layers):
            return Exception("Packet has no layers")
        highest_layer = layers[-1]
        http_packet = packet.getlayer(highest_layer)
        # log.info(f"have highest_layer {highest_layer} for {http_packet}")
        # breakpoint()
        if highest_layer is Request:
            return
        elif highest_layer is Response:
            return
        else:
            return Exception("Packet does not have an http1 layer")
