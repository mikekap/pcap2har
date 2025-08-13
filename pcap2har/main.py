#!/usr/bin/env python3
"""Main entry point for pcap2har."""

from dataclasses import dataclass, field
import datetime
from functools import total_ordering
import gzip
import json
import sys
from typing import Optional

from pyshark.capture.capture import Packet
import click
import base64
from pathlib import Path
import pyshark
from collections import defaultdict
import brotli
from . import __version__
import tqdm


@total_ordering
class CaseInsensitiveString(str):
    def __eq__(self, o):
        return self.casefold() == o.casefold()

    def __lt__(self, o):
        return self.casefold() < o.casefold()

    def __hash__(self) -> int:
        return hash(self.casefold())


@dataclass(slots=True, frozen=False)
class HttpRequest:
    method: str = ""
    httpVersion: str = ""
    url: str = ""
    headers: dict[str, list[str]] = field(
        default_factory=lambda: defaultdict(lambda: [])
    )
    startTimestamp: Optional[int] = None
    endTimestamp: int = 0
    headersSize: int = 0
    body: bytes = b""


@dataclass(slots=True, frozen=False)
class HttpResponse:
    status: int = 0
    statusText: str = ""
    httpVersion: str = ""
    headers: dict[str, list[str]] = field(
        default_factory=lambda: defaultdict(lambda: [])
    )
    startTimestamp: Optional[int] = None
    endTimestamp: int = 0
    headersSize: int = 0
    body: bytes = b""
    compressionSaved: int = 0


@dataclass(slots=True)
class WebsocketMessage:
    type: str = "send"
    time: int = 0
    opcode: int = 0
    data: bytes = b""
    data_text: str = ""


@dataclass(slots=True)
class HttpSession:
    remoteAddress: str = ""
    request: HttpRequest = field(default_factory=lambda: HttpRequest())
    response: HttpResponse = field(default_factory=lambda: HttpResponse())
    websocketMessages: list[WebsocketMessage] = field(default_factory=list)
    maxPacketTs: int = 0

    packets: list[Packet] = field(default_factory=list)


@click.command()
@click.version_option(__version__)
@click.argument("pcap_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(), help="Output HAR file path")
@click.option("--pretty/--no-pretty", help="Pretty print the json")
def main(pcap_file: Path, output: str = None, pretty=False):
    """Convert PCAP file to HAR format."""
    click.echo(f"Processing PCAP file: {pcap_file}", err=True)

    conv_details = read_pcap_file(pcap_file)
    if output:
        output_path = Path(output)
    else:
        output_path = pcap_file.with_suffix(".har")

    js = to_har_json(conv_details, comment=f"From {pcap_file}")

    click.echo(f"Output will be written to: {output_path}", err=True)
    with open(output_path, "w") as fp:
        if pretty:
            json.dump(js, fp, sort_keys=True, indent=2)
        else:
            json.dump(js, fp)


def read_pcap_file(pcap_file):
    file = pyshark.FileCapture(
        pcap_file,
        display_filter="http || http2 || http3 || websocket",
        keep_packets=False,
        override_prefs={
            "http.decompress_body": "FALSE",
            "http2.decompress_body": "FALSE",
        },
        tshark_path="/Users/mikekap/Projects/wireshark/build/run/Wireshark.app/Contents/MacOS/tshark",
    )

    conv_details = defaultdict(HttpSession)

    def unnest(p):
        return ((l, p) for l in p.layers)

    for layer, packet in (x for p in tqdm.tqdm(file) for x in unnest(p)):
        packet: pyshark.Packet = packet

        if layer.layer_name == "http3":
            stream_id = layer.get_field("frame_streamid")
            if not stream_id:
                continue
            full_stream_id = ("3", packet.quic.connection_number, stream_id)
            port = packet.udp.dstport
            http_version = "HTTP/3"
        elif layer.layer_name == "http2":
            if layer.get_field("streamid") == "0" or layer.stream == "Stream: Magic":
                continue
            full_stream_id = ("2", packet.tcp.stream, layer.streamid)
            port = packet.tcp.dstport
            http_version = "HTTP/2"
        elif layer.layer_name == "http":
            full_stream_id = ("1", packet.tcp.stream)
            port = packet.tcp.dstport
            http_version = "HTTP/1"
        elif layer.layer_name == "websocket":
            full_stream_id = ("1", packet.tcp.stream)
            port = packet.tcp.dstport
        else:
            continue

        match str(packet.frame_info.get_field("p2p_dir")):
            case "0":
                direction = "send"
            case "1":
                direction = "recv"
            case _:
                if conv_details[full_stream_id].remoteAddress:
                    direction = (
                        "send"
                        if f'{packet.ip.dst}:{port}'
                        == conv_details[full_stream_id].remoteAddress
                        else "recv"
                    )
                else:
                    direction = "send"

        timestamp = float(str(packet.frame_info.time_epoch))
        my_conv_details = (
            conv_details[full_stream_id].request
            if direction == "send"
            else conv_details[full_stream_id].response
        )
        has_something = False

        if packet not in conv_details[full_stream_id].packets:
            conv_details[full_stream_id].packets.append(packet)
        if direction == "send":
            conv_details[full_stream_id].remoteAddress = f'{packet.ip.dst}:{port}'

        if layer.layer_name == "websocket":
            message = WebsocketMessage()
            message.type = {"send": "send", "recv": "receive"}[direction]
            message.time = timestamp
            message.opcode = layer.opcode.hex_value
            # if text_data := layer.get_field('')
            # message.data_text =
            if payload := layer.get_field("payload"):
                message.data += payload.binary_value

            conv_details[full_stream_id].websocketMessages.append(message)

            conv_details[full_stream_id].maxPacketTs = timestamp
            continue

        if header := layer.get_field("request_line"):
            has_something = True

            if my_conv_details.startTimestamp is None:
                my_conv_details.startTimestamp = timestamp

            my_conv_details.httpVersion = layer.request_version

            headersLen = 0
            headers = my_conv_details.headers
            for header in header.all_fields:
                headers[CaseInsensitiveString(header.showname_key.strip())].append(
                    maybe_strip_suffix(header.showname_value.strip(), "\\r\\n")
                )
                headersLen += len(str(header))
            my_conv_details.headersSize += headersLen

            if full_uri := layer.get_field("request_full_uri"):
                if isinstance(my_conv_details, HttpRequest):
                    my_conv_details.url = full_uri
            if method := layer.get_field("request_method"):
                my_conv_details.method = method

        if header := layer.get_field("response_line"):
            has_something = True

            my_conv_details.httpVersion = layer.response_version
            headersLen = 0
            headers = my_conv_details.headers
            for header in header.all_fields:
                headers[CaseInsensitiveString(header.showname_key.strip())].append(
                    maybe_strip_suffix(header.showname_value.strip(), "\\r\\n")
                )
                headersLen += len(str(header))
            my_conv_details.headersSize += headersLen

            my_conv_details.status = int(str(layer.response_code))
            my_conv_details.statusText = layer.response_code_desc

        if header := layer.get_field("header") or layer.get_field("headers_header"):
            has_something = True

            if my_conv_details.startTimestamp is None:
                my_conv_details.startTimestamp = timestamp

            my_conv_details.httpVersion = http_version

            headers = my_conv_details.headers
            for header in header.all_fields:
                name, value = header.showname_value.split(": ", 1)
                headers[CaseInsensitiveString(name.strip())].append(value.strip())

            my_conv_details.headersSize += int(
                layer.get_field("header_length")
                or layer.get_field("headers_decoded_length")
            )
            if full_uri := layer.get_field("request_full_uri"):
                if isinstance(my_conv_details, HttpRequest):
                    my_conv_details.url = full_uri
            if method := layer.get_field("request_method") or layer.get_field(
                "headers_method"
            ):
                my_conv_details.method = method
            if status := headers.get(":status"):
                code, value = status[0].split(" ", 1)
                my_conv_details.status = int(code)
                my_conv_details.statusText = value

        match layer.layer_name:
            case "http":
                data = layer.get("chunk_data") or layer.get_field("file_data")
            case "http2":
                data = layer.get_field("body_reassembled_data")
                if not data and layer.flags.hex_value & 0x01:
                    data = layer.get_field("data_data")
            case "http3":
                data = layer.get_field("data_data") or layer.get_field("data")

        if data:
            has_something = True
            for d in data.all_fields:
                if d.showname_value == "<MISSING>" and layer.length == "0":
                    continue
                my_conv_details.body += d.binary_value

        if not has_something:
            continue

        my_conv_details.endTimestamp = timestamp
        conv_details[full_stream_id].maxPacketTs = timestamp

    for conv in conv_details.values():
        encoding = conv.response.headers.get("content-encoding") or []
        size_before = len(conv.response.body)
        match next(iter(encoding), None):
            case None:
                pass
            case "br":
                conv.response.body = brotli.decompress(conv.response.body)
            case "gzip":
                conv.response.body = gzip.decompress(conv.response.body)
            case _:
                print(f"Unknown encoding {encoding}")
        conv.response.compressionSaved = len(conv.response.body) - size_before
    return conv_details


def to_har_json(conv_details, comment=None):
    output = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "pcap2har",
                "version": __version__,
                "comment": comment,
            },
            "entries": [
                {
                    "startedDateTime": unix_ts_to8601(conv.request.startTimestamp),
                    "time": (conv.maxPacketTs - conv.request.startTimestamp) * 1000.0,
                    "serverIPAddress": conv.remoteAddress.rsplit(':', 1)[0],
                    "request": {
                        "method": conv.request.method,
                        "url": conv.request.url,
                        "httpVersion": conv.request.httpVersion,
                        "headers": [
                            {"name": h, "value": v}
                            for h, vs in conv.request.headers.items()
                            for v in vs
                        ],
                        "postData": (
                            {
                                "mimeType": first(
                                    conv.request.headers.get("content-type", [])
                                ),
                                "encoding": "base64",
                                "text": base64.b64encode(conv.request.body).decode(
                                    "ascii"
                                ),
                            }
                            if conv.request.body
                            else None
                        ),
                        "headersSize": conv.request.headersSize,
                        "bodySize": len(conv.request.body),
                    },
                    "response": {
                        "status": conv.response.status,
                        "statusText": conv.response.statusText,
                        "httpVersion": conv.response.httpVersion,
                        "headers": [
                            {"name": h, "value": v}
                            for h, vs in conv.response.headers.items()
                            for v in vs
                        ],
                        "headersSize": conv.response.headersSize,
                        "bodySize": len(conv.response.body) - conv.response.compressionSaved,
                        "content": {
                            "size": len(conv.response.body),
                            "compression": conv.response.compressionSaved,
                            **content_to_json(
                                first(conv.response.headers.get("content-type", [])),
                                conv.response.body,
                            ),
                        },
                    },
                    "_resourceType": "websocket" if conv.websocketMessages else None,
                    "_webSocketMessages": (
                        [
                            {
                                "type": m.type,
                                "time": m.time,
                                "opcode": m.opcode,
                                "data": (
                                    m.data.decode("utf-8")
                                    if m.opcode != 0x2
                                    else base64.b64encode(m.data).decode("ascii")
                                ),
                            }
                            for m in conv.websocketMessages
                        ]
                        if conv.websocketMessages
                        else None
                    ),
                    "cache": {},
                    "timings": {
                        "blocked": 0,
                        "dns": 0,
                        "connect": 0,
                        "send": (
                            conv.request.endTimestamp - conv.request.startTimestamp
                        )
                        * 1000.0,
                        "wait": (
                            (conv.response.startTimestamp - conv.request.endTimestamp)
                            * 1000.0
                            if conv.response.startTimestamp
                            else -1
                        ),
                        "receive": (
                            (conv.response.endTimestamp - conv.response.startTimestamp)
                            * 1000.0
                            if conv.response.startTimestamp
                            else -1
                        ),
                        "ssl": 0,
                    },
                    "connection": "-".join(map(str, cid)),
                }
                for cid, conv in conv_details.items()
                if conv.request.method != "CONNECT" and conv.maxPacketTs > 0
            ],
        }
    }

    return output


def content_to_json(content_type, body):
    if not body:
        return {"mimeType": "", "text": ""}
    if content_type.split(";", 1)[0].strip() in (
        "application/x-www-form-urlencoded",
        "application/json",
        "text/html",
        "text/plain",
        "text/javascript",
        "application/json+protobuf",
    ):
        return {"mimeType": content_type, "text": body.decode("utf-8")}
    else:
        return {
            "mimeType": content_type,
            "text": base64.b64encode(body).decode("ascii"),
            "encoding": "base64",
        }


def first(it, default=None):
    return next(iter(it), default)


def maybe_strip_suffix(s, suf):
    if s.endswith(suf):
        return s[: -len(suf)]
    return s


def unix_ts_to8601(ts):
    dt_object = datetime.datetime.fromtimestamp(ts, datetime.UTC)
    return dt_object.isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
