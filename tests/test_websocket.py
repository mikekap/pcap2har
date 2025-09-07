"""Tests for websocket parsing."""

from pathlib import Path
from pcap2har.main import to_har_json, read_pcap_file


def parse_pcap_to_har(file):
    return to_har_json(read_pcap_file(file))


def test_websocket_parse(golden):
    pcap_file = Path(__file__).parent / "resources" / "websocket.pcap"

    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)


def test_websocket_segmented(golden):
    pcap_file = Path(__file__).parent / "resources" / "ipv4-websocket-segmented.pcap"

    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)
