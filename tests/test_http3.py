"""Tests for HTTP/3 QUIC stream parsing."""

from pathlib import Path
from .common import parse_pcap_to_har


def test_http3_parse(golden):
    pcap_file = Path(__file__).parent / "resources" / "http3-connection7.pcap"

    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)
