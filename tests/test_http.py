"""Tests for HTTP stream parsing."""

from pathlib import Path
from .common import parse_pcap_to_har


def test_chunked_gzip(golden):
    pcap_file = Path(__file__).parent / "resources" / "http-chunked-gzip.pcap"

    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)
