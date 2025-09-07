"""Tests for HTTP stream parsing."""

from pathlib import Path
from pcap2har.main import to_har_json, read_pcap_file


def parse_pcap_to_har(file):
    return to_har_json(read_pcap_file(file))


def test_chunked_gzip(golden):
    pcap_file = Path(__file__).parent / "resources" / "http-chunked-gzip.pcap"

    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)
