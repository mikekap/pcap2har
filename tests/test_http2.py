"""Tests for HTTP/2 stream parsing."""

from pathlib import Path
from pcap2har.main import to_har_json, read_pcap_file


def parse_pcap_to_har(file):
    return to_har_json(read_pcap_file(file))


def test_http2_parse(golden):
    pcap_file = Path(__file__).parent / "resources" / "http2-dump.pcap"
    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)


def test_firefox_tls13(golden):
    pcap_file = (
        Path(__file__).parent / "resources" / "firefox-tls13-facebook-dsb.pcapng"
    )
    har_data = parse_pcap_to_har(str(pcap_file))
    golden.test(har_data)
