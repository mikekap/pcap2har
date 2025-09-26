from pcap2har.main import read_pcap_file, run_consistency_checks, to_har_json


def parse_pcap_to_har(file):
    conv_details = read_pcap_file(file)
    if not run_consistency_checks(conv_details, fatal=True):
        raise ValueError("Consistency checks failed")
    return to_har_json(conv_details, fatal=True)
