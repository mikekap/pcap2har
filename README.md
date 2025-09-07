# pcap2har

[![Tests](https://github.com/mikekap/pcap2har/workflows/Tests/badge.svg)](https://github.com/mikekap/pcap2har/actions/workflows/test.yml)

A Python project for converting PCAP files to HAR (HTTP Archive) format.

## Description

This project provides tools to analyze network packet capture files (PCAP) and convert them to HAR format for web traffic analysis.

## Installation

### From PyPI (Recommended)

```bash
pip install pcap2har
```

### From Source

This project uses `uv` for package management. Make sure you have `uv` installed:

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then install dependencies:

```bash
uv sync
```

## Usage

After installation, you can use the `pcap2har` command directly:

```bash
# Basic usage
pcap2har <pcap_file>

# With output file
pcap2har <pcap_file> -o output.har

# Pretty print output
pcap2har <pcap_file> --pretty

# Set log level
pcap2har <pcap_file> --log-level DEBUG
```

### Development Usage

If running from source:

```bash
# Basic usage
uv run python -m pcap2har.main <pcap_file>

# With output file
uv run python -m pcap2har.main <pcap_file> -o output.har

# Pretty print output
uv run python -m pcap2har.main <pcap_file> --pretty
```

## Development

1. Clone the repository
2. Install dependencies: `uv sync`
3. Run tests: `uv run python -m pytest tests/`
4. Format code: `uv run black .`
5. Lint code: `uv run flake8 pcap2har/ tests/`

## CI/CD

This project uses GitHub Actions for continuous integration:

- **Tests**: Runs on every PR and push to main/master across Python 3.10-3.13
- **Security**: Weekly security audits and dependency updates
- **Releases**: Automatic builds when tags are pushed

### Local Development

To run the same checks locally:

```bash
# Install dependencies
uv sync --group dev

# Run tests
uv run pytest

# Run specific test
uv run pytest tests/test_http2.py -v

# Check formatting
uv run black .

# Run linting
uv run flake8 pcap2har/ tests/

# Security audit
uv run uv audit
```

### Test Structure

The project uses `pytest-goldie` for golden tests. Tests are organized as follows:

```
tests/
├── test_http2.py          # HTTP/2 tests
├── test_http3.py          # HTTP/3 tests  
├── test_main.py           # Main module tests
├── resources/             # Test PCAP files
│   ├── http2-dump.pcap   # HTTP/2 test data
│   └── http3-connection7.pcap  # HTTP/3 test data
└── goldens/               # Golden test outputs
    ├── test_http2.py-test_http2_parse
    └── test_http3.py-test_http3_parse
```

To add a new test:

1. Create a new test file (e.g., `tests/test_new_protocol.py`)
2. Use the `golden` fixture for golden testing
3. Add test PCAP files to `tests/resources/`
4. Run the test to generate golden output: `uv run python -m pytest tests/test_new_protocol.py -v`

### Pre-commit Commands

Before committing code, run these commands to ensure quality:

```bash
# Format code
uv run black pcap2har/ tests/

# Lint code
uv run flake8 pcap2har/ tests/

# Run tests
uv run python -m pytest tests/ -v
```

### Useful tshark Commands

The project includes a `capture.pcapng` file for testing. Here are useful commands for filtering and analyzing the capture:

```bash
# Filter by TCP stream (useful for isolating HTTP/2 conversations)
tshark -r capture.pcapng -Y "tcp.stream eq 2" -w tests/resources/http2-dump.pcap

# Filter by TCP stream and HTTP/2 traffic
tshark -r capture.pcapng -Y "tcp.stream eq 2 and http2" -w tests/resources/http2-dump.pcap

# View HTTP/2 frames in a specific stream
tshark -r capture.pcapng -Y "tcp.stream eq 2 and http2" -T fields -e frame.number -e http2.type -e http2.streamid -e http2.headers.method -e http2.headers.path

# Filter by HTTP/3 traffic
tshark -r capture.pcapng -Y "http3" -w tests/resources/http3-dump.pcap

# Filter by specific ports
tshark -r capture.pcapng -Y "tcp.port == 443" -w tests/resources/https-dump.pcap

# Filter by IP address
tshark -r capture.pcapng -Y "ip.addr == 192.168.1.1" -w tests/resources/ip-filtered.pcap

# View packet statistics
tshark -r capture.pcapng -q -z io,phs

# Extract specific protocol data
tshark -r capture.pcapng -Y "http2" -T json > http2-data.json
```

### Generating Test Data

The project includes a `capture_packets.sh` script for capturing new network traffic:

```bash
# Make script executable
chmod +x capture_packets.sh

# Capture traffic while browsing a website
./capture_packets.sh https://example.com

# This will create capture.pcapng with decrypted TLS traffic
# Use tshark commands above to filter and extract specific conversations
```

## License

MIT 
