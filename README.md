# pcap2har

A Python project for converting PCAP files to HAR (HTTP Archive) format.

## Description

This project provides tools to analyze network packet capture files (PCAP) and convert them to HAR format for web traffic analysis.

## Installation

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

```bash
python src/main.py <pcap_file>
```

## Development

1. Clone the repository
2. Install dependencies: `uv sync`
3. Run tests: `uv run pytest tests/`
4. Format code: `uv run black .`
5. Lint code: `uv run flake8 .`

## License

MIT 