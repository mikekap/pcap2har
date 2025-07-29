# pcap2har

[![Tests](https://github.com/yourusername/pcap2har/workflows/Tests/badge.svg)](https://github.com/yourusername/pcap2har/actions/workflows/test.yml)

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

## CI/CD

This project uses GitHub Actions for continuous integration:

- **Tests**: Runs on every PR and push to main/master across Python 3.8-3.13
- **Security**: Weekly security audits and dependency updates
- **Releases**: Automatic builds when tags are pushed

### Local Development

To run the same checks locally:

```bash
# Install dependencies
uv sync --extra dev

# Run tests
uv run pytest tests/ -v

# Check formatting
uv run black --check src/ tests/

# Run linting
uv run flake8 src/ tests/

# Security audit
uv run uv audit
```

## License

MIT 