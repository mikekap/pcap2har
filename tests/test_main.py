"""Tests for main module."""

from click.testing import CliRunner
from pcap2har.main import main


class TestMain:
    """Test cases for main CLI."""

    def test_help(self):
        """Test that help is displayed."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Convert PCAP file to HAR format" in result.output

    def test_missing_file(self):
        """Test that missing file shows error."""
        runner = CliRunner()
        result = runner.invoke(main, ["nonexistent.pcap"])
        assert result.exit_code != 0
