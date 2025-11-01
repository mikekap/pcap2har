"""Tests for main module."""

from click.testing import CliRunner
from pcap2har.main import main, content_to_json, MAX_BODY_SIZE


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


def test_body_truncation():
    body = b"x" * 200
    max_size = 100

    result = content_to_json("text/plain", body, max_body_size=max_size)

    assert result["text"] == "x" * 100
    assert len(result["text"]) == max_size
    assert "comment" in result
    assert "truncated" in result["comment"].lower()
