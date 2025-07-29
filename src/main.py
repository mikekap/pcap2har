#!/usr/bin/env python3
"""Main entry point for pcap2har."""

import click
import sys
from pathlib import Path


@click.command()
@click.argument('pcap_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(), help='Output HAR file path')
def main(pcap_file: Path, output: str = None):
    """Convert PCAP file to HAR format."""
    click.echo(f"Processing PCAP file: {pcap_file}")
    
    if output:
        output_path = Path(output)
        click.echo(f"Output will be written to: {output_path}")
    else:
        output_path = pcap_file.with_suffix('.har')
        click.echo(f"Output will be written to: {output_path}")
    
    # TODO: Implement PCAP to HAR conversion
    click.echo("Conversion not yet implemented")


if __name__ == '__main__':
    main() 