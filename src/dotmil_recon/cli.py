import argparse
import json
from datetime import datetime, timezone

from dotmil_recon.core.models import Asset
from dotmil_recon.core.processor import Processor
from dotmil_recon.outputs.csv import CsvOutput
from dotmil_recon.outputs.json import JsonOutput
from dotmil_recon.sources.crtsh import CrtshSource


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dotmil-recon",
        description="DoD asset enumeration tool"
    )
    
    parser.add_argument(
        "-q", "--query",
        default="%.mil",
        help="Domain pattern to search (default: %%.mil)"
    )
    parser.add_argument(
        "-i", "--input",
        help="Input JSON file with assets to process (skips crt.sh query)"
    )
    parser.add_argument(
        "-s", "--source",
        default="crtsh",
        choices=["crtsh"],
        help="Data source (default: crtsh)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "-f", "--format",
        default="json",
        choices=["json", "csv"],
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--filter",
        help="Comma-separated filter patterns (e.g., legacy,dev,portal)"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Check if domains resolve (DNS only)"
    )
    parser.add_argument(
        "--live-only",
        action="store_true",
        help="Only output domains that resolve (implies --live)"
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Probe HTTP/HTTPS and detect technologies (implies --live)"
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress output"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show errors, redirects, timing)"
    )
    
    args = parser.parse_args()
    
    # --live-only implies --live, --probe implies --live
    check_liveness = args.live or args.live_only or args.probe
    probe_http = args.probe
    
    # Load assets from input file or fetch from source
    if args.input:
        assets = load_assets_from_file(args.input)
    else:
        source = CrtshSource()
        assets = source.fetch(args.query)
    
    # Process
    filters: list[str] = args.filter.split(",") if args.filter else []
    processor = Processor(
        filters=filters, 
        check_liveness=check_liveness,
        probe_http=probe_http,
        progress=not args.no_progress,
        verbose=args.verbose,
    )
    assets = processor.process(assets)
    
    # Filter to live only if requested
    if args.live_only:
        assets = [a for a in assets if a.live is True]
    
    # Output
    if args.format == "json":
        output = JsonOutput()
    else:
        output = CsvOutput()
    
    result = output.write(assets, args.output)
    
    if not args.output:
        print(result)


def load_assets_from_file(filepath: str) -> list[Asset]:
    """Load assets from a JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    assets: list[Asset] = []
    for item in data:
        # Handle both full Asset format and simplified format
        if 'discovered_at' in item:
            # Full Asset format
            assets.append(Asset(**item))
        else:
            # Simplified format (just domain, ip, live, etc.)
            assets.append(Asset(
                domain=item['domain'],
                source=item.get('source', 'file'),
                ip=item.get('ip'),
                live=item.get('live'),
                tags=item.get('tags', []),
                discovered_at=datetime.now(timezone.utc),
            ))
    
    return assets


if __name__ == "__main__":
    main()
