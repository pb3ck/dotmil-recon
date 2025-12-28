import argparse

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
        help="Check if domains resolve (slower)"
    )
    parser.add_argument(
        "--live-only",
        action="store_true",
        help="Only output domains that resolve (implies --live)"
    )
    
    args = parser.parse_args()
    
    # --live-only implies --live
    check_liveness = args.live or args.live_only
    
    # Select source
    source = CrtshSource()
    
    # Fetch assets
    assets = source.fetch(args.query)
    
    # Process
    filters: list[str] = args.filter.split(",") if args.filter else []
    processor = Processor(filters=filters, check_liveness=check_liveness)
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


if __name__ == "__main__":
    main()