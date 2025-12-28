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
    
    args = parser.parse_args()
    
    # Select source
    source = CrtshSource()
    
    # Fetch assets
    assets = source.fetch(args.query)
    
    # Process
    filters: list[str] = args.filter.split(",") if args.filter else []
    processor = Processor(filters=filters)
    assets = processor.process(assets)
    
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