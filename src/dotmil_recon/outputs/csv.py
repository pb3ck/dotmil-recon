import csv
import io

from dotmil_recon.core.models import Asset
from dotmil_recon.outputs.base import BaseOutput


class CsvOutput(BaseOutput):
    """CSV output format."""
    
    name = "csv"
    
    def write(self, assets: list[Asset], path: str | None = None) -> str:
        buffer = io.StringIO()
        
        fieldnames = ["domain", "source", "discovered_at", "ip", "org", "tags", "live"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        
        for asset in assets:
            writer.writerow({
                "domain": asset.domain,
                "source": asset.source,
                "discovered_at": asset.discovered_at.isoformat(),
                "ip": asset.ip or "",
                "org": asset.org or "",
                "tags": ",".join(asset.tags),
                "live": "" if asset.live is None else str(asset.live),
            })
        
        output = buffer.getvalue()
        
        if path:
            with open(path, "w") as f:
                f.write(output)
        
        return output