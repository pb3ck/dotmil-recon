from dotmil_recon.core.models import Asset
from dotmil_recon.outputs.base import BaseOutput


class JsonOutput(BaseOutput):
    """JSON output format."""
    
    name = "json"
    
    def write(self, assets: list[Asset], path: str | None = None) -> str:
        output = "[" + ",".join(a.model_dump_json() for a in assets) + "]"
        
        if path:
            with open(path, "w") as f:
                f.write(output)
        
        return output