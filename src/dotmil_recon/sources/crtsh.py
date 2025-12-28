import requests

from dotmil_recon.core.models import Asset
from dotmil_recon.sources.base import BaseSource

class CrtshSource(BaseSource):
    """Certificate Transparency logs via crt.sh"""

    name = "crtsh"
    base_url = "https://crt.sh"

    def fetch(self, query: str) -> list[Asset]:
        response = requests.get(
            self.base_url,
            params={"q": query, "output": "json"},
            timeout=30
        )
        response.raise_for_status()

        data = response.json()

        seen: set[str] = set()
        assets: list[Asset] = []

        for entry in data:
            domain = entry.get("name_value", "").lower().strip()

            if not domain or domain in seen:
                continue

            # Handle multiline entries (crt.sh returns these sometimes)
            for d in domain.split("\n"):
                d = d.strip()
                if d and d not in seen:
                    seen.add(d)
                    assets.append(Asset(domain=d, source=self.name))

        return assets