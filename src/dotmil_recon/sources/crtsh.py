import time

import requests

from dotmil_recon.core.models import Asset
from dotmil_recon.sources.base import BaseSource


class CrtshSource(BaseSource):
    """Certificate Transparency logs via crt.sh."""
    
    name = "crtsh"
    base_url = "https://crt.sh"
    max_retries = 12
    retry_delay = 45  # seconds
    
    def fetch(self, query: str) -> list[Asset]:
        response = self._request_with_retry(query)
        data = response.json()
        
        seen: set[str] = set()
        assets: list[Asset] = []
        
        for entry in data:
            domain = entry.get("name_value", "").lower().strip()
            
            if not domain or domain in seen:
                continue
            
            for d in domain.split("\n"):
                d = d.strip()
                
                if not d or d in seen or "@" in d:
                    continue
                
                if d.startswith("*."):
                    d = d[2:]
                
                if d in seen:
                    continue
                
                seen.add(d)
                assets.append(Asset(domain=d, source=self.name))
        
        return assets
    
    def _request_with_retry(self, query: str) -> requests.Response:
        """Make request with retry logic for crt.sh's processing behavior."""
        last_error: Exception | None = None
        
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    self.base_url,
                    params={"q": query, "output": "json", "exclude": "expired"},
                    headers={"User-Agent": "dotmil-recon/0.1.0"},
                    timeout=120
                )
                
                # crt.sh returns 502/503 while query is processing
                if response.status_code in (502, 503):
                    if attempt < self.max_retries - 1:
                        print(f"Query processing, waiting {self.retry_delay}s... (attempt {attempt + 1}/{self.max_retries})")
                        time.sleep(self.retry_delay)
                        continue
                    else:
                        response.raise_for_status()
                
                response.raise_for_status()
                return response
            
            except requests.exceptions.Timeout as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    print(f"Timeout, retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
        
        raise RuntimeError(f"Failed after {self.max_retries} attempts: {last_error}")