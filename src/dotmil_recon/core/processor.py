from dotmil_recon.core.models import Asset

# Patterns that suggest old or interesting infrastructure
DEFAULT_FILTERS: list[str] = [
    "legacy",
    "old",
    "dev",
    "test",
    "staging",
    "portal",
    "webmail",
    "owa",
    "vpn",
    "remote",
    "admin",
    "training",
]

class Processor:
    """Processes and filters discovered assets."""

    def __init__(self, filters: list[str] | None = None):
        self.filters = filters or []

    def process(self, assets: list[Asset]) -> list[Asset]:
        """
        Process assetsL dedupe, tag, and optionally filter.

        Args:
            assets: Raw assets from sources.

        Returns:
            Processed assets.
        """
        assets = self._dedupe(assets)
        assets = self._tag(assets)

        if self.filters:
            assets = self._filter(assets)
        
        return assets
    
    def _dedupe(self, assets: list[Asset]) -> list[Asset]:
        """Remove duplicate domains, keeping first occurrence."""
        seen: set[str] = set()
        result: list[Asset] = []

        for asset in assets:
            if asset.domain not in seen:
                seen.add(asset.domain)
                result.append(asset)
        
        return result
    
    def _tag(self, assets: list[Asset]) -> list[Asset]:
        """Apply tags based on domain patterns."""
        for asset in assets:
            for pattern in DEFAULT_FILTERS:
                if pattern in asset.domain:
                    asset.tags.append(pattern)

        return assets
    
    def _filter(self, assets: list[Asset]) -> list[Asset]:
        """Keep only assets matching filter patterns."""
        result: list[Asset] = []

        for asset in assets:
            for f in self.filters:
                if f in asset.domain:
                    result.append(asset)
                    break

        return result