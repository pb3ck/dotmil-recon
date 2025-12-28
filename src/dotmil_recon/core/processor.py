from dotmil_recon.core.models import Asset
from dotmil_recon.core.resolver import check_live


# Patterns that suggest old or interesting infrastructure
# These match as word boundaries (surrounded by dots or start/end)
DEFAULT_PATTERNS: list[str] = [
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

# Domains that look like matches but aren't (false positives)
FALSE_POSITIVES: set[str] = {
    "devens",      # Fort Devens
    "medevac",     # Medical evacuation
    "peoavn",      # PEO Aviation
}


def _matches_pattern(domain: str, pattern: str) -> bool:
    """Check if pattern matches as a word boundary in domain."""
    parts = domain.replace("-", ".").split(".")
    return pattern in parts


def _is_false_positive(domain: str) -> bool:
    """Check if domain contains known false positive patterns."""
    for fp in FALSE_POSITIVES:
        if fp in domain:
            return True
    return False


class Processor:
    """Processes and filters discovered assets."""

    def __init__(self, filters: list[str] | None = None, check_liveness: bool = False):
        self.filters = filters or []
        self.check_liveness = check_liveness

    def process(self, assets: list[Asset]) -> list[Asset]:
        """
        Process assets: dedupe, tag, and optionally filter.

        Args:
            assets: Raw assets from sources.

        Returns:
            Processed assets.
        """
        assets = self._dedupe(assets)
        assets = self._tag(assets)

        if self.filters:
            assets = self._filter(assets)
        
        if self.check_liveness:
            assets = self._check_live(assets)

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
            if _is_false_positive(asset.domain):
                continue
            
            for pattern in DEFAULT_PATTERNS:
                if _matches_pattern(asset.domain, pattern):
                    asset.tags.append(pattern)

        return assets

    def _filter(self, assets: list[Asset]) -> list[Asset]:
        """Keep only assets matching filter patterns."""
        result: list[Asset] = []

        for asset in assets:
            if _is_false_positive(asset.domain):
                continue
            
            for f in self.filters:
                if _matches_pattern(asset.domain, f):
                    result.append(asset)
                    break

        return result
    
    def _check_live(self, assets: list[Asset]) -> list[Asset]:
        """Check which domains resolve and update live status."""
        for asset in assets:
            asset.live = check_live(asset.domain)
        
        return assets