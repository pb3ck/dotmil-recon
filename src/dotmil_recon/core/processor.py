import sys
from typing import Callable, Optional

from dotmil_recon.core.models import Asset
from dotmil_recon.core.prober import probe_domain, resolve_ip


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

# Type alias for progress callback
ProgressCallback = Callable[[int, int, str, str], None]


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


def _default_progress(current: int, total: int, domain: str, status: str) -> None:
    """Default progress output to stderr."""
    # Use \r to overwrite line, pad with spaces to clear previous content
    msg = f"\r[{current}/{total}] {domain[:50]:<50} {status}"
    sys.stderr.write(msg)
    sys.stderr.flush()


def _progress_complete(total: int, live: int, dead: int) -> None:
    """Print completion summary."""
    sys.stderr.write(f"\r{' ' * 80}\r")  # Clear line
    sys.stderr.write(f"Checked {total} domains: {live} live, {dead} dead\n")
    sys.stderr.flush()


def _verbose_log(message: str) -> None:
    """Print verbose log message to stderr."""
    sys.stderr.write(f"  {message}\n")
    sys.stderr.flush()


class Processor:
    """Processes and filters discovered assets."""

    def __init__(
        self, 
        filters: list[str] | None = None, 
        check_liveness: bool = False,
        probe_http: bool = False,
        progress: bool = True,
        verbose: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
    ):
        self.filters = filters or []
        self.check_liveness = check_liveness
        self.probe_http = probe_http
        self.show_progress = progress
        self.verbose = verbose
        self.progress_callback = progress_callback or _default_progress

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
        
        if self.check_liveness or self.probe_http:
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
            
            tags: list[str] = asset.tags
            for pattern in DEFAULT_PATTERNS:
                if _matches_pattern(asset.domain, pattern):
                    tags.append(pattern)

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
        """Check which domains resolve and optionally probe HTTP."""
        total = len(assets)
        live_count = 0
        dead_count = 0
        
        for i, asset in enumerate(assets, 1):
            domain = asset.domain
            
            # First check DNS
            if self.show_progress:
                self.progress_callback(i, total, domain, "resolving...")
            
            ip = resolve_ip(domain)
            
            if ip:
                asset.ip = ip
                asset.live = True
                live_count += 1
                
                if self.verbose:
                    _verbose_log(f"{domain} -> {ip}")
                
                # HTTP probing if enabled
                if self.probe_http:
                    if self.show_progress:
                        self.progress_callback(i, total, domain, "probing http...")
                    
                    http_result, https_result = probe_domain(domain)
                    asset.http = http_result
                    asset.https = https_result
                    
                    # Verbose output for probe results
                    if self.verbose:
                        if https_result:
                            if https_result.error:
                                _verbose_log(f"  https: {https_result.error} ({https_result.duration_ms}ms)")
                            else:
                                redirect_info = f" -> {https_result.final_url}" if https_result.final_url else ""
                                tech_info = f" [{', '.join(https_result.technologies)}]" if https_result.technologies else ""
                                _verbose_log(f"  https: {https_result.status_code}{redirect_info}{tech_info} ({https_result.duration_ms}ms)")
                        if http_result:
                            if http_result.error:
                                _verbose_log(f"  http: {http_result.error} ({http_result.duration_ms}ms)")
                            else:
                                redirect_info = f" -> {http_result.final_url}" if http_result.final_url else ""
                                tech_info = f" [{', '.join(http_result.technologies)}]" if http_result.technologies else ""
                                _verbose_log(f"  http: {http_result.status_code}{redirect_info}{tech_info} ({http_result.duration_ms}ms)")
                    
                    # Build status string for progress
                    status_parts: list[str] = []
                    if https_result and not https_result.error:
                        tech_str = ",".join(https_result.technologies[:3]) if https_result.technologies else ""
                        status_parts.append(f"https:{https_result.status_code}")
                        if tech_str:
                            status_parts.append(f"[{tech_str}]")
                    elif https_result and https_result.error:
                        status_parts.append(f"https:{https_result.error}")
                    
                    if http_result and not http_result.error:
                        tech_str = ",".join(http_result.technologies[:3]) if http_result.technologies else ""
                        status_parts.append(f"http:{http_result.status_code}")
                        if tech_str:
                            status_parts.append(f"[{tech_str}]")
                    elif http_result and http_result.error:
                        status_parts.append(f"http:{http_result.error}")
                    
                    if self.show_progress:
                        self.progress_callback(i, total, domain, " ".join(status_parts) or "live")
                else:
                    if self.show_progress:
                        self.progress_callback(i, total, domain, f"live ({ip})")
            else:
                asset.live = False
                dead_count += 1
                if self.show_progress:
                    self.progress_callback(i, total, domain, "dead")
                if self.verbose:
                    _verbose_log(f"{domain} -> DNS failed")
        
        if self.show_progress:
            _progress_complete(total, live_count, dead_count)
        
        return assets
