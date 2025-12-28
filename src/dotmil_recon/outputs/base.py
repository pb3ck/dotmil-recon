from abc import ABC, abstractmethod

from dotmil_recon.core.models import Asset


class BaseOutput(ABC):
    """Abstract base class for all output formats."""
    
    name: str
    
    @abstractmethod
    def write(self, assets: list[Asset], path: str | None = None) -> str:
        """
        Write assets to output.
        
        Args:
            assets: Processed assets to output.
            path: File path, or None for stdout.
        
        Returns:
            Formatted output string.
        """
        pass