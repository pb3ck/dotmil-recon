from abc import ABC, abstractmethod

from dotmil_recon.core.models import Asset

class BaseSource(ABC):
    """Abstract base class for all data sources."""

    name: str # e.g., "crtsh", "shodan"

    @abstractmethod
    def fetch(self, query: str) -> list[Asset]:
        """
        Fetch assets matching the query.

        Args:
            query: Domain pattern to search (e.g., "%.mil")

        Returns:
            List of discovered assets.
        """
        pass