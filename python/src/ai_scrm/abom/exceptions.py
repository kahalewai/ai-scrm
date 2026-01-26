"""ABOM Exceptions - Control Domain 1 errors.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from typing import List, Optional, Any


class ABOMError(Exception):
    """Base exception for ABOM operations."""
    pass


class ABOMValidationError(ABOMError):
    """ABOM validation failed."""
    
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or []
    
    def __str__(self) -> str:
        if self.errors:
            return f"{self.args[0]}: {'; '.join(self.errors)}"
        return self.args[0]


class ABOMParseError(ABOMError):
    """Failed to parse ABOM document."""
    pass


class DiscoveryError(ABOMError):
    """Artifact discovery failed."""
    pass
