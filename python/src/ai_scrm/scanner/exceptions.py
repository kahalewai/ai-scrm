"""
Scanner exceptions for AI-SCRM.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""


class ScannerError(Exception):
    """Base exception for scanner operations."""
    pass


class ConfigNotFoundError(ScannerError):
    """Raised when expected configuration file is not found."""
    pass


class MCPConnectionError(ScannerError):
    """Raised when unable to connect to MCP server."""
    pass


class ModelInferenceError(ScannerError):
    """Raised when unable to infer model metadata."""
    pass
