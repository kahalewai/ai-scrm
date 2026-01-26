"""
AI-SCRM Framework Integrations.

Provides one-liner integrations for common frameworks.

Example:
    >>> from ai_scrm.integrations import guard, langchain_guard
    >>> 
    >>> @guard(tool="web-search")
    ... def search_web(query):
    ...     return results

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from .integrations import (
    guard,
    langchain_guard,
    FastAPIMiddleware,
    EmergencyBypass,
    emergency_bypass,
    is_bypass_active,
    get_bypass_reason,
    SecurityError,
)

__all__ = [
    "guard",
    "langchain_guard",
    "FastAPIMiddleware",
    "EmergencyBypass",
    "emergency_bypass",
    "is_bypass_active",
    "get_bypass_reason",
    "SecurityError",
]
