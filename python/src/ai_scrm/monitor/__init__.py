"""
AI-SCRM Monitor Module.

Provides continuous validation of AI systems with tiered checks:
- Fast hash checks (default: 60 seconds)
- MCP heartbeat checks (default: 5 minutes)
- Full re-scan (default: 30 minutes)

Example:
    >>> from ai_scrm.monitor import Monitor
    >>> monitor = Monitor(abom_path="abom-signed.json")
    >>> monitor.start()  # Background monitoring

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0    
"""

from .monitor import (
    Monitor,
    MonitorConfig,
    MonitorStatus,
    MonitorState,
)

__all__ = [
    "Monitor",
    "MonitorConfig", 
    "MonitorStatus",
    "MonitorState",
]
