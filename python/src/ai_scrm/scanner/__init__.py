"""
AI-SCRM Scanner Module.

Auto-discovers AI system components including:
- Model files (with smart supplier inference)
- MCP servers (from configs and network)
- Python libraries
- Prompt templates and configs

Example:
    >>> from ai_scrm.scanner import Scanner
    >>> scanner = Scanner()
    >>> result = scanner.scan(model_dirs=["./models"])
    >>> scanner.print_summary(result)

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from .scanner import (
    Scanner,
    ScanResult,
    DiscoveredModel,
    DiscoveredLibrary,
    DiscoveredPrompt,
)

from .mcp_discovery import (
    MCPDiscovery,
    TrustBoundaryClassifier,
    DiscoveredMCP,
)

from .metadata import (
    MetadataConfig,
    MetadataEnricher,
    load_metadata,
    save_metadata,
    generate_template,
)

from .inference import (
    infer_model_info,
    infer_format_from_extension,
    infer_quantization,
    ModelInfo,
)

from .exceptions import (
    ScannerError,
    ConfigNotFoundError,
    MCPConnectionError,
    ModelInferenceError,
)

__all__ = [
    # Scanner
    "Scanner",
    "ScanResult",
    "DiscoveredModel",
    "DiscoveredLibrary", 
    "DiscoveredPrompt",
    
    # MCP Discovery
    "MCPDiscovery",
    "TrustBoundaryClassifier",
    "DiscoveredMCP",
    
    # Metadata
    "MetadataConfig",
    "MetadataEnricher",
    "load_metadata",
    "save_metadata",
    "generate_template",
    
    # Inference
    "infer_model_info",
    "infer_format_from_extension",
    "infer_quantization",
    "ModelInfo",
    
    # Exceptions
    "ScannerError",
    "ConfigNotFoundError",
    "MCPConnectionError",
    "ModelInferenceError",
]
