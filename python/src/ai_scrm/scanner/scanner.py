"""
AI-SCRM Scanner - Auto-discovery of AI system components.

Scans for:
- Model files (with smart supplier inference)
- MCP servers (from configs and optionally network)
- Python libraries
- Prompt templates and config files
- Environment variables
- Vector stores

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

import hashlib
import json
import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .inference import (
    infer_model_info, 
    infer_format_from_extension,
    infer_quantization,
    get_huggingface_info,
    ModelInfo
)
from .mcp_discovery import MCPDiscovery, TrustBoundaryClassifier, DiscoveredMCP
from .exceptions import ScannerError

logger = logging.getLogger(__name__)


# Model file extensions to scan for
MODEL_EXTENSIONS = {
    ".safetensors", ".gguf", ".ggml", ".pt", ".pth", 
    ".bin", ".onnx", ".tflite", ".mlmodel", ".h5", 
    ".keras", ".pb", ".engine", ".trt"
}

# Prompt/config file patterns
PROMPT_PATTERNS = [
    "*.prompt", "*.prompt.txt", "*.prompt.md",
    "*_prompt.txt", "*_prompt.md",
    "system_prompt*", "system-prompt*",
    "*.jinja", "*.jinja2",
]

CONFIG_PATTERNS = [
    "config.yaml", "config.yml", "config.json",
    "settings.yaml", "settings.yml", "settings.json",
    "*.config.yaml", "*.config.json",
]


@dataclass
class DiscoveredModel:
    """Represents a discovered model file."""
    name: str
    path: str
    hash_value: str
    hash_algorithm: str = "SHA-256"
    format: Optional[str] = None
    supplier: Optional[str] = None
    model_type: str = "base"
    architecture: Optional[str] = None
    family: Optional[str] = None
    parameters: Optional[str] = None
    version: str = "1.0.0"
    size_bytes: int = 0
    inferred: bool = False  # True if metadata was inferred
    needs_review: List[str] = field(default_factory=list)  # Fields that need human review
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "hash_value": self.hash_value,
            "hash_algorithm": self.hash_algorithm,
            "format": self.format,
            "supplier": self.supplier,
            "model_type": self.model_type,
            "architecture": self.architecture,
            "family": self.family,
            "parameters": self.parameters,
            "version": self.version,
            "size_bytes": self.size_bytes,
            "inferred": self.inferred,
            "needs_review": self.needs_review,
        }


@dataclass
class DiscoveredLibrary:
    """Represents a discovered Python library."""
    name: str
    version: str
    source: str = "pip"  # pip, conda, requirements.txt
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
        }


@dataclass
class DiscoveredPrompt:
    """Represents a discovered prompt/config file."""
    name: str
    path: str
    hash_value: str
    prompt_type: str = "unknown"  # system, agent, tool, guardrail
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "hash_value": self.hash_value,
            "prompt_type": self.prompt_type,
        }


@dataclass  
class ScanResult:
    """Complete scan results."""
    models: List[DiscoveredModel] = field(default_factory=list)
    mcp_servers: List[DiscoveredMCP] = field(default_factory=list)
    libraries: List[DiscoveredLibrary] = field(default_factory=list)
    prompts: List[DiscoveredPrompt] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    scan_paths: List[str] = field(default_factory=list)
    needs_review_count: int = 0
    
    def summary(self) -> Dict[str, Any]:
        """Get summary of scan results."""
        return {
            "models": len(self.models),
            "mcp_servers": len(self.mcp_servers),
            "libraries": len(self.libraries),
            "prompts": len(self.prompts),
            "needs_review": self.needs_review_count,
            "scan_time": self.scan_time,
        }
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "models": [m.to_dict() for m in self.models],
            "mcp_servers": [s.to_dict() for s in self.mcp_servers],
            "libraries": [l.to_dict() for l in self.libraries],
            "prompts": [p.to_dict() for p in self.prompts],
            "scan_paths": self.scan_paths,
        }


class Scanner:
    """
    AI-SCRM Scanner for auto-discovering AI system components.
    
    Example:
        >>> scanner = Scanner()
        >>> result = scanner.scan(model_dirs=["./models"])
        >>> print(result.summary())
        {'models': 3, 'mcp_servers': 47, 'libraries': 156, ...}
    """
    
    def __init__(
        self,
        trust_boundary_patterns: Optional[Dict[str, str]] = None,
        mcp_config_paths: Optional[List[str]] = None,
        scan_mcp_ports: Optional[List[int]] = None,
        query_mcp_capabilities: bool = True,
        include_dev_dependencies: bool = False,
        hash_algorithm: str = "SHA-256"
    ):
        """
        Initialize scanner.
        
        Args:
            trust_boundary_patterns: Custom trust boundary patterns
            mcp_config_paths: Additional MCP config paths to check
            scan_mcp_ports: Ports to scan for MCP servers (optional)
            query_mcp_capabilities: Whether to query MCP servers for capabilities
            include_dev_dependencies: Include dev dependencies in library scan
            hash_algorithm: Hash algorithm for file hashes
        """
        self.hash_algorithm = hash_algorithm
        self.include_dev_dependencies = include_dev_dependencies
        
        # Initialize MCP discovery
        self.mcp_discovery = MCPDiscovery(
            config_paths=mcp_config_paths,
            scan_ports=scan_mcp_ports,
            query_capabilities=query_mcp_capabilities
        )
        
        # Initialize trust boundary classifier
        self.trust_classifier = TrustBoundaryClassifier(default_boundary="external")
        if trust_boundary_patterns:
            self.trust_classifier.add_patterns_from_dict(trust_boundary_patterns)
    
    def scan(
        self,
        model_dirs: Optional[List[str]] = None,
        prompt_dirs: Optional[List[str]] = None,
        scan_cwd: bool = True,
        scan_huggingface_cache: bool = True,
        scan_libraries: bool = True,
        scan_mcp: bool = True,
    ) -> ScanResult:
        """
        Perform a full scan for AI components.
        
        Args:
            model_dirs: Directories to scan for model files
            prompt_dirs: Directories to scan for prompt files
            scan_cwd: Whether to scan current working directory
            scan_huggingface_cache: Whether to scan HuggingFace cache
            scan_libraries: Whether to scan Python libraries
            scan_mcp: Whether to scan for MCP servers
            
        Returns:
            ScanResult with all discovered components
        """
        result = ScanResult()
        scan_paths = set()
        
        # Determine directories to scan
        if model_dirs:
            scan_paths.update(model_dirs)
        if prompt_dirs:
            scan_paths.update(prompt_dirs)
        if scan_cwd:
            scan_paths.add(".")
        
        # Scan for models
        model_scan_dirs = list(scan_paths)
        if scan_huggingface_cache:
            hf_cache = Path.home() / ".cache" / "huggingface" / "hub"
            if hf_cache.exists():
                model_scan_dirs.append(str(hf_cache))
        
        for dir_path in model_scan_dirs:
            models = self._scan_directory_for_models(dir_path)
            result.models.extend(models)
        
        # Scan for prompts
        for dir_path in scan_paths:
            prompts = self._scan_directory_for_prompts(dir_path)
            result.prompts.extend(prompts)
        
        # Scan for libraries
        if scan_libraries:
            result.libraries = self._scan_libraries()
        
        # Scan for MCP servers
        if scan_mcp:
            result.mcp_servers = self.mcp_discovery.discover_all()
            self.trust_classifier.classify_all(result.mcp_servers)
        
        # Count items needing review
        result.needs_review_count = sum(
            1 for m in result.models if m.needs_review
        )
        
        result.scan_paths = list(scan_paths)
        
        return result
    
    def _scan_directory_for_models(self, dir_path: str) -> List[DiscoveredModel]:
        """Scan a directory for model files."""
        models = []
        path = Path(dir_path).expanduser()
        
        if not path.exists():
            logger.debug(f"Directory not found: {path}")
            return models
        
        logger.info(f"Scanning for models in: {path}")
        
        for filepath in path.rglob("*"):
            if not filepath.is_file():
                continue
            
            # Check extension
            ext = filepath.suffix.lower()
            if ext not in MODEL_EXTENSIONS:
                continue
            
            # Skip small files (likely not models)
            if filepath.stat().st_size < 1_000_000:  # 1MB minimum
                continue
            
            model = self._process_model_file(filepath)
            if model:
                models.append(model)
        
        logger.info(f"Found {len(models)} models in {path}")
        return models
    
    def _process_model_file(self, filepath: Path) -> Optional[DiscoveredModel]:
        """Process a single model file."""
        try:
            # Compute hash
            hash_value = self._compute_file_hash(filepath)
            
            # Get file info
            stat = filepath.stat()
            filename = filepath.name
            
            # Infer format from extension
            format_str = infer_format_from_extension(filename)
            
            # Try to infer model info from filename
            model_info = infer_model_info(filename)
            
            # Check for HuggingFace cache structure
            hf_info = None
            if ".cache/huggingface" in str(filepath):
                # Walk up to find the model directory
                for parent in filepath.parents:
                    hf_info = get_huggingface_info(str(parent))
                    if hf_info:
                        break
            
            # Build discovered model
            model = DiscoveredModel(
                name=filepath.stem,
                path=str(filepath),
                hash_value=hash_value,
                hash_algorithm=self.hash_algorithm,
                format=format_str,
                size_bytes=stat.st_size,
                version="1.0.0"
            )
            
            # Apply inferred info
            if model_info:
                model.supplier = model_info.supplier
                model.model_type = model_info.model_type
                model.architecture = model_info.architecture
                model.family = model_info.family
                model.parameters = model_info.parameters
                model.inferred = True
            
            # Override with HuggingFace info if available
            if hf_info:
                if not model.supplier:
                    model.supplier = hf_info.get("organization")
                model.name = hf_info.get("model_name", model.name)
            
            # Mark what needs review
            if not model.supplier:
                model.needs_review.append("supplier")
            
            # Check for quantization
            quant = infer_quantization(filename)
            if quant and not model.format:
                model.format = quant
            
            return model
            
        except Exception as e:
            logger.warning(f"Error processing model file {filepath}: {e}")
            return None
    
    def _scan_directory_for_prompts(self, dir_path: str) -> List[DiscoveredPrompt]:
        """Scan a directory for prompt and config files."""
        prompts = []
        path = Path(dir_path).expanduser()
        
        if not path.exists():
            return prompts
        
        # Scan for prompt files
        for pattern in PROMPT_PATTERNS:
            for filepath in path.rglob(pattern):
                if filepath.is_file():
                    prompt = self._process_prompt_file(filepath)
                    if prompt:
                        prompts.append(prompt)
        
        return prompts
    
    def _process_prompt_file(self, filepath: Path) -> Optional[DiscoveredPrompt]:
        """Process a single prompt file."""
        try:
            hash_value = self._compute_file_hash(filepath)
            
            # Try to infer prompt type from filename
            name_lower = filepath.name.lower()
            prompt_type = "unknown"
            
            if "system" in name_lower:
                prompt_type = "system"
            elif "agent" in name_lower:
                prompt_type = "agent"
            elif "tool" in name_lower:
                prompt_type = "tool"
            elif "guard" in name_lower or "safety" in name_lower:
                prompt_type = "guardrail"
            
            return DiscoveredPrompt(
                name=filepath.stem,
                path=str(filepath),
                hash_value=hash_value,
                prompt_type=prompt_type
            )
            
        except Exception as e:
            logger.warning(f"Error processing prompt file {filepath}: {e}")
            return None
    
    def _scan_libraries(self) -> List[DiscoveredLibrary]:
        """Scan installed Python libraries."""
        libraries = []
        
        try:
            # Try importlib.metadata first (Python 3.8+)
            from importlib.metadata import distributions
            
            for dist in distributions():
                lib = DiscoveredLibrary(
                    name=dist.metadata["Name"],
                    version=dist.metadata["Version"],
                    source="pip"
                )
                libraries.append(lib)
            
        except ImportError:
            # Fallback to pkg_resources
            try:
                import pkg_resources
                for dist in pkg_resources.working_set:
                    lib = DiscoveredLibrary(
                        name=dist.project_name,
                        version=dist.version,
                        source="pip"
                    )
                    libraries.append(lib)
            except ImportError:
                # Last resort: pip list
                try:
                    result = subprocess.run(
                        ["pip", "list", "--format=json"],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        for pkg in json.loads(result.stdout):
                            lib = DiscoveredLibrary(
                                name=pkg["name"],
                                version=pkg["version"],
                                source="pip"
                            )
                            libraries.append(lib)
                except Exception as e:
                    logger.warning(f"Could not scan libraries: {e}")
        
        # Also check requirements.txt
        req_files = ["requirements.txt", "requirements-dev.txt", "requirements-prod.txt"]
        for req_file in req_files:
            if Path(req_file).exists():
                self._parse_requirements_file(req_file, libraries)
        
        # Deduplicate by name (keep pip version)
        seen = set()
        unique_libs = []
        for lib in libraries:
            if lib.name.lower() not in seen:
                seen.add(lib.name.lower())
                unique_libs.append(lib)
        
        return unique_libs
    
    def _parse_requirements_file(
        self, 
        filepath: str, 
        libraries: List[DiscoveredLibrary]
    ) -> None:
        """Parse a requirements.txt file."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    
                    # Parse package==version or package>=version
                    match = re.match(r'^([a-zA-Z0-9_-]+)([=<>!]+)?(.+)?$', line)
                    if match:
                        name = match.group(1)
                        version = match.group(3) or "unknown"
                        
                        lib = DiscoveredLibrary(
                            name=name,
                            version=version.strip(),
                            source=f"requirements:{filepath}"
                        )
                        libraries.append(lib)
                        
        except Exception as e:
            logger.warning(f"Error parsing {filepath}: {e}")
    
    def _compute_file_hash(self, filepath: Path) -> str:
        """Compute hash of a file."""
        if self.hash_algorithm.upper() == "SHA-256":
            hasher = hashlib.sha256()
        elif self.hash_algorithm.upper() == "SHA-512":
            hasher = hashlib.sha512()
        elif self.hash_algorithm.upper() == "SHA-384":
            hasher = hashlib.sha384()
        else:
            hasher = hashlib.sha256()
        
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def scan_quick(self) -> ScanResult:
        """
        Perform a quick scan with default settings.
        
        Scans:
        - Current directory for models
        - MCP configs in default locations
        - Installed Python libraries
        """
        return self.scan(
            model_dirs=["."],
            scan_cwd=True,
            scan_huggingface_cache=True,
            scan_libraries=True,
            scan_mcp=True
        )
    
    def print_summary(self, result: ScanResult) -> None:
        """Print a human-readable summary of scan results."""
        summary = result.summary()
        
        print("\n" + "=" * 60)
        print("  AI-SCRM Scan Results")
        print("=" * 60)
        print(f"\n  Scan completed: {result.scan_time}")
        print(f"  Directories scanned: {', '.join(result.scan_paths)}")
        print()
        print(f"  📦 Models:      {summary['models']:>5}")
        print(f"  🔌 MCP Servers: {summary['mcp_servers']:>5}")
        print(f"  📚 Libraries:   {summary['libraries']:>5}")
        print(f"  📝 Prompts:     {summary['prompts']:>5}")
        print()
        
        if summary['needs_review'] > 0:
            print(f"  ⚠️  Items needing review: {summary['needs_review']}")
            print()
            print("  The following items need manual input:")
            for model in result.models:
                if model.needs_review:
                    print(f"    - {model.name}: missing {', '.join(model.needs_review)}")
        else:
            print("  ✓ All items have complete metadata")
        
        print()
        print("=" * 60)
        print()
