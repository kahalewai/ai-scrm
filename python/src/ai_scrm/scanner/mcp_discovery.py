"""
MCP Server Discovery for AI-SCRM.

Discovers MCP servers from:
- Configuration files (claude_desktop_config.json, mcp.json, etc.)
- Environment variables
- Running processes (optional)
- Network scanning (optional, opt-in)

Also queries discovered servers for their capabilities.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

import json
import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
import socket

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredMCP:
    """Represents a discovered MCP server."""
    name: str
    endpoint: str
    capabilities: List[str] = field(default_factory=list)
    trust_boundary: str = "external"  # Default to most restrictive
    source: str = "unknown"  # Where it was discovered
    version: Optional[str] = None
    description: Optional[str] = None
    command: Optional[str] = None  # For stdio-based MCP
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    transport: str = "unknown"  # stdio, http, sse
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "endpoint": self.endpoint,
            "capabilities": self.capabilities,
            "trust_boundary": self.trust_boundary,
            "source": self.source,
            "version": self.version,
            "description": self.description,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "transport": self.transport,
        }


# Default MCP configuration file locations
DEFAULT_MCP_CONFIG_PATHS = [
    # Claude Desktop (macOS)
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    # Claude Desktop (Windows)
    "~/AppData/Roaming/Claude/claude_desktop_config.json",
    # Claude Desktop (Linux)
    "~/.config/claude/claude_desktop_config.json",
    # Project-level configs
    "./mcp.json",
    "./mcp-servers.json",
    "./.mcp/config.json",
    "./config/mcp.json",
    # Alternative locations
    "~/.mcp/config.json",
    "~/.config/mcp/servers.json",
]

# Well-known MCP server names and their typical capabilities
KNOWN_MCP_SERVERS: Dict[str, Dict[str, Any]] = {
    "filesystem": {
        "capabilities": ["read_file", "write_file", "list_directory", "create_directory", "delete_file"],
        "description": "File system access"
    },
    "git": {
        "capabilities": ["clone", "commit", "push", "pull", "status", "diff", "log"],
        "description": "Git repository operations"
    },
    "github": {
        "capabilities": ["list_repos", "create_issue", "create_pr", "search_code"],
        "description": "GitHub API access"
    },
    "postgres": {
        "capabilities": ["query", "execute", "list_tables", "describe_table"],
        "description": "PostgreSQL database access"
    },
    "sqlite": {
        "capabilities": ["query", "execute", "list_tables"],
        "description": "SQLite database access"
    },
    "slack": {
        "capabilities": ["send_message", "list_channels", "search_messages"],
        "description": "Slack workspace access"
    },
    "brave-search": {
        "capabilities": ["web_search", "news_search"],
        "description": "Brave Search API"
    },
    "puppeteer": {
        "capabilities": ["navigate", "screenshot", "click", "type", "evaluate"],
        "description": "Browser automation"
    },
    "memory": {
        "capabilities": ["store", "retrieve", "search", "delete"],
        "description": "Persistent memory/knowledge base"
    },
    "fetch": {
        "capabilities": ["fetch_url", "download"],
        "description": "HTTP fetch operations"
    },
    "time": {
        "capabilities": ["get_current_time", "convert_timezone"],
        "description": "Time and timezone operations"
    },
    "sequential-thinking": {
        "capabilities": ["think_step", "plan", "reflect"],
        "description": "Sequential reasoning support"
    },
    "exa": {
        "capabilities": ["search", "find_similar", "get_contents"],
        "description": "Exa search API"
    },
    "everart": {
        "capabilities": ["generate_image", "edit_image"],
        "description": "Image generation"
    },
}


class MCPDiscovery:
    """
    Discovers MCP servers from various sources.
    
    Example:
        >>> discovery = MCPDiscovery()
        >>> servers = discovery.discover_all()
        >>> for server in servers:
        ...     print(f"{server.name}: {server.endpoint}")
    """
    
    def __init__(
        self,
        config_paths: Optional[List[str]] = None,
        env_prefix: str = "MCP_",
        scan_ports: Optional[List[int]] = None,
        query_capabilities: bool = True,
        timeout: float = 5.0
    ):
        """
        Initialize MCP discovery.
        
        Args:
            config_paths: List of config file paths to check
            env_prefix: Prefix for environment variables
            scan_ports: Optional list of ports to scan for MCP servers
            query_capabilities: Whether to query servers for capabilities
            timeout: Timeout for network operations
        """
        self.config_paths = config_paths or DEFAULT_MCP_CONFIG_PATHS
        self.env_prefix = env_prefix
        self.scan_ports = scan_ports
        self.query_capabilities = query_capabilities
        self.timeout = timeout
        self._discovered: Dict[str, DiscoveredMCP] = {}
    
    def discover_all(self) -> List[DiscoveredMCP]:
        """
        Discover MCP servers from all sources.
        
        Returns:
            List of discovered MCP servers
        """
        self._discovered.clear()
        
        # 1. Discover from config files
        self._discover_from_configs()
        
        # 2. Discover from environment variables
        self._discover_from_env()
        
        # 3. Optional: Scan network ports
        if self.scan_ports:
            self._discover_from_ports()
        
        # 4. Query capabilities for discovered servers
        if self.query_capabilities:
            self._query_all_capabilities()
        
        # 5. Enrich with known server info
        self._enrich_with_known_info()
        
        return list(self._discovered.values())
    
    def discover_from_file(self, filepath: str) -> List[DiscoveredMCP]:
        """
        Discover MCP servers from a specific config file.
        
        Args:
            filepath: Path to configuration file
            
        Returns:
            List of discovered servers from this file
        """
        path = Path(filepath).expanduser()
        if not path.exists():
            logger.debug(f"Config file not found: {path}")
            return []
        
        discovered = []
        
        try:
            with open(path, 'r') as f:
                config = json.load(f)
            
            # Claude Desktop format
            if "mcpServers" in config:
                for name, server_config in config["mcpServers"].items():
                    mcp = self._parse_claude_desktop_server(name, server_config, str(path))
                    if mcp:
                        discovered.append(mcp)
                        self._discovered[mcp.name] = mcp
            
            # Generic MCP config format
            elif "servers" in config:
                for server_config in config["servers"]:
                    mcp = self._parse_generic_server(server_config, str(path))
                    if mcp:
                        discovered.append(mcp)
                        self._discovered[mcp.name] = mcp
            
            # Array format
            elif isinstance(config, list):
                for server_config in config:
                    mcp = self._parse_generic_server(server_config, str(path))
                    if mcp:
                        discovered.append(mcp)
                        self._discovered[mcp.name] = mcp
            
            logger.info(f"Discovered {len(discovered)} MCP servers from {path}")
            
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {path}: {e}")
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")
        
        return discovered
    
    def _parse_claude_desktop_server(
        self, 
        name: str, 
        config: Dict[str, Any],
        source: str
    ) -> Optional[DiscoveredMCP]:
        """Parse Claude Desktop MCP server config format."""
        
        # stdio transport (command-based)
        if "command" in config:
            endpoint = f"stdio://{config['command']}"
            return DiscoveredMCP(
                name=name,
                endpoint=endpoint,
                command=config["command"],
                args=config.get("args", []),
                env=config.get("env", {}),
                source=source,
                transport="stdio"
            )
        
        # HTTP/SSE transport
        if "url" in config:
            return DiscoveredMCP(
                name=name,
                endpoint=config["url"],
                source=source,
                transport="http" if "http" in config["url"] else "sse"
            )
        
        logger.warning(f"Unknown MCP config format for {name}")
        return None
    
    def _parse_generic_server(
        self, 
        config: Dict[str, Any],
        source: str
    ) -> Optional[DiscoveredMCP]:
        """Parse generic MCP server config format."""
        
        name = config.get("name")
        if not name:
            logger.warning(f"MCP server config missing name in {source}")
            return None
        
        # Try various endpoint fields
        endpoint = (
            config.get("endpoint") or
            config.get("url") or
            config.get("uri") or
            config.get("address")
        )
        
        if not endpoint and "command" in config:
            endpoint = f"stdio://{config['command']}"
        
        if not endpoint:
            logger.warning(f"MCP server {name} has no endpoint in {source}")
            return None
        
        return DiscoveredMCP(
            name=name,
            endpoint=endpoint,
            capabilities=config.get("capabilities", []),
            version=config.get("version"),
            description=config.get("description"),
            command=config.get("command"),
            args=config.get("args"),
            env=config.get("env"),
            source=source,
            transport=config.get("transport", "unknown")
        )
    
    def _discover_from_configs(self) -> None:
        """Discover MCP servers from all config file paths."""
        for path in self.config_paths:
            self.discover_from_file(path)
        
        # Also check MCP_CONFIG_PATH environment variable
        env_config_path = os.environ.get("MCP_CONFIG_PATH")
        if env_config_path:
            self.discover_from_file(env_config_path)
    
    def _discover_from_env(self) -> None:
        """Discover MCP servers from environment variables."""
        
        # Look for MCP_SERVERS JSON
        mcp_servers_json = os.environ.get("MCP_SERVERS")
        if mcp_servers_json:
            try:
                servers = json.loads(mcp_servers_json)
                if isinstance(servers, dict):
                    for name, config in servers.items():
                        if isinstance(config, str):
                            # Simple endpoint string
                            mcp = DiscoveredMCP(
                                name=name,
                                endpoint=config,
                                source="env:MCP_SERVERS"
                            )
                        else:
                            mcp = self._parse_generic_server(
                                {"name": name, **config},
                                "env:MCP_SERVERS"
                            )
                        if mcp:
                            self._discovered[mcp.name] = mcp
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in MCP_SERVERS environment variable")
        
        # Look for individual MCP_* variables
        for key, value in os.environ.items():
            if key.startswith(self.env_prefix) and key != "MCP_SERVERS" and key != "MCP_CONFIG_PATH":
                # MCP_FILESYSTEM_URL=http://localhost:3000
                name_part = key[len(self.env_prefix):].lower().replace("_url", "").replace("_endpoint", "")
                if name_part and value:
                    mcp = DiscoveredMCP(
                        name=name_part,
                        endpoint=value,
                        source=f"env:{key}"
                    )
                    # Don't override if already discovered from config
                    if mcp.name not in self._discovered:
                        self._discovered[mcp.name] = mcp
    
    def _discover_from_ports(self) -> None:
        """Scan local ports for MCP servers."""
        if not self.scan_ports:
            return
        
        for port in self.scan_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Port is open, might be MCP server
                    endpoint = f"http://127.0.0.1:{port}"
                    name = f"unknown-mcp-{port}"
                    
                    mcp = DiscoveredMCP(
                        name=name,
                        endpoint=endpoint,
                        source=f"port-scan:{port}",
                        transport="http"
                    )
                    
                    # Don't override known servers
                    if not any(str(port) in s.endpoint for s in self._discovered.values()):
                        self._discovered[name] = mcp
                        logger.info(f"Discovered potential MCP server on port {port}")
                        
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
    
    def _query_all_capabilities(self) -> None:
        """Query capabilities for all discovered servers."""
        for mcp in self._discovered.values():
            if mcp.transport == "http" and not mcp.capabilities:
                caps = self._query_server_capabilities(mcp.endpoint)
                if caps:
                    mcp.capabilities = caps
    
    def _query_server_capabilities(self, endpoint: str) -> List[str]:
        """
        Query an MCP server for its capabilities.
        
        This attempts to call standard MCP capability endpoints.
        """
        try:
            import urllib.request
            import urllib.error
            
            # Try common capability endpoints
            capability_paths = [
                "/capabilities",
                "/mcp/capabilities", 
                "/.well-known/mcp-capabilities",
                "/api/capabilities"
            ]
            
            base_url = endpoint.rstrip("/")
            
            for path in capability_paths:
                try:
                    url = base_url + path
                    req = urllib.request.Request(
                        url,
                        headers={"Accept": "application/json"},
                        method="GET"
                    )
                    
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        data = json.loads(response.read().decode())
                        
                        # Various response formats
                        if isinstance(data, list):
                            return data
                        if "capabilities" in data:
                            return data["capabilities"]
                        if "tools" in data:
                            return [t.get("name", t) for t in data["tools"]]
                        
                except urllib.error.URLError:
                    continue
                except Exception:
                    continue
            
        except Exception as e:
            logger.debug(f"Could not query capabilities for {endpoint}: {e}")
        
        return []
    
    def _enrich_with_known_info(self) -> None:
        """Enrich discovered servers with known server information."""
        for mcp in self._discovered.values():
            # Try to match by name
            name_lower = mcp.name.lower()
            
            for known_name, known_info in KNOWN_MCP_SERVERS.items():
                if known_name in name_lower or name_lower in known_name:
                    # Add capabilities if not already discovered
                    if not mcp.capabilities:
                        mcp.capabilities = known_info.get("capabilities", [])
                    if not mcp.description:
                        mcp.description = known_info.get("description")
                    break


class TrustBoundaryClassifier:
    """
    Classifies MCP servers into trust boundaries based on patterns.
    
    Example:
        >>> classifier = TrustBoundaryClassifier()
        >>> classifier.add_pattern("localhost:*", "internal")
        >>> classifier.add_pattern("*.company.com", "internal")
        >>> boundary = classifier.classify("http://localhost:3000")
        >>> print(boundary)  # "internal"
    """
    
    def __init__(self, default_boundary: str = "external"):
        """
        Initialize classifier.
        
        Args:
            default_boundary: Default boundary for unmatched endpoints
        """
        self.default_boundary = default_boundary
        self._patterns: List[tuple] = []
        
        # Add sensible defaults
        self._add_default_patterns()
    
    def _add_default_patterns(self) -> None:
        """Add default trust boundary patterns."""
        # Localhost patterns - internal
        self._patterns.extend([
            (r"^https?://localhost[:/]", "internal"),
            (r"^https?://127\.0\.0\.1[:/]", "internal"),
            (r"^https?://\[::1\][:/]", "internal"),
            (r"^stdio://", "internal"),  # Local stdio processes
        ])
        
        # Private IP ranges - internal
        self._patterns.extend([
            (r"^https?://10\.\d+\.\d+\.\d+[:/]", "internal"),
            (r"^https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+[:/]", "internal"),
            (r"^https?://192\.168\.\d+\.\d+[:/]", "internal"),
        ])
    
    def add_pattern(self, pattern: str, boundary: str) -> None:
        """
        Add a pattern for trust boundary classification.
        
        Args:
            pattern: Glob-style pattern (supports * and ?)
            boundary: Trust boundary ("internal", "external", "hybrid")
        """
        # Convert glob to regex
        regex = pattern.replace(".", r"\.")
        regex = regex.replace("*", ".*")
        regex = regex.replace("?", ".")
        
        # Prepend https?:// if not present
        if not regex.startswith("^") and "://" not in regex:
            regex = r"^https?://.*" + regex
        
        self._patterns.append((regex, boundary))
    
    def add_patterns_from_dict(self, patterns: Dict[str, str]) -> None:
        """
        Add multiple patterns from a dictionary.
        
        Args:
            patterns: Dict mapping pattern to boundary
        """
        for pattern, boundary in patterns.items():
            self.add_pattern(pattern, boundary)
    
    def classify(self, endpoint: str) -> str:
        """
        Classify an endpoint into a trust boundary.
        
        Args:
            endpoint: MCP server endpoint URL
            
        Returns:
            Trust boundary string
        """
        for pattern, boundary in self._patterns:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return boundary
        
        return self.default_boundary
    
    def classify_all(self, servers: List[DiscoveredMCP]) -> None:
        """
        Classify all servers in place.
        
        Args:
            servers: List of discovered MCP servers to classify
        """
        for server in servers:
            server.trust_boundary = self.classify(server.endpoint)
