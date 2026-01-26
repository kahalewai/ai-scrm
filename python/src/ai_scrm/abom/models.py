"""
ABOM Data Models - AI-SCS Compliant Implementation

This module implements Control Domain 1 (Section 5) of the AI Supply Chain Standard.
All data structures align with CycloneDX 1.6 specification with AI-SCS extensions.

AI-SCS Compliance:
    - Section 4.1: All 7 asset categories supported
    - Section 5.3.1-5.3.6: All mandatory fields implemented
    - Section 5.4: Machine-readable, versioned, immutable, cryptographically verifiable

Classes:
    Hash: Cryptographic hash representation (5.3.1, 6.2)
    Property: Key-value metadata with AI-SCS namespaces
    ExternalReference: External references for base model refs, endpoints
    ABOMComponent: Individual component in ABOM (5.3.x)
    ABOMDependency: Dependency relationship (5.3.3)
    ABOMMetadata: ABOM document metadata (5.4)
    ABOM: Root ABOM document

Example:
    >>> from ai_scrm.abom import ABOM, ABOMComponent, Hash
    >>> comp = ABOMComponent(
    ...     type="machine-learning-model",
    ...     name="llama-7b",
    ...     version="1.0.0",
    ...     hashes=[Hash(alg="SHA-256", content="abc123...")]
    ... )
    >>> abom = ABOM(components=[comp])
    >>> abom.validate()
    True

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import json
import hashlib
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Union, Iterator, Tuple
from pathlib import Path
from enum import Enum

from ai_scrm.abom.exceptions import ABOMValidationError, ABOMParseError

# Configure logging
logger = logging.getLogger(__name__)

# =============================================================================
# Constants - AI-SCS Standard Identifiers
# =============================================================================

CYCLONEDX_SPEC_VERSION = "1.6"
"""CycloneDX specification version (1.6 or 1.7 supported)"""

AI_SCS_VERSION = "0.1"
"""AI-SCS standard version this implementation conforms to"""

TOOL_VENDOR = "ai-scrm"
"""Vendor identifier for tool metadata"""

TOOL_NAME = "ai-scrm"
"""Tool name for ABOM generation metadata"""

# Import version from package
try:
    from ai_scrm import __version__ as TOOL_VERSION
except ImportError:
    TOOL_VERSION = "1.0.0"
"""Tool version for ABOM generation metadata"""


# =============================================================================
# Helper Functions
# =============================================================================


def _generate_uuid() -> str:
    """
    Generate a URN UUID for ABOM serial numbers.
    
    Returns:
        str: URN-formatted UUID (e.g., "urn:uuid:550e8400-e29b-41d4-a716-446655440000")
    
    Example:
        >>> serial = _generate_uuid()
        >>> serial.startswith("urn:uuid:")
        True
    """
    return f"urn:uuid:{uuid.uuid4()}"


def _now_iso() -> str:
    """
    Generate ISO 8601 timestamp in UTC.
    
    Returns:
        str: ISO formatted timestamp (e.g., "2024-01-15T10:30:00Z")
    
    Example:
        >>> ts = _now_iso()
        >>> ts.endswith("Z")
        True
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_hash(data: Union[bytes, str, Path], alg: str = "SHA-256") -> str:
    """
    Compute cryptographic hash of data.
    
    Supports file paths, bytes, or strings. Used for AI-SCS 5.3.1 (model hashes)
    and 6.2 (artifact integrity verification).
    
    Args:
        data: Input data - can be bytes, string, or Path to file
        alg: Hash algorithm (default: SHA-256). Supports SHA-256, SHA-384, SHA-512, SHA3-256
    
    Returns:
        str: Lowercase hexadecimal hash digest
    
    Raises:
        FileNotFoundError: If path does not exist
        ValueError: If algorithm is not supported
    
    Example:
        >>> _compute_hash(b"hello world", "SHA-256")
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
        >>> _compute_hash(Path("model.safetensors"), "SHA-256")  # doctest: +SKIP
    """
    try:
        # Normalize algorithm name
        alg_normalized = alg.replace("-", "").replace("_", "").lower()
        
        if isinstance(data, Path):
            if not data.exists():
                raise FileNotFoundError(f"File not found: {data}")
            h = hashlib.new(alg_normalized)
            with open(data, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        return hashlib.new(alg_normalized, data).hexdigest()
    
    except ValueError as e:
        raise ValueError(f"Unsupported hash algorithm '{alg}': {e}")


def _canonicalize(data: Dict[str, Any]) -> bytes:
    """
    Create canonical JSON representation for signing.
    
    AI-SCS 5.4 requires ABOM to be cryptographically verifiable.
    Canonical form ensures consistent hashing regardless of key order.
    
    Args:
        data: Dictionary to canonicalize
    
    Returns:
        bytes: UTF-8 encoded canonical JSON
    
    Example:
        >>> _canonicalize({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
    """
    return json.dumps(
        data, 
        sort_keys=True, 
        separators=(",", ":"), 
        ensure_ascii=True
    ).encode("utf-8")


# =============================================================================
# Enumerations - AI-SCS Section 4.1 Asset Categories
# =============================================================================


class ComponentType(str, Enum):
    """
    CycloneDX 1.6 component types mapped to AI-SCS asset categories.
    
    AI-SCS Section 4.1 requires support for 7 asset categories.
    These CycloneDX types map to those categories as follows:
    
    Mapping:
        - APPLICATION: Agents, Planners, Orchestrators (4.1.5)
        - LIBRARY: Dependencies, Frameworks, Tokenizers (4.1.4)
        - SERVICE: Tools, Plugins, MCP Servers, APIs (4.1.6)
        - DATA: Datasets, Prompts, Policies (4.1.2, 5.3.6)
        - MACHINE_LEARNING_MODEL: Models, Embeddings (4.1.1, 4.1.3)
        - PLATFORM: Execution environments, TEEs (4.1.7)
        - DEVICE: Accelerators (4.1.7)
    """
    APPLICATION = "application"
    LIBRARY = "library"
    SERVICE = "service"
    DATA = "data"
    MACHINE_LEARNING_MODEL = "machine-learning-model"
    PLATFORM = "platform"
    DEVICE = "device"


class ArtifactType(str, Enum):
    """
    AI-SCS artifact type classifications per Section 4.1.
    
    These represent the canonical AI Supply Chain Asset (AISCA) types
    that MUST be declared in the ABOM. Use in ai-scs:artifactType property.
    
    Categories:
        4.1.1 Models: MODEL, BASE_MODEL, FINE_TUNED_MODEL, ADAPTER
        4.1.2 Data: DATASET, TRAINING_DATA, FINETUNING_DATA, EVALUATION_DATA
        4.1.3 Embeddings: EMBEDDING_MODEL, VECTOR_INDEX, VECTOR_DATABASE
        4.1.4 Dependencies: FRAMEWORK, TOKENIZER, INFERENCE_ENGINE, RUNTIME_LIBRARY
        4.1.5 Agents: AGENT, PLANNER, ORCHESTRATOR
        4.1.6 Tools: TOOL, PLUGIN, MCP_SERVER, TOOL_ROUTER, EXTERNAL_API
        4.1.7 Infrastructure: EXECUTION_ENV, TEE, ACCELERATOR
        5.3.6 Behavioral: PROMPT_TEMPLATE, POLICY, GUARDRAIL
    """
    # 4.1.1 Models
    MODEL = "model"
    BASE_MODEL = "base-model"
    FINE_TUNED_MODEL = "fine-tuned-model"
    ADAPTER = "adapter"  # LoRA, PEFT, QLoRA
    
    # 4.1.2 Data
    DATASET = "dataset"
    TRAINING_DATA = "training-data"
    FINETUNING_DATA = "finetuning-data"
    EVALUATION_DATA = "evaluation-data"
    
    # 4.1.3 Embeddings
    EMBEDDING_MODEL = "embedding-model"
    VECTOR_INDEX = "vector-index"
    VECTOR_DATABASE = "vector-database"
    
    # 4.1.4 Dependencies
    FRAMEWORK = "framework"
    TOKENIZER = "tokenizer"
    INFERENCE_ENGINE = "inference-engine"
    RUNTIME_LIBRARY = "runtime-library"
    
    # 4.1.5 Agents
    AGENT = "agent"
    PLANNER = "planner"
    ORCHESTRATOR = "orchestrator"
    
    # 4.1.6 Tools
    TOOL = "tool"
    PLUGIN = "plugin"
    MCP_SERVER = "mcp-server"
    TOOL_ROUTER = "tool-router"
    TOOL_BROKER = "tool-broker"
    EXTERNAL_API = "external-api"
    FUNCTION_CALL = "function-call"
    
    # 4.1.7 Infrastructure
    EXECUTION_ENV = "execution-environment"
    TEE = "trusted-execution-environment"
    ACCELERATOR = "accelerator"
    
    # 5.3.6 Behavioral and Policy Artifacts
    PROMPT_TEMPLATE = "prompt-template"
    SYSTEM_PROMPT = "system-prompt"
    GUARDRAIL_PROMPT = "guardrail-prompt"
    POLICY = "policy"
    GUARDRAIL = "guardrail"
    ROUTING_CONFIG = "routing-config"


class AISystemType(str, Enum):
    """
    AI system type classifications.
    
    Used in metadata to identify the type of AI system the ABOM describes.
    """
    LLM = "llm"
    AGENT = "agent"
    PIPELINE = "pipeline"
    RAG = "rag"
    HYBRID = "hybrid"
    MULTIMODAL = "multimodal"


class AIRuntimeType(str, Enum):
    """
    AI system runtime environment types.
    
    Used to indicate deployment context per AI-SCS 4.1.7 Infrastructure requirements.
    """
    CLOUD = "cloud"
    ON_PREM = "on-prem"
    EDGE = "edge"
    TEE = "tee"
    HYBRID = "hybrid"


# =============================================================================
# Data Classes - Core ABOM Structures
# =============================================================================


@dataclass
class Hash:
    """
    Cryptographic hash representation.
    
    AI-SCS Requirements:
        - Section 5.3.1: Models MUST have cryptographic hash
        - Section 5.3.2: Datasets SHOULD have hashes or immutable references
        - Section 6.2: Covered artifacts MUST be verifiable via hash
    
    Attributes:
        alg: Hash algorithm (e.g., "SHA-256", "SHA-384", "SHA-512", "SHA3-256")
        content: Lowercase hexadecimal hash digest
    
    Example:
        >>> h = Hash(alg="SHA-256", content="abc123def456")
        >>> h.to_dict()
        {'alg': 'SHA-256', 'content': 'abc123def456'}
        >>> h.verify(b"test data")  # doctest: +SKIP
    
    Test Cases:
        Input: Hash(alg="sha_256", content="ABC123")
        Expected: alg="SHA-256", content="abc123" (normalized)
        
        Input: Hash(alg="", content="abc")
        Expected: Raises ValueError
    """
    alg: str
    content: str
    
    def __post_init__(self) -> None:
        """Normalize algorithm name and content."""
        if not self.alg:
            raise ValueError("Hash algorithm cannot be empty")
        if not self.content:
            raise ValueError("Hash content cannot be empty")
        
        # Normalize: SHA_256 -> SHA-256, sha256 -> SHA-256
        self.alg = self.alg.upper().replace("_", "-")
        if self.alg in ("SHA256", "SHA384", "SHA512"):
            self.alg = f"{self.alg[:3]}-{self.alg[3:]}"
        
        # Normalize content to lowercase
        self.content = self.content.lower().strip()
    
    def to_dict(self) -> Dict[str, str]:
        """
        Convert to CycloneDX hash format.
        
        Returns:
            dict: {"alg": "SHA-256", "content": "abc123..."}
        """
        return {"alg": self.alg, "content": self.content}
    
    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> "Hash":
        """
        Create Hash from dictionary.
        
        Args:
            d: Dictionary with "alg" and "content" keys
        
        Returns:
            Hash instance
        
        Raises:
            KeyError: If required keys missing
        """
        if "alg" not in d or "content" not in d:
            raise KeyError("Hash dict must contain 'alg' and 'content'")
        return cls(alg=d["alg"], content=d["content"])
    
    @classmethod
    def from_file(cls, path: Union[str, Path], alg: str = "SHA-256") -> "Hash":
        """
        Compute hash from file.
        
        Args:
            path: Path to file
            alg: Hash algorithm
        
        Returns:
            Hash instance with computed digest
        """
        content = _compute_hash(Path(path), alg)
        return cls(alg=alg, content=content)
    
    def verify(self, data: Union[bytes, str, Path]) -> bool:
        """
        Verify data against this hash (AI-SCS 6.2).
        
        Args:
            data: Data to verify - bytes, string, or file path
        
        Returns:
            bool: True if hash matches, False otherwise
        
        Example:
            >>> h = Hash(alg="SHA-256", content="b94d27b...")
            >>> h.verify(b"hello world")  # doctest: +SKIP
        """
        try:
            computed = _compute_hash(data, self.alg)
            return computed.lower() == self.content.lower()
        except Exception as e:
            logger.warning(f"Hash verification failed: {e}")
            return False
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Hash):
            return NotImplemented
        return self.alg == other.alg and self.content == other.content
    
    def __hash__(self) -> int:
        return hash((self.alg, self.content))


@dataclass
class Property:
    """
    Key-value metadata property using AI-SCS namespaces.
    
    AI-SCS defines specific property namespaces for different artifact types.
    Properties enable extended metadata beyond core CycloneDX fields.
    
    Namespaces:
        ai-scs:* - AI-SCS standard properties (profile, version)
        ai.model.* - Model properties (type, format, baseModelRef)
        ai.data.* - Dataset properties (type, source, license)
        ai.embedding.* - Embedding properties (dimension)
        ai.vector.* - Vector store properties (indexType, updatePolicy)
        ai.agent.* - Agent properties (type, permittedTools)
        ai.tool.* - Tool properties (type, capability, endpoint)
        ai.mcp.* - MCP server properties (endpoint, capabilities, trustBoundary)
        ai.prompt.* - Prompt properties (type)
        ai.policy.* - Policy properties (type, enforcement)
        ai.infra.* - Infrastructure properties (type, teeType)
    
    Attributes:
        name: Property name using namespace (e.g., "ai.model.format")
        value: Property value as string
    
    Example:
        >>> p = Property(name="ai.model.format", value="safetensors")
        >>> p.to_dict()
        {'name': 'ai.model.format', 'value': 'safetensors'}
    """
    name: str
    value: str
    
    def __post_init__(self) -> None:
        """Validate property name is not empty."""
        if not self.name:
            raise ValueError("Property name cannot be empty")
        if self.value is None:
            self.value = ""
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to CycloneDX property format."""
        return {"name": self.name, "value": self.value}
    
    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> "Property":
        """Create Property from dictionary."""
        return cls(name=d["name"], value=d.get("value", ""))
    
    @property
    def namespace(self) -> str:
        """
        Get property namespace (first segment before dot).
        
        Returns:
            str: Namespace (e.g., "ai" from "ai.model.format")
        """
        return self.name.split(".")[0] if "." in self.name else self.name


@dataclass
class ExternalReference:
    """
    External reference for linking to external resources.
    
    AI-SCS Requirements:
        - Section 5.3.1: Base model reference (for fine-tuned models)
        - Section 5.3.5: MCP endpoint references
    
    Attributes:
        type: Reference type (e.g., "documentation", "website", "vcs", "distribution")
        url: URL or URI to external resource
        comment: Optional description
        hashes: Optional hashes for referenced resource
    
    Example:
        >>> ref = ExternalReference(
        ...     type="distribution",
        ...     url="https://huggingface.co/meta-llama/Llama-2-7b",
        ...     comment="Base model"
        ... )
    """
    type: str
    url: str
    comment: Optional[str] = None
    hashes: Optional[List[Hash]] = None
    
    def __post_init__(self) -> None:
        """Validate and normalize external reference."""
        if not self.type:
            raise ValueError("ExternalReference type cannot be empty")
        if not self.url:
            raise ValueError("ExternalReference url cannot be empty")
        
        if self.hashes:
            self.hashes = [
                Hash.from_dict(h) if isinstance(h, dict) else h 
                for h in self.hashes
            ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to CycloneDX external reference format."""
        r: Dict[str, Any] = {"type": self.type, "url": self.url}
        if self.comment:
            r["comment"] = self.comment
        if self.hashes:
            r["hashes"] = [h.to_dict() for h in self.hashes]
        return r
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExternalReference":
        """Create ExternalReference from dictionary."""
        hashes = None
        if d.get("hashes"):
            hashes = [Hash.from_dict(h) for h in d["hashes"]]
        return cls(
            type=d["type"],
            url=d["url"],
            comment=d.get("comment"),
            hashes=hashes
        )


@dataclass
class ABOMComponent:
    """
    ABOM Component representing an AI Supply Chain Asset.
    
    AI-SCS Section 5.3 defines mandatory fields per component type:
    
    5.3.1 Models (type="machine-learning-model"):
        REQUIRED: name, version, hash, format, supplier, baseModelRef (if fine-tuned)
        Properties: ai.model.type, ai.model.format, ai.model.baseModelRef
    
    5.3.2 Data (type="data"):
        REQUIRED: identifier, source, version, hash
        Properties: ai.data.type, ai.data.source, ai.data.license
    
    5.3.3 Dependencies (type="library"):
        REQUIRED: name, version
        Properties: ai.library.type
    
    5.3.4 Embeddings:
        REQUIRED: model identifier, vector store identifier, update policy
        Properties: ai.embedding.dimension, ai.vector.updatePolicy
    
    5.3.5 Agents/Tools (type="application"/"service"):
        REQUIRED: identifier, permitted tools (agents), capabilities (tools)
        MCP Servers REQUIRED: endpoint, capabilities, trustBoundary
        Properties: ai.agent.permittedTools, ai.mcp.endpoint, ai.mcp.trustBoundary
    
    5.3.6 Behavioral (type="data" with ai.prompt.* or ai.policy.*):
        REQUIRED: type reference
        Properties: ai.prompt.type, ai.policy.type
    
    Attributes:
        type: CycloneDX component type
        name: Component name (REQUIRED)
        version: Component version (REQUIRED)
        bom_ref: Unique reference within ABOM
        hashes: Cryptographic hashes (REQUIRED for models per 5.3.1)
        properties: AI-SCS metadata properties
        description: Human-readable description
        purl: Package URL for dependencies
        supplier: Source organization (REQUIRED for models per 5.3.1)
        licenses: License information
        external_references: External references (base model, etc.)
    
    Example:
        >>> comp = ABOMComponent(
        ...     type="machine-learning-model",
        ...     name="llama-7b",
        ...     version="1.0.0",
        ...     hashes=[Hash(alg="SHA-256", content="abc...")],
        ...     properties=[
        ...         Property(name="ai.model.type", value="base"),
        ...         Property(name="ai.model.format", value="safetensors")
        ...     ],
        ...     supplier={"name": "Meta"}
        ... )
        >>> errors = comp.validate_ai_scs()
        >>> len(errors)
        0
    """
    type: str
    name: str
    version: str
    bom_ref: Optional[str] = None
    hashes: List[Hash] = field(default_factory=list)
    properties: List[Property] = field(default_factory=list)
    description: Optional[str] = None
    purl: Optional[str] = None
    supplier: Optional[Dict[str, str]] = None
    licenses: Optional[List[Dict[str, Any]]] = None
    external_references: Optional[List[ExternalReference]] = None
    
    def __post_init__(self) -> None:
        """Initialize and normalize component data."""
        # Validate required fields
        if not self.name:
            raise ValueError("Component name cannot be empty")
        if not self.version:
            raise ValueError("Component version cannot be empty")
        if not self.type:
            raise ValueError("Component type cannot be empty")
        
        # Generate bom-ref if not provided
        if not self.bom_ref:
            prefix_map = {
                "machine-learning-model": "model",
                "data": "data",
                "service": "tool",
                "application": "agent",
                "library": "lib",
                "platform": "platform",
                "device": "device",
            }
            prefix = prefix_map.get(self.type, "comp")
            # Sanitize name for bom-ref (remove special chars)
            safe_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in self.name)
            self.bom_ref = f"{prefix}:{safe_name}@{self.version}"
        
        # Convert dict hashes to Hash objects
        self.hashes = [
            Hash.from_dict(h) if isinstance(h, dict) else h 
            for h in self.hashes
        ]
        
        # Convert dict properties to Property objects
        self.properties = [
            Property.from_dict(p) if isinstance(p, dict) else p 
            for p in self.properties
        ]
        
        # Convert dict external_references to ExternalReference objects
        if self.external_references:
            self.external_references = [
                ExternalReference.from_dict(e) if isinstance(e, dict) else e
                for e in self.external_references
            ]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to CycloneDX component format.
        
        Returns:
            dict: CycloneDX-compliant component dictionary
        """
        r: Dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "bom-ref": self.bom_ref,
        }
        
        if self.hashes:
            r["hashes"] = [h.to_dict() for h in self.hashes]
        if self.properties:
            r["properties"] = [p.to_dict() for p in self.properties]
        if self.description:
            r["description"] = self.description
        if self.purl:
            r["purl"] = self.purl
        if self.supplier:
            r["supplier"] = self.supplier
        if self.licenses:
            r["licenses"] = self.licenses
        if self.external_references:
            r["externalReferences"] = [e.to_dict() for e in self.external_references]
        
        return r
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ABOMComponent":
        """
        Create ABOMComponent from dictionary.
        
        Args:
            d: Dictionary with component data
        
        Returns:
            ABOMComponent instance
        
        Raises:
            KeyError: If required fields missing
        """
        if "type" not in d or "name" not in d or "version" not in d:
            raise KeyError("Component dict must contain 'type', 'name', and 'version'")
        
        external_refs = None
        if d.get("externalReferences"):
            external_refs = [ExternalReference.from_dict(e) for e in d["externalReferences"]]
        
        return cls(
            type=d["type"],
            name=d["name"],
            version=d["version"],
            bom_ref=d.get("bom-ref"),
            hashes=[Hash.from_dict(h) for h in d.get("hashes", [])],
            properties=[Property.from_dict(p) for p in d.get("properties", [])],
            description=d.get("description"),
            purl=d.get("purl"),
            supplier=d.get("supplier"),
            licenses=d.get("licenses"),
            external_references=external_refs,
        )
    
    def get_property(self, name: str) -> Optional[str]:
        """
        Get property value by name.
        
        Args:
            name: Property name (e.g., "ai.model.format")
        
        Returns:
            Property value or None if not found
        """
        for p in self.properties:
            if p.name == name:
                return p.value
        return None
    
    def set_property(self, name: str, value: str) -> None:
        """
        Set or update a property value.
        
        Args:
            name: Property name
            value: Property value
        """
        for p in self.properties:
            if p.name == name:
                p.value = value
                return
        self.properties.append(Property(name=name, value=value))
    
    def has_property(self, name: str) -> bool:
        """Check if property exists."""
        return any(p.name == name for p in self.properties)
    
    def get_artifact_type(self) -> Optional[ArtifactType]:
        """
        Determine AI-SCS artifact type from component.
        
        Returns:
            ArtifactType enum or None if cannot be determined
        """
        # Check explicit artifact type property first
        explicit = self.get_property("ai-scs:artifactType")
        if explicit:
            try:
                return ArtifactType(explicit)
            except ValueError:
                pass
        
        # Infer from component type and properties
        if self.type == "machine-learning-model":
            model_type = self.get_property("ai.model.type")
            if model_type == "base":
                return ArtifactType.BASE_MODEL
            elif model_type == "fine-tuned":
                return ArtifactType.FINE_TUNED_MODEL
            elif model_type and "adapter" in model_type.lower():
                return ArtifactType.ADAPTER
            elif self.get_property("ai.embedding.dimension"):
                return ArtifactType.EMBEDDING_MODEL
            return ArtifactType.MODEL
        
        if self.type == "data":
            # Check for behavioral artifacts first
            if self.get_property("ai.prompt.type"):
                return ArtifactType.PROMPT_TEMPLATE
            if self.get_property("ai.policy.type"):
                return ArtifactType.POLICY
            
            data_type = self.get_property("ai.data.type")
            if data_type == "training":
                return ArtifactType.TRAINING_DATA
            elif data_type == "fine-tuning":
                return ArtifactType.FINETUNING_DATA
            elif data_type == "evaluation":
                return ArtifactType.EVALUATION_DATA
            
            # Check for vector store
            if self.get_property("ai.vector.indexType"):
                return ArtifactType.VECTOR_INDEX
            
            return ArtifactType.DATASET
        
        if self.type == "service":
            tool_type = self.get_property("ai.tool.type")
            if tool_type == "mcp-server":
                return ArtifactType.MCP_SERVER
            elif tool_type == "tool-router":
                return ArtifactType.TOOL_ROUTER
            elif tool_type == "plugin":
                return ArtifactType.PLUGIN
            elif tool_type == "external-api":
                return ArtifactType.EXTERNAL_API
            return ArtifactType.TOOL
        
        if self.type == "application":
            agent_type = self.get_property("ai.agent.type")
            if agent_type == "planner":
                return ArtifactType.PLANNER
            elif agent_type == "orchestrator":
                return ArtifactType.ORCHESTRATOR
            return ArtifactType.AGENT
        
        if self.type == "library":
            lib_type = self.get_property("ai.library.type")
            if lib_type == "framework":
                return ArtifactType.FRAMEWORK
            elif lib_type == "tokenizer":
                return ArtifactType.TOKENIZER
            elif lib_type == "inference-engine":
                return ArtifactType.INFERENCE_ENGINE
            return ArtifactType.RUNTIME_LIBRARY
        
        if self.type == "platform":
            if self.get_property("ai.infra.teeType"):
                return ArtifactType.TEE
            return ArtifactType.EXECUTION_ENV
        
        if self.type == "device":
            return ArtifactType.ACCELERATOR
        
        return None
    
    def validate_ai_scs(self) -> List[str]:
        """
        Validate component against AI-SCS mandatory field requirements.
        
        Checks all requirements from AI-SCS Section 5.3.x based on component type.
        
        Returns:
            List of validation error messages (empty if valid)
        
        Example:
            >>> comp = ABOMComponent(type="machine-learning-model", name="test", version="1.0")
            >>> errors = comp.validate_ai_scs()
            >>> "missing cryptographic hash" in errors[0].lower()
            True
        """
        errors: List[str] = []
        
        # 5.3.1 Model Information
        if self.type == "machine-learning-model":
            # Hash is REQUIRED
            if not self.hashes:
                errors.append(
                    f"Model '{self.name}': missing cryptographic hash (AI-SCS 5.3.1)"
                )
            
            # Format is REQUIRED
            if not self.get_property("ai.model.format"):
                errors.append(
                    f"Model '{self.name}': missing ai.model.format (AI-SCS 5.3.1)"
                )
            
            # Supplier (source organization) is REQUIRED
            if not self.supplier:
                errors.append(
                    f"Model '{self.name}': missing supplier/source organization (AI-SCS 5.3.1)"
                )
            
            # Base model reference REQUIRED for fine-tuned/adapter models
            model_type = self.get_property("ai.model.type")
            if model_type in ("fine-tuned", "adapter", "adapter-lora", "adapter-peft"):
                if not self.get_property("ai.model.baseModelRef"):
                    errors.append(
                        f"Model '{self.name}': fine-tuned/adapter model missing "
                        f"ai.model.baseModelRef (AI-SCS 5.3.1)"
                    )
        
        # 5.3.2 Data Provenance
        if self.type == "data":
            # Skip validation for behavioral artifacts (5.3.6) and vector stores (5.3.4)
            is_behavioral = self.get_property("ai.prompt.type") or self.get_property("ai.policy.type")
            is_vector_store = self.get_property("ai.vector.indexType") or self.get_property("ai.vector.updatePolicy")
            
            if not is_behavioral and not is_vector_store:
                # Dataset type REQUIRED
                if not self.get_property("ai.data.type"):
                    errors.append(
                        f"Dataset '{self.name}': missing ai.data.type (AI-SCS 5.3.2)"
                    )
                
                # Source REQUIRED
                if not self.get_property("ai.data.source") and not self.supplier:
                    errors.append(
                        f"Dataset '{self.name}': missing ai.data.source or supplier (AI-SCS 5.3.2)"
                    )
        
        # 5.3.4 Embedding Information
        if self.get_property("ai.vector.indexType"):
            # Update policy REQUIRED for vector stores
            if not self.get_property("ai.vector.updatePolicy"):
                errors.append(
                    f"Vector store '{self.name}': missing ai.vector.updatePolicy (AI-SCS 5.3.4)"
                )
        
        # 5.3.5 Agent and Tool Declarations
        if self.type == "application":
            # Agent type REQUIRED
            if not self.get_property("ai.agent.type"):
                errors.append(
                    f"Agent '{self.name}': missing ai.agent.type (AI-SCS 5.3.5)"
                )
            
            # Permitted tools REQUIRED for agents
            if not self.get_property("ai.agent.permittedTools"):
                errors.append(
                    f"Agent '{self.name}': missing ai.agent.permittedTools (AI-SCS 5.3.5)"
                )
        
        if self.type == "service":
            tool_type = self.get_property("ai.tool.type")
            
            # MCP Server specific requirements
            if tool_type == "mcp-server":
                # Endpoint REQUIRED
                if not self.get_property("ai.mcp.endpoint"):
                    errors.append(
                        f"MCP Server '{self.name}': missing ai.mcp.endpoint (AI-SCS 5.3.5)"
                    )
                
                # Capabilities REQUIRED
                if not self.get_property("ai.mcp.capabilities"):
                    errors.append(
                        f"MCP Server '{self.name}': missing ai.mcp.capabilities (AI-SCS 5.3.5)"
                    )
                
                # Trust boundary REQUIRED
                if not self.get_property("ai.mcp.trustBoundary"):
                    errors.append(
                        f"MCP Server '{self.name}': missing ai.mcp.trustBoundary (AI-SCS 5.3.5)"
                    )
            
            # Tool capability REQUIRED for all tools
            elif tool_type and not self.get_property("ai.tool.capability"):
                errors.append(
                    f"Tool '{self.name}': missing ai.tool.capability (AI-SCS 5.3.5)"
                )
        
        # 5.3.6 Behavioral and Policy Artifacts
        if self.get_property("ai.prompt.type") or self.get_property("ai.policy.type"):
            # These are behavioral artifacts - check for hash
            if not self.hashes:
                errors.append(
                    f"Behavioral artifact '{self.name}': SHOULD have hash for integrity (AI-SCS 5.3.6)"
                )
        
        return errors


@dataclass
class ABOMDependency:
    """
    Dependency relationship in the ABOM.
    
    AI-SCS Section 5.3.3 requires explicit dependency graph including
    transitive dependencies and version constraints.
    
    Attributes:
        ref: bom-ref of the component with dependencies
        depends_on: List of bom-refs this component depends on
    
    Example:
        >>> dep = ABOMDependency(
        ...     ref="agent:my-agent@1.0",
        ...     depends_on=["model:llama@7b", "tool:search@1.0"]
        ... )
    """
    ref: str
    depends_on: List[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """Validate dependency reference."""
        if not self.ref:
            raise ValueError("Dependency ref cannot be empty")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to CycloneDX dependency format."""
        r: Dict[str, Any] = {"ref": self.ref}
        if self.depends_on:
            r["dependsOn"] = self.depends_on
        return r
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ABOMDependency":
        """Create ABOMDependency from dictionary."""
        return cls(
            ref=d["ref"],
            depends_on=d.get("dependsOn", [])
        )
    
    def add_dependency(self, bom_ref: str) -> None:
        """Add a dependency if not already present."""
        if bom_ref not in self.depends_on:
            self.depends_on.append(bom_ref)


@dataclass
class ABOMMetadata:
    """
    ABOM document metadata.
    
    AI-SCS Section 5.4 requires ABOM to be:
    - Machine-readable (JSON format)
    - Versioned (version field + serial number)
    - Immutable once published (serial number changes on update)
    - Cryptographically verifiable (signature support)
    
    Attributes:
        timestamp: ISO 8601 generation timestamp
        tools: List of tools that generated this ABOM
        component: The AI system this ABOM describes
        properties: AI-SCS metadata properties (profile, version)
        authors: Optional list of ABOM authors
        supplier: Optional supplier information
    
    Example:
        >>> meta = ABOMMetadata()
        >>> meta.get_property("ai-scs:profile")
        'ABOM'
    """
    timestamp: str = field(default_factory=_now_iso)
    tools: List[Dict[str, str]] = field(default_factory=list)
    component: Optional[Dict[str, Any]] = None
    properties: List[Property] = field(default_factory=list)
    authors: Optional[List[Dict[str, str]]] = None
    supplier: Optional[Dict[str, str]] = None
    
    def __post_init__(self) -> None:
        """Initialize metadata with defaults."""
        # Set default tool if not provided
        if not self.tools:
            self.tools = [{
                "vendor": TOOL_VENDOR,
                "name": TOOL_NAME,
                "version": TOOL_VERSION
            }]
        
        # Convert dict properties to Property objects
        self.properties = [
            Property.from_dict(p) if isinstance(p, dict) else p 
            for p in self.properties
        ]
        
        # Ensure AI-SCS profile property is present
        if not any(p.name == "ai-scs:profile" for p in self.properties):
            self.properties.insert(0, Property(name="ai-scs:profile", value="ABOM"))
        
        # Ensure AI-SCS version property is present
        if not any(p.name == "ai-scs:version" for p in self.properties):
            self.properties.insert(1, Property(name="ai-scs:version", value=AI_SCS_VERSION))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to CycloneDX metadata format."""
        r: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "tools": self.tools,
        }
        if self.component:
            r["component"] = self.component
        if self.properties:
            r["properties"] = [p.to_dict() for p in self.properties]
        if self.authors:
            r["authors"] = self.authors
        if self.supplier:
            r["supplier"] = self.supplier
        return r
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ABOMMetadata":
        """Create ABOMMetadata from dictionary."""
        return cls(
            timestamp=d.get("timestamp", _now_iso()),
            tools=d.get("tools", []),
            component=d.get("component"),
            properties=[Property.from_dict(p) for p in d.get("properties", [])],
            authors=d.get("authors"),
            supplier=d.get("supplier"),
        )
    
    def set_system(self, name: str, version: str, sys_type: str, 
                   runtime: str = "cloud") -> None:
        """
        Set the AI system information.
        
        Args:
            name: System name
            version: System version
            sys_type: System type (llm, agent, pipeline, rag)
            runtime: Runtime environment (cloud, on-prem, edge, tee)
        """
        self.component = {
            "type": "application",
            "name": name,
            "version": version
        }
        self.set_property("ai.system.type", sys_type)
        self.set_property("ai.system.runtime", runtime)
    
    def set_property(self, name: str, value: str) -> None:
        """Set or update a metadata property."""
        for p in self.properties:
            if p.name == name:
                p.value = value
                return
        self.properties.append(Property(name=name, value=value))
    
    def get_property(self, name: str) -> Optional[str]:
        """Get metadata property value by name."""
        for p in self.properties:
            if p.name == name:
                return p.value
        return None


@dataclass
class ABOM:
    """
    AI Bill of Materials & Provenance - Root Document.
    
    AI-SCS Control Domain 1 (Section 5) compliant ABOM structure.
    Aligned with CycloneDX 1.6 specification.
    
    Requirements Implemented:
        5.1: Generate, maintain, and make available ABOM
        5.2: Enumerate ALL AI Supply Chain Assets
        5.3: Include all mandatory fields
        5.4: Machine-readable, versioned, immutable, cryptographically verifiable
        5.5: Enable detection, forensics, risk assessment, policy enforcement
    
    Attributes:
        components: List of AI Supply Chain Assets
        dependencies: Dependency relationships between components
        metadata: ABOM metadata including AI-SCS profile
        serial_number: Unique URN UUID identifier
        version: Document version (increments on updates)
        bom_format: Always "CycloneDX"
        spec_version: CycloneDX spec version (1.6)
        signature: Optional cryptographic signature
    
    Example:
        >>> from ai_scrm.abom import ABOM, ABOMBuilder
        >>> builder = ABOMBuilder()
        >>> builder.add_model(name="llama", version="7b", hash_value="abc...", format="safetensors")
        >>> abom = builder.finalize(system_name="my-agent")
        >>> abom.to_file("abom.json")
        >>> abom.validate()
        True
    """
    components: List[ABOMComponent] = field(default_factory=list)
    dependencies: List[ABOMDependency] = field(default_factory=list)
    metadata: ABOMMetadata = field(default_factory=ABOMMetadata)
    serial_number: str = field(default_factory=_generate_uuid)
    version: int = 1
    bom_format: str = "CycloneDX"
    spec_version: str = CYCLONEDX_SPEC_VERSION
    signature: Optional[Dict[str, Any]] = None
    
    def __post_init__(self) -> None:
        """Initialize and normalize ABOM data."""
        # Convert dict components to ABOMComponent objects
        self.components = [
            ABOMComponent.from_dict(c) if isinstance(c, dict) else c 
            for c in self.components
        ]
        
        # Convert dict dependencies to ABOMDependency objects
        self.dependencies = [
            ABOMDependency.from_dict(d) if isinstance(d, dict) else d 
            for d in self.dependencies
        ]
        
        # Convert dict metadata to ABOMMetadata object
        if isinstance(self.metadata, dict):
            self.metadata = ABOMMetadata.from_dict(self.metadata)
    
    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        """
        Convert ABOM to CycloneDX-compliant dictionary.
        
        Args:
            include_signature: Whether to include signature in output
        
        Returns:
            dict: CycloneDX 1.6 compliant ABOM dictionary
        """
        r: Dict[str, Any] = {
            "$schema": f"https://cyclonedx.org/schema/bom-{self.spec_version}.schema.json",
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": self.metadata.to_dict(),
            "components": [c.to_dict() for c in self.components],
            "dependencies": [d.to_dict() for d in self.dependencies],
        }
        
        if include_signature and self.signature:
            r["signature"] = self.signature
        
        return r
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ABOM":
        """
        Create ABOM from dictionary.
        
        Args:
            d: Dictionary with ABOM data
        
        Returns:
            ABOM instance
        
        Raises:
            ABOMParseError: If parsing fails
        """
        try:
            return cls(
                bom_format=d.get("bomFormat", "CycloneDX"),
                spec_version=d.get("specVersion", CYCLONEDX_SPEC_VERSION),
                serial_number=d.get("serialNumber", _generate_uuid()),
                version=d.get("version", 1),
                metadata=ABOMMetadata.from_dict(d.get("metadata", {})),
                components=[ABOMComponent.from_dict(c) for c in d.get("components", [])],
                dependencies=[ABOMDependency.from_dict(dep) for dep in d.get("dependencies", [])],
                signature=d.get("signature"),
            )
        except Exception as e:
            raise ABOMParseError(f"Failed to parse ABOM: {e}")
    
    @classmethod
    def from_json(cls, s: str) -> "ABOM":
        """
        Create ABOM from JSON string.
        
        Args:
            s: JSON string
        
        Returns:
            ABOM instance
        
        Raises:
            ABOMParseError: If JSON parsing fails
        """
        try:
            return cls.from_dict(json.loads(s))
        except json.JSONDecodeError as e:
            raise ABOMParseError(f"Invalid JSON: {e}")
    
    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ABOM":
        """
        Load ABOM from JSON file.
        
        Args:
            path: Path to JSON file
        
        Returns:
            ABOM instance
        
        Raises:
            FileNotFoundError: If file doesn't exist
            ABOMParseError: If parsing fails
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"ABOM file not found: {path}")
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except Exception as e:
            raise ABOMParseError(f"Failed to load ABOM from {path}: {e}")
    
    def to_json(self, pretty: bool = True) -> str:
        """
        Serialize ABOM to JSON string.
        
        Args:
            pretty: Whether to format with indentation
        
        Returns:
            JSON string
        """
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            ensure_ascii=False
        )
    
    def to_file(self, path: Union[str, Path]) -> None:
        """
        Save ABOM to JSON file.
        
        Args:
            path: Output file path
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"ABOM saved to: {path}")
    
    def canonicalize(self) -> bytes:
        """
        Get canonical JSON representation for signing.
        
        AI-SCS 5.4 requires ABOM to be cryptographically verifiable.
        
        Returns:
            bytes: Canonical UTF-8 encoded JSON
        """
        return _canonicalize(self.to_dict(include_signature=False))
    
    def compute_hash(self, alg: str = "SHA-256") -> str:
        """
        Compute hash of canonical ABOM.
        
        Args:
            alg: Hash algorithm
        
        Returns:
            Hexadecimal hash digest
        """
        return _compute_hash(self.canonicalize(), alg)
    
    def validate(self) -> bool:
        """
        Validate ABOM structural integrity.
        
        Checks:
            - Serial number format (URN:UUID)
            - AI-SCS profile present
            - At least one component
            - Unique bom-refs
            - Models have hashes
            - Dependency refs exist
        
        Returns:
            True if valid
        
        Raises:
            ABOMValidationError: If validation fails with list of errors
        """
        errors: List[str] = []
        
        # Serial number format
        if not self.serial_number:
            errors.append("Missing serial number")
        elif not self.serial_number.startswith("urn:uuid:"):
            errors.append("Serial number must be URN:UUID format")
        
        # AI-SCS profile
        profile = self.metadata.get_property("ai-scs:profile")
        if profile != "ABOM":
            errors.append("Missing or invalid ai-scs:profile (must be 'ABOM')")
        
        # Must have components
        if not self.components:
            errors.append("ABOM must have at least one component")
        
        # Check unique bom-refs and models have hashes
        refs: set = set()
        for comp in self.components:
            if comp.bom_ref in refs:
                errors.append(f"Duplicate bom-ref: {comp.bom_ref}")
            refs.add(comp.bom_ref)
            
            # AI-SCS 5.3.1: Models MUST have hash
            if comp.type == "machine-learning-model" and not comp.hashes:
                errors.append(f"Model '{comp.bom_ref}' missing cryptographic hash (AI-SCS 5.3.1)")
        
        # Validate dependency refs exist
        for dep in self.dependencies:
            if dep.ref not in refs:
                errors.append(f"Dependency ref '{dep.ref}' not found in components")
            for depends_on in dep.depends_on:
                if depends_on not in refs:
                    errors.append(f"Dependency target '{depends_on}' not found in components")
        
        if errors:
            raise ABOMValidationError("ABOM validation failed", errors)
        
        logger.debug("ABOM validation passed")
        return True
    
    def validate_ai_scs(self, strict: bool = True) -> List[str]:
        """
        Validate ABOM against full AI-SCS standard requirements.
        
        Performs comprehensive validation against AI-SCS Section 5.3
        mandatory field requirements for each component type.
        
        Args:
            strict: If True, include all warnings
        
        Returns:
            List of validation issues (empty if fully compliant)
        """
        issues: List[str] = []
        
        # Run basic validation first
        try:
            self.validate()
        except ABOMValidationError as e:
            issues.extend(e.errors)
        
        # Validate each component against AI-SCS requirements
        for comp in self.components:
            comp_issues = comp.validate_ai_scs()
            issues.extend(comp_issues)
        
        # Check AI-SCS version present
        if not self.metadata.get_property("ai-scs:version"):
            issues.append("Missing ai-scs:version in metadata")
        
        return issues
    
    def add_component(self, component: ABOMComponent) -> None:
        """Add a component to the ABOM."""
        self.components.append(component)
    
    def get_component(self, bom_ref: str) -> Optional[ABOMComponent]:
        """
        Get component by bom-ref.
        
        Args:
            bom_ref: Component reference
        
        Returns:
            ABOMComponent or None if not found
        """
        for comp in self.components:
            if comp.bom_ref == bom_ref:
                return comp
        return None
    
    def add_dependency(self, ref: str, depends_on: Union[str, List[str]]) -> None:
        """
        Add a dependency relationship.
        
        Args:
            ref: bom-ref of component with dependencies
            depends_on: bom-ref(s) of dependencies
        """
        if isinstance(depends_on, str):
            depends_on = [depends_on]
        
        # Check if dependency already exists
        for dep in self.dependencies:
            if dep.ref == ref:
                for d in depends_on:
                    dep.add_dependency(d)
                return
        
        self.dependencies.append(ABOMDependency(ref=ref, depends_on=depends_on))
    
    def increment_version(self) -> None:
        """
        Increment version and generate new serial number.
        
        AI-SCS 5.4: ABOM must be versioned and immutable once published.
        This creates a new version with new serial number.
        """
        self.version += 1
        self.serial_number = _generate_uuid()
        self.metadata.timestamp = _now_iso()
        self.signature = None  # Invalidate signature
    
    # =========================================================================
    # Convenience methods for AI-SCS 4.1 asset categories
    # =========================================================================
    
    def get_models(self) -> List[ABOMComponent]:
        """Get all model components (4.1.1)."""
        return [c for c in self.components if c.type == "machine-learning-model"]
    
    def get_datasets(self) -> List[ABOMComponent]:
        """Get all dataset components (4.1.2)."""
        return [c for c in self.components 
                if c.type == "data" and not c.get_property("ai.prompt.type")]
    
    def get_embeddings(self) -> List[ABOMComponent]:
        """Get embedding models and vector stores (4.1.3)."""
        return [c for c in self.components 
                if c.get_property("ai.embedding.dimension") or 
                   c.get_property("ai.vector.indexType")]
    
    def get_dependencies(self) -> List[ABOMComponent]:
        """Get library/dependency components (4.1.4)."""
        return [c for c in self.components if c.type == "library"]
    
    def get_agents(self) -> List[ABOMComponent]:
        """Get agent components (4.1.5)."""
        return [c for c in self.components if c.type == "application"]
    
    def get_tools(self) -> List[ABOMComponent]:
        """Get tool/service components (4.1.6)."""
        return [c for c in self.components if c.type == "service"]
    
    def get_mcp_servers(self) -> List[ABOMComponent]:
        """Get MCP server components specifically (5.3.5)."""
        return [c for c in self.components 
                if c.get_property("ai.tool.type") == "mcp-server"]
    
    def get_infrastructure(self) -> List[ABOMComponent]:
        """Get infrastructure components (4.1.7)."""
        return [c for c in self.components 
                if c.type in ("platform", "device")]
    
    def get_behavioral_artifacts(self) -> List[ABOMComponent]:
        """Get behavioral/policy artifacts (5.3.6)."""
        return [c for c in self.components 
                if c.get_property("ai.prompt.type") or 
                   c.get_property("ai.policy.type")]
    
    def __len__(self) -> int:
        """Return number of components."""
        return len(self.components)
    
    def __iter__(self) -> Iterator[ABOMComponent]:
        """Iterate over components."""
        return iter(self.components)
    
    def summary(self) -> Dict[str, Any]:
        """
        Get summary statistics about the ABOM.
        
        Returns:
            dict: Summary with counts for all AI-SCS asset categories
        """
        return {
            "serial_number": self.serial_number,
            "version": self.version,
            "timestamp": self.metadata.timestamp,
            "ai_scs_version": self.metadata.get_property("ai-scs:version"),
            "total_components": len(self.components),
            "models": len(self.get_models()),
            "datasets": len(self.get_datasets()),
            "embeddings": len(self.get_embeddings()),
            "dependencies": len(self.get_dependencies()),
            "agents": len(self.get_agents()),
            "tools": len(self.get_tools()),
            "mcp_servers": len(self.get_mcp_servers()),
            "infrastructure": len(self.get_infrastructure()),
            "behavioral_artifacts": len(self.get_behavioral_artifacts()),
            "dependency_relationships": len(self.dependencies),
            "signed": self.signature is not None,
        }
