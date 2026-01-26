"""
ABOM Builder - AI-SCS Compliant Builder Pattern

This module provides a fluent builder interface for creating AI-SCS compliant
ABOM documents. It ensures all mandatory fields from AI-SCS Section 5.3 are
properly captured for each asset category.

AI-SCS Compliance:
    - Section 4.1: All 7 asset categories with dedicated methods
    - Section 5.3.1: Model information with hash, format, supplier, base_model_ref
    - Section 5.3.2: Data provenance with type, source, license
    - Section 5.3.3: Dependency graph support
    - Section 5.3.4: Embedding info with dimension, update_policy
    - Section 5.3.5: Agent/tool declarations with MCP server support
    - Section 5.3.6: Behavioral artifacts (prompts, policies)

Usage:
    >>> from ai_scrm.abom import ABOMBuilder
    >>> builder = ABOMBuilder()
    >>> builder.add_model(
    ...     name="llama-7b",
    ...     version="1.0.0",
    ...     hash_value="abc123...",
    ...     format="safetensors",
    ...     supplier="Meta"
    ... )
    >>> builder.add_mcp_server(
    ...     name="file-server",
    ...     version="1.0.0",
    ...     endpoint="http://localhost:3000",
    ...     trust_boundary="internal",
    ...     capabilities=["read", "write"]
    ... )
    >>> abom = builder.finalize(system_name="my-agent", system_type="agent")
    >>> abom.to_file("abom.json")

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import logging
from typing import List, Optional, Union, Dict, Any

from ai_scrm.abom.models import (
    ABOM,
    ABOMComponent,
    ABOMDependency,
    Hash,
    Property,
    ExternalReference,
    ArtifactType,
)
from ai_scrm.abom.exceptions import ABOMValidationError

# Configure logging
logger = logging.getLogger(__name__)


class ABOMBuilder:
    """
    Fluent builder for creating AI-SCS compliant ABOM documents.
    
    This builder provides dedicated methods for each AI-SCS 4.1 asset category,
    ensuring all mandatory fields from Section 5.3 are properly captured.
    
    Asset Category Methods:
        4.1.1 Models: add_model(), add_fine_tuned_model(), add_adapter()
        4.1.2 Data: add_dataset(), add_training_data(), add_evaluation_data()
        4.1.3 Embeddings: add_embedding_model(), add_vector_store()
        4.1.4 Dependencies: add_library(), add_framework(), add_tokenizer()
        4.1.5 Agents: add_agent(), add_planner(), add_orchestrator()
        4.1.6 Tools: add_tool(), add_mcp_server(), add_external_api()
        4.1.7 Infrastructure: add_infrastructure(), add_tee(), add_accelerator()
        5.3.6 Behavioral: add_prompt_template(), add_policy(), add_guardrail()
    
    Attributes:
        components: List of components added to the builder
        dependencies: List of dependency relationships
    
    Example:
        >>> builder = ABOMBuilder()
        >>> builder.add_model(
        ...     name="gpt-4",
        ...     version="1.0",
        ...     hash_value="abc...",
        ...     format="pytorch",
        ...     supplier="OpenAI"
        ... ).add_tool(
        ...     name="web-search",
        ...     version="1.0",
        ...     tool_type="plugin",
        ...     capability="Search the web"
        ... )
        >>> abom = builder.finalize(system_name="my-assistant")
    
    Test Cases:
        Input: builder.add_model(name="test", version="1.0", hash_value="abc")
        Expected: ABOMValidationError (missing format and supplier)
        
        Input: builder.finalize() with no components
        Expected: ABOMValidationError("No components added")
    """
    
    def __init__(self) -> None:
        """Initialize empty builder."""
        self.components: List[ABOMComponent] = []
        self.dependencies: List[ABOMDependency] = []
        logger.debug("ABOMBuilder initialized")
    
    # =========================================================================
    # Section 4.1.1: Models
    # =========================================================================
    
    def add_model(
        self,
        name: str,
        version: str,
        hash_value: str,
        hash_alg: str = "SHA-256",
        model_type: str = "base",
        format: Optional[str] = None,
        supplier: Optional[str] = None,
        base_model_ref: Optional[str] = None,
        architecture: Optional[str] = None,
        parameters: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a model component (AI-SCS 4.1.1, 5.3.1).
        
        AI-SCS 5.3.1 Mandatory Fields:
            - Model name (name parameter)
            - Model version (version parameter)
            - Cryptographic hash (hash_value parameter) - REQUIRED
            - Model format (format parameter) - REQUIRED
            - Source organization (supplier parameter) - REQUIRED
            - Base model reference (base_model_ref) - REQUIRED for fine-tuned/adapters
        
        Args:
            name: Model name (e.g., "llama-7b", "gpt-4")
            version: Model version (e.g., "1.0.0", "2024-01-15")
            hash_value: SHA-256 hash of model weights - REQUIRED
            hash_alg: Hash algorithm (default: SHA-256)
            model_type: One of "base", "fine-tuned", "adapter", "adapter-lora", 
                       "adapter-peft", "quantized", "merged"
            format: Model format - REQUIRED (safetensors, pytorch, gguf, onnx, etc.)
            supplier: Source organization - REQUIRED (e.g., "Meta", "OpenAI")
            base_model_ref: Reference to base model - REQUIRED for fine-tuned/adapters
            architecture: Model architecture (e.g., "transformer", "llama")
            parameters: Parameter count (e.g., "7B", "70B")
            description: Human-readable description
            **extra_properties: Additional ai.model.* properties
        
        Returns:
            self for method chaining
        
        Raises:
            ValueError: If hash_value is empty
        
        Example:
            >>> builder.add_model(
            ...     name="llama-2-7b",
            ...     version="1.0.0",
            ...     hash_value="a]b3c4d5e6f7...",
            ...     format="safetensors",
            ...     supplier="Meta",
            ...     model_type="base",
            ...     architecture="llama",
            ...     parameters="7B"
            ... )
        
        Test Cases:
            Input: add_model(name="test", version="1.0", hash_value="")
            Expected: ValueError("hash_value cannot be empty")
            
            Input: add_model(name="test", version="1.0", hash_value="abc", format="safetensors", supplier="Test")
            Expected: Component added with all required fields
        """
        # Validate required field
        if not hash_value:
            raise ValueError("hash_value cannot be empty (AI-SCS 5.3.1 requires cryptographic hash)")
        
        # Build properties list
        properties: List[Property] = [
            Property(name="ai.model.type", value=model_type),
        ]
        
        if format:
            properties.append(Property(name="ai.model.format", value=format))
        if architecture:
            properties.append(Property(name="ai.model.architecture", value=architecture))
        if parameters:
            properties.append(Property(name="ai.model.parameters", value=parameters))
        if base_model_ref:
            properties.append(Property(name="ai.model.baseModelRef", value=base_model_ref))
        
        # Add any extra properties
        for key, value in extra_properties.items():
            prop_name = f"ai.model.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        # Create component
        component = ABOMComponent(
            type="machine-learning-model",
            name=name,
            version=version,
            hashes=[Hash(alg=hash_alg, content=hash_value)],
            properties=properties,
            description=description,
            supplier={"name": supplier} if supplier else None,
        )
        
        self.components.append(component)
        logger.debug(f"Added model: {name}@{version}")
        return self
    
    def add_fine_tuned_model(
        self,
        name: str,
        version: str,
        hash_value: str,
        base_model_ref: str,
        format: Optional[str] = None,
        supplier: Optional[str] = None,
        training_data_ref: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a fine-tuned model (AI-SCS 4.1.1).
        
        Convenience method that sets model_type="fine-tuned" and requires base_model_ref.
        
        Args:
            name: Model name
            version: Model version
            hash_value: SHA-256 hash - REQUIRED
            base_model_ref: Reference to base model - REQUIRED
            format: Model format
            supplier: Source organization
            training_data_ref: Reference to training dataset
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_fine_tuned_model(
            ...     name="llama-2-7b-chat",
            ...     version="1.0.0",
            ...     hash_value="xyz789...",
            ...     base_model_ref="model:llama-2-7b@1.0.0",
            ...     format="safetensors",
            ...     supplier="Meta"
            ... )
        """
        if not base_model_ref:
            raise ValueError("base_model_ref is required for fine-tuned models (AI-SCS 5.3.1)")
        
        extra = dict(extra_properties)
        if training_data_ref:
            extra["trainingDataRef"] = training_data_ref
        
        return self.add_model(
            name=name,
            version=version,
            hash_value=hash_value,
            model_type="fine-tuned",
            format=format,
            supplier=supplier,
            base_model_ref=base_model_ref,
            description=description,
            **extra
        )
    
    def add_adapter(
        self,
        name: str,
        version: str,
        hash_value: str,
        base_model_ref: str,
        adapter_type: str = "lora",
        format: Optional[str] = None,
        supplier: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add an adapter layer (LoRA, PEFT, QLoRA) (AI-SCS 4.1.1).
        
        Args:
            name: Adapter name
            version: Adapter version
            hash_value: SHA-256 hash - REQUIRED
            base_model_ref: Reference to base model - REQUIRED
            adapter_type: Type of adapter (lora, peft, qlora)
            format: Adapter format
            supplier: Source organization
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        """
        if not base_model_ref:
            raise ValueError("base_model_ref is required for adapters (AI-SCS 5.3.1)")
        
        extra = dict(extra_properties)
        extra["adapterType"] = adapter_type
        
        return self.add_model(
            name=name,
            version=version,
            hash_value=hash_value,
            model_type=f"adapter-{adapter_type}",
            format=format,
            supplier=supplier,
            base_model_ref=base_model_ref,
            description=description,
            **extra
        )
    
    # =========================================================================
    # Section 4.1.2: Data
    # =========================================================================
    
    def add_dataset(
        self,
        name: str,
        version: str,
        data_type: str = "training",
        source: Optional[str] = None,
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        license: Optional[str] = None,
        record_count: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a dataset component (AI-SCS 4.1.2, 5.3.2).
        
        AI-SCS 5.3.2 Mandatory Fields:
            - Dataset identifier (name parameter)
            - Dataset source (source parameter) - REQUIRED
            - Dataset version/snapshot (version parameter)
            - Hashes or immutable references (hash_value parameter)
            - Licensing constraints (license parameter) - if applicable
        
        Args:
            name: Dataset identifier - REQUIRED
            version: Dataset version/snapshot - REQUIRED
            data_type: One of "training", "fine-tuning", "evaluation", "preference"
            source: Dataset source - REQUIRED (e.g., "huggingface", "internal")
            hash_value: Hash for immutable reference (recommended)
            hash_alg: Hash algorithm
            license: Licensing constraints (e.g., "CC-BY-4.0", "proprietary")
            record_count: Number of records (e.g., "1000000")
            description: Human-readable description
            **extra_properties: Additional ai.data.* properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_dataset(
            ...     name="dolly-15k",
            ...     version="1.0",
            ...     data_type="fine-tuning",
            ...     source="databricks",
            ...     license="CC-BY-SA-3.0",
            ...     record_count="15000"
            ... )
        """
        properties: List[Property] = [
            Property(name="ai.data.type", value=data_type),
        ]
        
        if source:
            properties.append(Property(name="ai.data.source", value=source))
        if license:
            properties.append(Property(name="ai.data.license", value=license))
        if record_count:
            properties.append(Property(name="ai.data.recordCount", value=record_count))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.data.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        hashes: List[Hash] = []
        if hash_value:
            hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        component = ABOMComponent(
            type="data",
            name=name,
            version=version,
            hashes=hashes,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added dataset: {name}@{version}")
        return self
    
    def add_training_data(
        self,
        name: str,
        version: str,
        source: Optional[str] = None,
        **kwargs
    ) -> "ABOMBuilder":
        """Convenience method for training datasets (4.1.2)."""
        return self.add_dataset(name=name, version=version, data_type="training", source=source, **kwargs)
    
    def add_evaluation_data(
        self,
        name: str,
        version: str,
        source: Optional[str] = None,
        **kwargs
    ) -> "ABOMBuilder":
        """Convenience method for evaluation datasets (4.1.2)."""
        return self.add_dataset(name=name, version=version, data_type="evaluation", source=source, **kwargs)
    
    # =========================================================================
    # Section 4.1.3: Embeddings
    # =========================================================================
    
    def add_embedding_model(
        self,
        name: str,
        version: str,
        hash_value: str,
        hash_alg: str = "SHA-256",
        dimension: Optional[str] = None,
        format: Optional[str] = "pytorch",
        supplier: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add an embedding model (AI-SCS 4.1.3, 5.3.4).
        
        AI-SCS 5.3.4 Mandatory Fields:
            - Embedding model identifier (name)
            - Dimension (dimension parameter)
        
        Also requires 5.3.1 model fields:
            - Hash, format, supplier
        
        Args:
            name: Embedding model name
            version: Model version
            hash_value: SHA-256 hash - REQUIRED
            hash_alg: Hash algorithm
            dimension: Vector dimension (e.g., "768", "1536")
            format: Model format (default: pytorch)
            supplier: Source organization
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_embedding_model(
            ...     name="text-embedding-ada-002",
            ...     version="1.0",
            ...     hash_value="abc123...",
            ...     dimension="1536",
            ...     supplier="OpenAI"
            ... )
        """
        if not hash_value:
            raise ValueError("hash_value is required for embedding models")
        
        properties: List[Property] = [
            Property(name="ai.model.type", value="embedding"),
        ]
        
        if dimension:
            properties.append(Property(name="ai.embedding.dimension", value=dimension))
        if format:
            properties.append(Property(name="ai.model.format", value=format))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.embedding.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="machine-learning-model",
            name=name,
            version=version,
            hashes=[Hash(alg=hash_alg, content=hash_value)],
            properties=properties,
            description=description,
            supplier={"name": supplier} if supplier else None,
        )
        
        self.components.append(component)
        logger.debug(f"Added embedding model: {name}@{version}")
        return self
    
    def add_vector_store(
        self,
        name: str,
        version: str,
        index_type: Optional[str] = None,
        update_policy: Optional[str] = None,
        embedding_model_ref: Optional[str] = None,
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a vector store/index (AI-SCS 4.1.3, 5.3.4).
        
        AI-SCS 5.3.4 Mandatory Fields:
            - Vector store identifier (name)
            - Index version (version)
            - Update policy (update_policy) - REQUIRED
        
        Args:
            name: Vector store name
            version: Index version
            index_type: Index type (HNSW, IVF, flat, etc.)
            update_policy: Update policy - REQUIRED (append-only, replace, incremental)
            embedding_model_ref: Reference to embedding model used
            hash_value: Hash of index data
            hash_alg: Hash algorithm
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_vector_store(
            ...     name="docs-index",
            ...     version="2024-01-15",
            ...     index_type="HNSW",
            ...     update_policy="append-only",
            ...     embedding_model_ref="model:text-embedding-ada-002@1.0"
            ... )
        """
        properties: List[Property] = []
        
        if index_type:
            properties.append(Property(name="ai.vector.indexType", value=index_type))
        if update_policy:
            properties.append(Property(name="ai.vector.updatePolicy", value=update_policy))
        if embedding_model_ref:
            properties.append(Property(name="ai.vector.embeddingModelRef", value=embedding_model_ref))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.vector.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        hashes: List[Hash] = []
        if hash_value:
            hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        component = ABOMComponent(
            type="data",
            name=name,
            version=version,
            hashes=hashes,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added vector store: {name}@{version}")
        return self
    
    # =========================================================================
    # Section 4.1.4: Dependencies
    # =========================================================================
    
    def add_library(
        self,
        name: str,
        version: str,
        lib_type: str = "runtime",
        purl: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a library/dependency (AI-SCS 4.1.4, 5.3.3).
        
        AI-SCS 5.3.3 Dependency Graph requires:
            - Software dependencies
            - AI-specific dependencies
            - Transitive dependencies
            - Version constraints
        
        Args:
            name: Library name
            version: Library version
            lib_type: Type (runtime, framework, tokenizer, inference-engine)
            purl: Package URL (auto-generated if not provided)
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_library(
            ...     name="transformers",
            ...     version="4.36.0",
            ...     lib_type="framework"
            ... )
        """
        properties: List[Property] = [
            Property(name="ai.library.type", value=lib_type),
        ]
        
        for key, value in extra_properties.items():
            prop_name = f"ai.library.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        # Auto-generate purl if not provided
        if not purl:
            purl = f"pkg:pypi/{name}@{version}"
        
        component = ABOMComponent(
            type="library",
            name=name,
            version=version,
            purl=purl,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added library: {name}@{version}")
        return self
    
    def add_framework(self, name: str, version: str, **kwargs) -> "ABOMBuilder":
        """Convenience method for frameworks (4.1.4)."""
        return self.add_library(name=name, version=version, lib_type="framework", **kwargs)
    
    def add_tokenizer(
        self,
        name: str,
        version: str,
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        **kwargs
    ) -> "ABOMBuilder":
        """
        Add a tokenizer (4.1.4).
        
        Tokenizers are AI-specific dependencies that may have their own hashes.
        """
        builder_result = self.add_library(name=name, version=version, lib_type="tokenizer", **kwargs)
        
        # If hash provided, add it to the last component
        if hash_value and self.components:
            self.components[-1].hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        return builder_result
    
    def add_inference_engine(self, name: str, version: str, **kwargs) -> "ABOMBuilder":
        """Convenience method for inference engines (4.1.4)."""
        return self.add_library(name=name, version=version, lib_type="inference-engine", **kwargs)
    
    # =========================================================================
    # Section 4.1.5: Agents
    # =========================================================================
    
    def add_agent(
        self,
        name: str,
        version: str,
        agent_type: str = "agent",
        permitted_tools: Optional[List[str]] = None,
        autonomy_level: str = "medium",
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add an agent component (AI-SCS 4.1.5, 5.3.5).
        
        AI-SCS 5.3.5 Mandatory Fields for Agents:
            - Agent identifier (name)
            - Agent type (agent_type) - agent, planner, orchestrator
            - Permitted tools (permitted_tools) - REQUIRED
        
        Args:
            name: Agent identifier
            version: Agent version
            agent_type: One of "agent", "planner", "orchestrator", "executor"
            permitted_tools: List of tool bom-refs - REQUIRED
            autonomy_level: Level (low, medium, high)
            hash_value: Hash of agent logic
            hash_alg: Hash algorithm
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_agent(
            ...     name="research-agent",
            ...     version="1.0.0",
            ...     agent_type="orchestrator",
            ...     permitted_tools=["tool:web-search@1.0", "tool:file-write@1.0"],
            ...     autonomy_level="high"
            ... )
        """
        properties: List[Property] = [
            Property(name="ai.agent.type", value=agent_type),
            Property(name="ai.agent.autonomyLevel", value=autonomy_level),
        ]
        
        if permitted_tools:
            properties.append(Property(
                name="ai.agent.permittedTools",
                value=",".join(permitted_tools)
            ))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.agent.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        hashes: List[Hash] = []
        if hash_value:
            hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        component = ABOMComponent(
            type="application",
            name=name,
            version=version,
            hashes=hashes,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added agent: {name}@{version}")
        return self
    
    def add_planner(self, name: str, version: str, **kwargs) -> "ABOMBuilder":
        """Convenience method for planners (4.1.5)."""
        return self.add_agent(name=name, version=version, agent_type="planner", **kwargs)
    
    def add_orchestrator(self, name: str, version: str, **kwargs) -> "ABOMBuilder":
        """Convenience method for orchestrators (4.1.5)."""
        return self.add_agent(name=name, version=version, agent_type="orchestrator", **kwargs)
    
    # =========================================================================
    # Section 4.1.6: Tools
    # =========================================================================
    
    def add_tool(
        self,
        name: str,
        version: str,
        tool_type: str = "plugin",
        capability: Optional[str] = None,
        has_side_effects: bool = False,
        auth_required: bool = False,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a tool/plugin component (AI-SCS 4.1.6, 5.3.5).
        
        AI-SCS 5.3.5 Mandatory Fields for Tools:
            - Tool identifier (name)
            - Tool capabilities (capability) - REQUIRED
        
        Args:
            name: Tool identifier
            version: Tool version
            tool_type: One of "plugin", "function-call", "external-api"
            capability: Tool capability description - REQUIRED
            has_side_effects: Whether tool has side effects
            auth_required: Whether authentication required
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_tool(
            ...     name="calculator",
            ...     version="1.0",
            ...     tool_type="function-call",
            ...     capability="Perform mathematical calculations"
            ... )
        """
        properties: List[Property] = [
            Property(name="ai.tool.type", value=tool_type),
            Property(name="ai.tool.sideEffects", value=str(has_side_effects).lower()),
            Property(name="ai.tool.authRequired", value=str(auth_required).lower()),
        ]
        
        if capability:
            properties.append(Property(name="ai.tool.capability", value=capability))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.tool.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="service",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added tool: {name}@{version}")
        return self
    
    def add_mcp_server(
        self,
        name: str,
        version: str,
        endpoint: str,
        trust_boundary: str,
        capabilities: Optional[List[str]] = None,
        service_id: Optional[str] = None,
        auth_required: bool = True,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add an MCP server component (AI-SCS 4.1.6, 5.3.5).
        
        AI-SCS 5.3.5 REQUIRES for MCP servers:
            - Service identifier (name or service_id)
            - Endpoint or logical reference (endpoint) - REQUIRED
            - Declared capabilities (capabilities) - REQUIRED
            - Trust or authorization boundary (trust_boundary) - REQUIRED
        
        Args:
            name: MCP server name
            version: Server version
            endpoint: Server endpoint URL - REQUIRED
            trust_boundary: Trust boundary - REQUIRED (internal, external, dmz)
            capabilities: List of capabilities - REQUIRED
            service_id: Optional service identifier
            auth_required: Whether authentication required
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Raises:
            ValueError: If required fields missing
        
        Example:
            >>> builder.add_mcp_server(
            ...     name="filesystem-server",
            ...     version="1.0.0",
            ...     endpoint="http://localhost:3000/mcp",
            ...     trust_boundary="internal",
            ...     capabilities=["read_file", "write_file", "list_directory"]
            ... )
        """
        # Validate required fields per AI-SCS 5.3.5
        if not endpoint:
            raise ValueError("endpoint is required for MCP servers (AI-SCS 5.3.5)")
        if not trust_boundary:
            raise ValueError("trust_boundary is required for MCP servers (AI-SCS 5.3.5)")
        
        properties: List[Property] = [
            Property(name="ai.tool.type", value="mcp-server"),
            Property(name="ai.mcp.endpoint", value=endpoint),
            Property(name="ai.mcp.trustBoundary", value=trust_boundary),
            Property(name="ai.tool.authRequired", value=str(auth_required).lower()),
        ]
        
        if service_id:
            properties.append(Property(name="ai.mcp.serviceId", value=service_id))
        if capabilities:
            properties.append(Property(name="ai.mcp.capabilities", value=",".join(capabilities)))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.mcp.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="service",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added MCP server: {name}@{version}")
        return self
    
    def add_external_api(
        self,
        name: str,
        version: str,
        endpoint: str,
        trust_boundary: str = "external",
        capability: Optional[str] = None,
        auth_required: bool = True,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add an external API dependency (AI-SCS 4.1.6, 5.3.5).
        
        Args:
            name: API name
            version: API version
            endpoint: API endpoint URL
            trust_boundary: Trust boundary (usually "external")
            capability: API capability description
            auth_required: Whether authentication required
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        """
        properties: List[Property] = [
            Property(name="ai.tool.type", value="external-api"),
            Property(name="ai.tool.endpoint", value=endpoint),
            Property(name="ai.tool.trustBoundary", value=trust_boundary),
            Property(name="ai.tool.authRequired", value=str(auth_required).lower()),
        ]
        
        if capability:
            properties.append(Property(name="ai.tool.capability", value=capability))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.tool.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="service",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added external API: {name}@{version}")
        return self
    
    def add_tool_router(
        self,
        name: str,
        version: str,
        endpoint: Optional[str] = None,
        trust_boundary: str = "internal",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """Add a tool router/broker (AI-SCS 4.1.6, 5.3.5)."""
        properties: List[Property] = [
            Property(name="ai.tool.type", value="tool-router"),
            Property(name="ai.tool.trustBoundary", value=trust_boundary),
        ]
        
        if endpoint:
            properties.append(Property(name="ai.tool.endpoint", value=endpoint))
        
        for key, value in extra_properties.items():
            prop_name = f"ai.tool.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="service",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        return self
    
    # =========================================================================
    # Section 4.1.7: Infrastructure
    # =========================================================================
    
    def add_infrastructure(
        self,
        name: str,
        version: str,
        infra_type: str = "execution-environment",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add infrastructure component (AI-SCS 4.1.7).
        
        Args:
            name: Infrastructure name
            version: Version
            infra_type: Type (execution-environment, tee, accelerator)
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        """
        properties: List[Property] = [
            Property(name="ai.infra.type", value=infra_type),
        ]
        
        for key, value in extra_properties.items():
            prop_name = f"ai.infra.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="platform",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        return self
    
    def add_tee(
        self,
        name: str,
        version: str,
        tee_type: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """Add Trusted Execution Environment (4.1.7)."""
        extra = dict(extra_properties)
        if tee_type:
            extra["teeType"] = tee_type
        return self.add_infrastructure(
            name=name, version=version, infra_type="tee",
            description=description, **extra
        )
    
    def add_accelerator(
        self,
        name: str,
        version: str,
        accelerator_type: Optional[str] = None,
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """Add accelerator (GPU, TPU, etc.) (4.1.7)."""
        extra = dict(extra_properties)
        if accelerator_type:
            extra["acceleratorType"] = accelerator_type
        
        properties: List[Property] = [
            Property(name="ai.infra.type", value="accelerator"),
        ]
        
        for key, value in extra.items():
            prop_name = f"ai.infra.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        component = ABOMComponent(
            type="device",
            name=name,
            version=version,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        return self
    
    # =========================================================================
    # Section 5.3.6: Behavioral and Policy Artifacts
    # =========================================================================
    
    def add_prompt_template(
        self,
        name: str,
        version: str,
        prompt_type: str = "system",
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a prompt template artifact (AI-SCS 5.3.6).
        
        AI-SCS 5.3.6 applies when prompts are externally managed or dynamically loaded.
        
        Args:
            name: Prompt template identifier
            version: Template version
            prompt_type: One of "system", "agent", "tool", "guardrail"
            hash_value: Hash for integrity verification
            hash_alg: Hash algorithm
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_prompt_template(
            ...     name="system-prompt-v1",
            ...     version="1.0.0",
            ...     prompt_type="system",
            ...     hash_value="abc123..."
            ... )
        """
        properties: List[Property] = [
            Property(name="ai.prompt.type", value=prompt_type),
        ]
        
        for key, value in extra_properties.items():
            prop_name = f"ai.prompt.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        hashes: List[Hash] = []
        if hash_value:
            hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        component = ABOMComponent(
            type="data",
            name=name,
            version=version,
            hashes=hashes,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        logger.debug(f"Added prompt template: {name}@{version}")
        return self
    
    def add_policy(
        self,
        name: str,
        version: str,
        policy_type: str = "guardrail",
        enforcement: str = "block",
        hash_value: Optional[str] = None,
        hash_alg: str = "SHA-256",
        description: Optional[str] = None,
        **extra_properties: str
    ) -> "ABOMBuilder":
        """
        Add a policy artifact (AI-SCS 5.3.6).
        
        Args:
            name: Policy identifier
            version: Policy version
            policy_type: Type (guardrail, routing, retrieval)
            enforcement: Enforcement mode (block, warn, log)
            hash_value: Hash for integrity
            hash_alg: Hash algorithm
            description: Description
            **extra_properties: Additional properties
        
        Returns:
            self for method chaining
        """
        properties: List[Property] = [
            Property(name="ai.policy.type", value=policy_type),
            Property(name="ai.policy.enforcement", value=enforcement),
        ]
        
        for key, value in extra_properties.items():
            prop_name = f"ai.policy.{key}" if not key.startswith("ai.") else key
            properties.append(Property(name=prop_name, value=str(value)))
        
        hashes: List[Hash] = []
        if hash_value:
            hashes.append(Hash(alg=hash_alg, content=hash_value))
        
        component = ABOMComponent(
            type="data",
            name=name,
            version=version,
            hashes=hashes,
            properties=properties,
            description=description,
        )
        
        self.components.append(component)
        return self
    
    def add_guardrail(self, name: str, version: str, **kwargs) -> "ABOMBuilder":
        """Convenience method for guardrails (5.3.6)."""
        return self.add_policy(name=name, version=version, policy_type="guardrail", **kwargs)
    
    # =========================================================================
    # Dependencies (AI-SCS 5.3.3)
    # =========================================================================
    
    def add_dependency(
        self,
        from_ref: str,
        to_refs: Union[str, List[str]]
    ) -> "ABOMBuilder":
        """
        Add a dependency relationship (AI-SCS 5.3.3).
        
        Args:
            from_ref: bom-ref of component with dependencies
            to_refs: bom-ref(s) of dependencies
        
        Returns:
            self for method chaining
        
        Example:
            >>> builder.add_dependency(
            ...     from_ref="agent:my-agent@1.0",
            ...     to_refs=["model:llama@7b", "tool:search@1.0"]
            ... )
        """
        if isinstance(to_refs, str):
            to_refs = [to_refs]
        
        # Check if dependency for this ref already exists
        for dep in self.dependencies:
            if dep.ref == from_ref:
                for ref in to_refs:
                    dep.add_dependency(ref)
                return self
        
        self.dependencies.append(ABOMDependency(ref=from_ref, depends_on=to_refs))
        logger.debug(f"Added dependency: {from_ref} -> {to_refs}")
        return self
    
    # =========================================================================
    # Build Methods
    # =========================================================================
    
    def finalize(
        self,
        system_name: str = "ai-system",
        system_version: str = "1.0.0",
        system_type: str = "llm",
        runtime: str = "cloud",
        validate: bool = True,
        validate_ai_scs: bool = False,
    ) -> ABOM:
        """
        Finalize and build the ABOM document.
        
        Args:
            system_name: Name of the AI system this ABOM describes
            system_version: Version of the AI system
            system_type: Type (llm, agent, pipeline, rag, hybrid)
            runtime: Runtime environment (cloud, on-prem, edge, tee)
            validate: Run basic validation
            validate_ai_scs: Run full AI-SCS compliance validation
        
        Returns:
            ABOM: Finalized ABOM document
        
        Raises:
            ABOMValidationError: If validation fails
        
        Example:
            >>> abom = builder.finalize(
            ...     system_name="my-assistant",
            ...     system_type="agent",
            ...     validate_ai_scs=True
            ... )
        """
        if not self.components:
            raise ABOMValidationError("No components added to builder", [])
        
        # Create ABOM
        abom = ABOM(
            components=list(self.components),
            dependencies=list(self.dependencies)
        )
        
        # Set system information
        abom.metadata.set_system(system_name, system_version, system_type, runtime)
        
        # Validate if requested
        if validate:
            abom.validate()
        
        if validate_ai_scs:
            issues = abom.validate_ai_scs()
            if issues:
                logger.warning(f"AI-SCS compliance issues found: {issues}")
        
        logger.info(f"ABOM finalized: {len(self.components)} components")
        return abom
    
    def reset(self) -> "ABOMBuilder":
        """
        Clear all components and dependencies.
        
        Returns:
            self for method chaining
        """
        self.components.clear()
        self.dependencies.clear()
        logger.debug("ABOMBuilder reset")
        return self
    
    def __len__(self) -> int:
        """Return number of components."""
        return len(self.components)
