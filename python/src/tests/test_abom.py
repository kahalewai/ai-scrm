"""
Test Suite - Control Domain 1: ABOM (AI-SCS Section 5)

Tests for AI Bill of Materials & Provenance compliance.

AI-SCS Requirements Tested:
    - Section 4.1: All 7 asset categories
    - Section 5.3.1: Model mandatory fields
    - Section 5.3.2: Data provenance fields
    - Section 5.3.3: Dependency graph
    - Section 5.3.4: Embedding information
    - Section 5.3.5: Agent and tool declarations
    - Section 5.3.6: Behavioral artifacts
    - Section 5.4: ABOM properties (machine-readable, versioned, etc.)

Run with: pytest tests/test_abom.py -v
"""
import pytest
import json
import tempfile
from pathlib import Path


class TestHash:
    """Test Hash class for AI-SCS 5.3.1, 6.2 compliance."""
    
    def test_hash_creation(self):
        """Test basic hash creation."""
        from ai_scrm.abom import Hash
        
        h = Hash(alg="SHA-256", content="abc123def456")
        assert h.alg == "SHA-256"
        assert h.content == "abc123def456"
    
    def test_hash_normalization(self):
        """Test algorithm and content normalization."""
        from ai_scrm.abom import Hash
        
        # Algorithm normalization
        h1 = Hash(alg="sha_256", content="ABC123")
        assert h1.alg == "SHA-256"
        assert h1.content == "abc123"  # Lowercase
        
        h2 = Hash(alg="sha256", content="DEF456")
        assert h2.alg == "SHA-256"
    
    def test_hash_equality(self):
        """Test hash equality comparison."""
        from ai_scrm.abom import Hash
        
        h1 = Hash(alg="SHA-256", content="abc123")
        h2 = Hash(alg="sha-256", content="ABC123")
        assert h1 == h2
    
    def test_hash_to_dict(self):
        """Test hash serialization."""
        from ai_scrm.abom import Hash
        
        h = Hash(alg="SHA-256", content="abc123")
        d = h.to_dict()
        assert d == {"alg": "SHA-256", "content": "abc123"}
    
    def test_hash_from_dict(self):
        """Test hash deserialization."""
        from ai_scrm.abom import Hash
        
        d = {"alg": "SHA-256", "content": "abc123"}
        h = Hash.from_dict(d)
        assert h.alg == "SHA-256"
        assert h.content == "abc123"
    
    def test_hash_empty_validation(self):
        """Test that empty hash raises error."""
        from ai_scrm.abom import Hash
        
        with pytest.raises(ValueError, match="cannot be empty"):
            Hash(alg="", content="abc")
        
        with pytest.raises(ValueError, match="cannot be empty"):
            Hash(alg="SHA-256", content="")


class TestProperty:
    """Test Property class for AI-SCS namespaces."""
    
    def test_property_creation(self):
        """Test property creation."""
        from ai_scrm.abom import Property
        
        p = Property(name="ai.model.format", value="safetensors")
        assert p.name == "ai.model.format"
        assert p.value == "safetensors"
    
    def test_property_namespace(self):
        """Test namespace extraction."""
        from ai_scrm.abom import Property
        
        p = Property(name="ai.model.format", value="safetensors")
        assert p.namespace == "ai"
    
    def test_property_empty_name_validation(self):
        """Test that empty name raises error."""
        from ai_scrm.abom import Property
        
        with pytest.raises(ValueError, match="cannot be empty"):
            Property(name="", value="test")


class TestABOMComponent:
    """Test ABOMComponent for AI-SCS 5.3.x mandatory fields."""
    
    def test_model_requires_hash(self):
        """AI-SCS 5.3.1: Models MUST have cryptographic hash."""
        from ai_scrm.abom import ABOMComponent
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test-model",
            version="1.0.0"
        )
        errors = comp.validate_ai_scs()
        assert any("hash" in e.lower() for e in errors)
    
    def test_model_requires_format(self):
        """AI-SCS 5.3.1: Models MUST have format."""
        from ai_scrm.abom import ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test-model",
            version="1.0.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        errors = comp.validate_ai_scs()
        assert any("format" in e.lower() for e in errors)
    
    def test_model_requires_supplier(self):
        """AI-SCS 5.3.1: Models MUST have source organization."""
        from ai_scrm.abom import ABOMComponent, Hash, Property
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test-model",
            version="1.0.0",
            hashes=[Hash(alg="SHA-256", content="abc123")],
            properties=[Property(name="ai.model.format", value="safetensors")]
        )
        errors = comp.validate_ai_scs()
        assert any("supplier" in e.lower() for e in errors)
    
    def test_fine_tuned_requires_base_ref(self):
        """AI-SCS 5.3.1: Fine-tuned models MUST have base model reference."""
        from ai_scrm.abom import ABOMComponent, Hash, Property
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test-model-ft",
            version="1.0.0",
            hashes=[Hash(alg="SHA-256", content="abc123")],
            properties=[
                Property(name="ai.model.format", value="safetensors"),
                Property(name="ai.model.type", value="fine-tuned")
            ],
            supplier={"name": "Test Org"}
        )
        errors = comp.validate_ai_scs()
        assert any("baseModelRef" in e for e in errors)
    
    def test_dataset_requires_type(self):
        """AI-SCS 5.3.2: Datasets MUST have type."""
        from ai_scrm.abom import ABOMComponent
        
        comp = ABOMComponent(
            type="data",
            name="test-dataset",
            version="1.0.0"
        )
        errors = comp.validate_ai_scs()
        assert any("type" in e.lower() for e in errors)
    
    def test_dataset_requires_source(self):
        """AI-SCS 5.3.2: Datasets MUST have source."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="data",
            name="test-dataset",
            version="1.0.0",
            properties=[Property(name="ai.data.type", value="training")]
        )
        errors = comp.validate_ai_scs()
        assert any("source" in e.lower() for e in errors)
    
    def test_vector_store_requires_update_policy(self):
        """AI-SCS 5.3.4: Vector stores MUST have update policy."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="data",
            name="test-vector-store",
            version="1.0.0",
            properties=[Property(name="ai.vector.indexType", value="HNSW")]
        )
        errors = comp.validate_ai_scs()
        assert any("updatePolicy" in e for e in errors)
    
    def test_agent_requires_type(self):
        """AI-SCS 5.3.5: Agents MUST have type."""
        from ai_scrm.abom import ABOMComponent
        
        comp = ABOMComponent(
            type="application",
            name="test-agent",
            version="1.0.0"
        )
        errors = comp.validate_ai_scs()
        assert any("type" in e.lower() for e in errors)
    
    def test_agent_requires_permitted_tools(self):
        """AI-SCS 5.3.5: Agents MUST have permitted tools."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="application",
            name="test-agent",
            version="1.0.0",
            properties=[Property(name="ai.agent.type", value="agent")]
        )
        errors = comp.validate_ai_scs()
        assert any("permittedTools" in e for e in errors)
    
    def test_mcp_requires_endpoint(self):
        """AI-SCS 5.3.5: MCP servers MUST have endpoint."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="service",
            name="test-mcp",
            version="1.0.0",
            properties=[Property(name="ai.tool.type", value="mcp-server")]
        )
        errors = comp.validate_ai_scs()
        assert any("endpoint" in e.lower() for e in errors)
    
    def test_mcp_requires_trust_boundary(self):
        """AI-SCS 5.3.5: MCP servers MUST have trust boundary."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="service",
            name="test-mcp",
            version="1.0.0",
            properties=[
                Property(name="ai.tool.type", value="mcp-server"),
                Property(name="ai.mcp.endpoint", value="http://localhost:3000")
            ]
        )
        errors = comp.validate_ai_scs()
        assert any("trustBoundary" in e for e in errors)
    
    def test_mcp_requires_capabilities(self):
        """AI-SCS 5.3.5: MCP servers MUST have capabilities."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="service",
            name="test-mcp",
            version="1.0.0",
            properties=[
                Property(name="ai.tool.type", value="mcp-server"),
                Property(name="ai.mcp.endpoint", value="http://localhost:3000"),
                Property(name="ai.mcp.trustBoundary", value="internal")
            ]
        )
        errors = comp.validate_ai_scs()
        assert any("capabilities" in e.lower() for e in errors)
    
    def test_valid_model_no_errors(self):
        """Test fully compliant model has no validation errors."""
        from ai_scrm.abom import ABOMComponent, Hash, Property
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="valid-model",
            version="1.0.0",
            hashes=[Hash(alg="SHA-256", content="abc123")],
            properties=[
                Property(name="ai.model.type", value="base"),
                Property(name="ai.model.format", value="safetensors")
            ],
            supplier={"name": "Test Org"}
        )
        errors = comp.validate_ai_scs()
        assert len(errors) == 0
    
    def test_valid_mcp_no_errors(self):
        """Test fully compliant MCP server has no validation errors."""
        from ai_scrm.abom import ABOMComponent, Property
        
        comp = ABOMComponent(
            type="service",
            name="valid-mcp",
            version="1.0.0",
            properties=[
                Property(name="ai.tool.type", value="mcp-server"),
                Property(name="ai.mcp.endpoint", value="http://localhost:3000"),
                Property(name="ai.mcp.trustBoundary", value="internal"),
                Property(name="ai.mcp.capabilities", value="read,write")
            ]
        )
        errors = comp.validate_ai_scs()
        assert len(errors) == 0


class TestABOM:
    """Test ABOM class for AI-SCS 5.4 compliance."""
    
    def test_abom_has_ai_scs_profile(self):
        """AI-SCS 5.4: ABOM must identify profile."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        assert abom.metadata.get_property("ai-scs:profile") == "ABOM"
    
    def test_abom_has_ai_scs_version(self):
        """AI-SCS 5.4: ABOM must have version."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        assert abom.metadata.get_property("ai-scs:version") == "0.1"
    
    def test_abom_serial_number_format(self):
        """AI-SCS 5.4: Serial number must be URN:UUID."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        assert abom.serial_number.startswith("urn:uuid:")
    
    def test_abom_cyclonedx_16(self):
        """ABOM must use CycloneDX 1.6."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        assert abom.spec_version == "1.6"
        d = abom.to_dict()
        assert "1.6" in d["$schema"]
    
    def test_abom_validation_rejects_duplicate_refs(self):
        """ABOM must not have duplicate bom-refs."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.abom.exceptions import ABOMValidationError
        
        comp1 = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            bom_ref="duplicate-ref",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        comp2 = ABOMComponent(
            type="machine-learning-model",
            name="test2",
            version="1.0",
            bom_ref="duplicate-ref",
            hashes=[Hash(alg="SHA-256", content="def456")]
        )
        abom = ABOM(components=[comp1, comp2])
        
        with pytest.raises(ABOMValidationError, match="Duplicate"):
            abom.validate()
    
    def test_abom_serialization_roundtrip(self):
        """ABOM must survive JSON serialization roundtrip."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash, Property
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")],
            properties=[Property(name="ai.model.format", value="safetensors")]
        )
        abom = ABOM(components=[comp])
        
        json_str = abom.to_json()
        loaded = ABOM.from_json(json_str)
        
        assert loaded.serial_number == abom.serial_number
        assert len(loaded.components) == 1
        assert loaded.components[0].name == "test"
    
    def test_abom_file_roundtrip(self):
        """ABOM must survive file save/load roundtrip."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        
        try:
            abom.to_file(path)
            loaded = ABOM.from_file(path)
            assert loaded.serial_number == abom.serial_number
        finally:
            path.unlink()
    
    def test_abom_get_models(self):
        """Test filtering models from ABOM."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        
        model = ABOMComponent(
            type="machine-learning-model",
            name="model",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        tool = ABOMComponent(
            type="service",
            name="tool",
            version="1.0"
        )
        abom = ABOM(components=[model, tool])
        
        models = abom.get_models()
        assert len(models) == 1
        assert models[0].name == "model"
    
    def test_abom_get_mcp_servers(self):
        """Test filtering MCP servers from ABOM."""
        from ai_scrm.abom import ABOM, ABOMComponent, Property
        
        mcp = ABOMComponent(
            type="service",
            name="mcp-server",
            version="1.0",
            properties=[Property(name="ai.tool.type", value="mcp-server")]
        )
        tool = ABOMComponent(
            type="service",
            name="tool",
            version="1.0"
        )
        abom = ABOM(components=[mcp, tool])
        
        mcps = abom.get_mcp_servers()
        assert len(mcps) == 1
        assert mcps[0].name == "mcp-server"


class TestABOMBuilder:
    """Test ABOMBuilder for AI-SCS 4.1 asset categories."""
    
    def test_add_model(self):
        """Test adding model (4.1.1)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_model(
            name="llama-7b",
            version="1.0.0",
            hash_value="abc123",
            format="safetensors",
            supplier="Meta"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].type == "machine-learning-model"
        assert builder.components[0].get_property("ai.model.format") == "safetensors"
    
    def test_add_model_requires_hash(self):
        """Test model requires hash."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        with pytest.raises(ValueError, match="hash_value"):
            builder.add_model(name="test", version="1.0", hash_value="")
    
    def test_add_fine_tuned_model_requires_base_ref(self):
        """Test fine-tuned model requires base_model_ref."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        with pytest.raises(ValueError, match="base_model_ref"):
            builder.add_fine_tuned_model(
                name="test-ft",
                version="1.0",
                hash_value="abc123",
                base_model_ref=""
            )
    
    def test_add_dataset(self):
        """Test adding dataset (4.1.2)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_dataset(
            name="training-data",
            version="1.0",
            data_type="training",
            source="internal"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].type == "data"
        assert builder.components[0].get_property("ai.data.type") == "training"
    
    def test_add_embedding_model(self):
        """Test adding embedding model (4.1.3)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_embedding_model(
            name="ada-002",
            version="1.0",
            hash_value="abc123",
            dimension="1536"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].get_property("ai.embedding.dimension") == "1536"
    
    def test_add_vector_store(self):
        """Test adding vector store (4.1.3)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_vector_store(
            name="docs-index",
            version="1.0",
            index_type="HNSW",
            update_policy="append-only"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].get_property("ai.vector.updatePolicy") == "append-only"
    
    def test_add_library(self):
        """Test adding library (4.1.4)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_library(name="transformers", version="4.36.0")
        
        assert len(builder.components) == 1
        assert builder.components[0].type == "library"
        assert builder.components[0].purl == "pkg:pypi/transformers@4.36.0"
    
    def test_add_agent(self):
        """Test adding agent (4.1.5)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_agent(
            name="research-agent",
            version="1.0",
            permitted_tools=["search", "browse"]
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].type == "application"
        assert "search" in builder.components[0].get_property("ai.agent.permittedTools")
    
    def test_add_tool(self):
        """Test adding tool (4.1.6)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_tool(
            name="calculator",
            version="1.0",
            capability="Perform math"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].type == "service"
    
    def test_add_mcp_server(self):
        """Test adding MCP server (4.1.6, 5.3.5)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_mcp_server(
            name="file-server",
            version="1.0",
            endpoint="http://localhost:3000",
            trust_boundary="internal",
            capabilities=["read", "write"]
        )
        
        assert len(builder.components) == 1
        comp = builder.components[0]
        assert comp.get_property("ai.tool.type") == "mcp-server"
        assert comp.get_property("ai.mcp.endpoint") == "http://localhost:3000"
        assert comp.get_property("ai.mcp.trustBoundary") == "internal"
    
    def test_add_mcp_requires_endpoint(self):
        """Test MCP server requires endpoint."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        with pytest.raises(ValueError, match="endpoint"):
            builder.add_mcp_server(
                name="test",
                version="1.0",
                endpoint="",
                trust_boundary="internal"
            )
    
    def test_add_mcp_requires_trust_boundary(self):
        """Test MCP server requires trust_boundary."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        with pytest.raises(ValueError, match="trust_boundary"):
            builder.add_mcp_server(
                name="test",
                version="1.0",
                endpoint="http://localhost",
                trust_boundary=""
            )
    
    def test_add_prompt_template(self):
        """Test adding prompt template (5.3.6)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_prompt_template(
            name="system-prompt",
            version="1.0",
            prompt_type="system"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].get_property("ai.prompt.type") == "system"
    
    def test_add_policy(self):
        """Test adding policy (5.3.6)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_policy(
            name="content-filter",
            version="1.0",
            policy_type="guardrail",
            enforcement="block"
        )
        
        assert len(builder.components) == 1
        assert builder.components[0].get_property("ai.policy.enforcement") == "block"
    
    def test_add_dependency(self):
        """Test adding dependency relationship (5.3.3)."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_model(name="llama", version="7b", hash_value="abc", format="safetensors", supplier="Meta")
        builder.add_agent(name="agent", version="1.0", permitted_tools=[])
        builder.add_dependency(
            from_ref="agent:agent@1.0",
            to_refs=["model:llama@7b"]
        )
        
        assert len(builder.dependencies) == 1
        assert "model:llama@7b" in builder.dependencies[0].depends_on
    
    def test_finalize_creates_abom(self):
        """Test finalize creates valid ABOM."""
        from ai_scrm.abom import ABOMBuilder
        
        builder = ABOMBuilder()
        builder.add_model(name="test", version="1.0", hash_value="abc", format="safetensors", supplier="Test")
        
        abom = builder.finalize(system_name="test-system", system_type="llm")
        
        assert abom.metadata.component["name"] == "test-system"
        assert abom.metadata.get_property("ai.system.type") == "llm"
    
    def test_finalize_requires_components(self):
        """Test finalize fails with no components."""
        from ai_scrm.abom import ABOMBuilder
        from ai_scrm.abom.exceptions import ABOMValidationError
        
        builder = ABOMBuilder()
        with pytest.raises(ABOMValidationError, match="No components"):
            builder.finalize()
    
    def test_method_chaining(self):
        """Test fluent builder pattern."""
        from ai_scrm.abom import ABOMBuilder
        
        abom = (
            ABOMBuilder()
            .add_model(name="m1", version="1.0", hash_value="abc", format="safetensors", supplier="Test")
            .add_dataset(name="d1", version="1.0", source="internal")
            .add_tool(name="t1", version="1.0", capability="test")
            .finalize(system_name="test")
        )
        
        assert len(abom.components) == 3
