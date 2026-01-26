"""
Test Suite - Control Domain 3: Validation (AI-SCS Section 7)

Tests for Continuous AI Supply Chain Validation.

AI-SCS Requirements Tested:
    - Section 7.1: Continuous validation requirement
    - Section 7.2: Runtime validation objectives
    - Section 7.2.1: Enforcement expectations
    - Section 7.3: Event emission
    - Section 7.4: Response integration

Run with: pytest tests/test_validation.py -v
"""
import pytest
import tempfile
from pathlib import Path


class TestObservation:
    """Test Observation class."""
    
    def test_observation_creation(self):
        """Test basic observation creation."""
        from ai_scrm.validation import Observation
        
        obs = Observation(
            type="model-integrity",
            result="compliant"
        )
        assert obs.type == "model-integrity"
        assert obs.result == "compliant"
    
    def test_observation_with_details(self):
        """Test observation with all fields."""
        from ai_scrm.validation import Observation
        
        obs = Observation(
            type="model-integrity",
            result="non-compliant",
            component_ref="model:llama@7b",
            details="Hash mismatch",
            expected="abc123",
            actual="xyz789"
        )
        
        d = obs.to_dict()
        assert d["componentRef"] == "model:llama@7b"
        assert d["expected"] == "abc123"
        assert d["actual"] == "xyz789"
    
    def test_observation_requires_type(self):
        """Test observation requires type."""
        from ai_scrm.validation import Observation
        
        with pytest.raises(ValueError, match="type"):
            Observation(type="", result="compliant")
    
    def test_observation_requires_result(self):
        """Test observation requires result."""
        from ai_scrm.validation import Observation
        
        with pytest.raises(ValueError, match="result"):
            Observation(type="model-integrity", result="")


class TestRADEEvent:
    """Test RADE event classes."""
    
    def test_rade_event_creation(self):
        """Test basic RADE event creation."""
        from ai_scrm.validation import RADEEvent, Observation
        
        event = RADEEvent(
            event_type="drift",
            observation=Observation(type="model-integrity", result="non-compliant"),
            abom_serial="urn:uuid:12345"
        )
        
        assert event.event_type == "drift"
        assert event.event_id.startswith("urn:uuid:")
    
    def test_drift_event(self):
        """AI-SCS 7.2: Drift events for deviations."""
        from ai_scrm.validation import DriftEvent, Observation
        
        event = DriftEvent(
            observation=Observation(
                type="model-substitution",
                result="non-compliant",
                details="Model hash does not match"
            ),
            abom_serial="urn:uuid:12345",
            severity="critical"
        )
        
        assert event.event_type == "drift"
        assert event.severity == "critical"
        assert event.requires_action()
    
    def test_attestation_event(self):
        """Test attestation for compliant systems."""
        from ai_scrm.validation import AttestationEvent, Observation
        
        event = AttestationEvent(
            observation=Observation(
                type="system-integrity",
                result="compliant",
                details="All components verified"
            ),
            abom_serial="urn:uuid:12345"
        )
        
        assert event.event_type == "attestation"
        assert event.is_compliant()
        assert not event.requires_action()
    
    def test_violation_event(self):
        """AI-SCS 7.3: Violation events for policy violations."""
        from ai_scrm.validation import ViolationEvent, Observation
        
        event = ViolationEvent(
            observation=Observation(
                type="tool-unauthorized",
                result="non-compliant",
                details="Attempted to use undeclared tool"
            ),
            abom_serial="urn:uuid:12345"
        )
        
        assert event.event_type == "violation"
        assert event.action_required
    
    def test_expiration_event(self):
        """AI-SCS 7.3: Expiration events for trust expiration."""
        from ai_scrm.validation import ExpirationEvent, Observation
        
        event = ExpirationEvent(
            observation=Observation(
                type="trust-expired",
                result="non-compliant",
                details="Trust assertion expired"
            ),
            abom_serial="urn:uuid:12345",
            severity="high"
        )
        
        assert event.event_type == "expiration"
    
    def test_event_to_json(self):
        """Test event JSON serialization."""
        from ai_scrm.validation import DriftEvent, Observation
        import json
        
        event = DriftEvent(
            observation=Observation(type="model-integrity", result="non-compliant"),
            abom_serial="urn:uuid:12345"
        )
        
        json_str = event.to_json()
        d = json.loads(json_str)
        
        assert d["eventType"] == "drift"
        assert d["abomBinding"]["serialNumber"] == "urn:uuid:12345"
    
    def test_event_requires_abom_serial(self):
        """Test event requires abom_serial."""
        from ai_scrm.validation import RADEEvent, Observation
        
        with pytest.raises(ValueError, match="abom_serial"):
            RADEEvent(
                event_type="drift",
                observation=Observation(type="test", result="compliant"),
                abom_serial=""
            )


class TestDriftDetector:
    """Test DriftDetector for AI-SCS 7.2."""
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.validation import DriftDetector
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        detector = DriftDetector(abom, system_name="test-system")
        assert detector.system_name == "test-system"
    
    def test_detector_requires_abom(self):
        """Test detector requires ABOM."""
        from ai_scrm.validation import DriftDetector
        
        with pytest.raises(ValueError, match="ABOM"):
            DriftDetector(None)
    
    def test_check_component_matching(self):
        """Test checking component with matching hash."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.validation import DriftDetector
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        detector = DriftDetector(abom)
        
        event = detector.check_component("model:test@1.0", "abc123")
        assert event.is_compliant()
    
    def test_check_component_mismatch(self):
        """AI-SCS 7.2: Detect model substitution."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.validation import DriftDetector
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        detector = DriftDetector(abom)
        
        event = detector.check_component("model:test@1.0", "xyz789")
        
        assert event.event_type == "drift"
        assert event.severity == "critical"
    
    def test_check_tool_authorized(self):
        """AI-SCS 7.2: Detect unauthorized tool activation."""
        from ai_scrm.abom import ABOM, ABOMComponent, Property
        from ai_scrm.validation import DriftDetector
        
        tool = ABOMComponent(
            type="service",
            name="search-tool",
            version="1.0",
            properties=[Property(name="ai.tool.type", value="plugin")]
        )
        abom = ABOM(components=[tool])
        detector = DriftDetector(abom)
        
        # Authorized tool
        event = detector.check_tool_authorized("search-tool")
        assert event.is_compliant()
        
        # Unauthorized tool
        event = detector.check_tool_authorized("unknown-tool")
        assert event.event_type == "violation"
    
    def test_check_mcp_authorized(self):
        """AI-SCS 7.2: Detect unauthorized MCP server."""
        from ai_scrm.abom import ABOM, ABOMComponent, Property
        from ai_scrm.validation import DriftDetector
        
        mcp = ABOMComponent(
            type="service",
            name="file-server",
            version="1.0",
            properties=[
                Property(name="ai.tool.type", value="mcp-server"),
                Property(name="ai.mcp.endpoint", value="http://localhost:3000")
            ]
        )
        abom = ABOM(components=[mcp])
        detector = DriftDetector(abom)
        
        # Authorized MCP
        event = detector.check_mcp_authorized("file-server")
        assert event.is_compliant()
        
        # Unauthorized MCP
        event = detector.check_mcp_authorized("unknown-mcp")
        assert event.event_type == "violation"
    
    def test_check_mcp_endpoint_mismatch(self):
        """AI-SCS 5.3.5: Verify MCP endpoint matches."""
        from ai_scrm.abom import ABOM, ABOMComponent, Property
        from ai_scrm.validation import DriftDetector
        
        mcp = ABOMComponent(
            type="service",
            name="file-server",
            version="1.0",
            properties=[
                Property(name="ai.tool.type", value="mcp-server"),
                Property(name="ai.mcp.endpoint", value="http://localhost:3000")
            ]
        )
        abom = ABOM(components=[mcp])
        detector = DriftDetector(abom)
        
        # Endpoint mismatch
        event = detector.check_mcp_authorized(
            "file-server",
            endpoint="http://malicious:9999"
        )
        assert event.event_type == "drift"


class TestRADEEmitter:
    """Test RADEEmitter for AI-SCS 7.3, 7.4."""
    
    def test_emitter_creation(self):
        """Test emitter initialization."""
        from ai_scrm.validation import RADEEmitter
        
        emitter = RADEEmitter(system_name="test-system")
        assert emitter.system_name == "test-system"
    
    def test_add_file_handler(self):
        """AI-SCS 7.3: Emit structured events."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, Observation
        
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        
        try:
            emitter = RADEEmitter()
            emitter.add_file_handler(path)
            
            event = DriftEvent(
                observation=Observation(type="test", result="non-compliant"),
                abom_serial="urn:uuid:12345"
            )
            emitter.emit(event)
            
            # Check file was written
            content = path.read_text()
            assert "drift" in content
            assert "urn:uuid:12345" in content
        finally:
            path.unlink()
    
    def test_emit_sets_defaults(self):
        """Test emitter sets system_name on events."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, Observation
        
        events_received = []
        
        def handler(event):
            events_received.append(event)
        
        emitter = RADEEmitter(system_name="my-system", environment="production")
        emitter.add_handler(handler)
        
        event = DriftEvent(
            observation=Observation(type="test", result="non-compliant"),
            abom_serial="urn:uuid:12345"
        )
        emitter.emit(event)
        
        assert events_received[0].system_name == "my-system"
        assert events_received[0].environment == "production"
    
    def test_emit_all(self):
        """Test emitting multiple events."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, AttestationEvent, Observation
        
        events_received = []
        
        emitter = RADEEmitter()
        emitter.add_handler(lambda e: events_received.append(e))
        
        events = [
            DriftEvent(
                observation=Observation(type="test1", result="non-compliant"),
                abom_serial="urn:uuid:12345"
            ),
            AttestationEvent(
                observation=Observation(type="test2", result="compliant"),
                abom_serial="urn:uuid:12345"
            ),
        ]
        emitter.emit_all(events)
        
        assert len(events_received) == 2
    
    def test_statistics(self):
        """Test emission statistics."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, ViolationEvent, Observation
        
        emitter = RADEEmitter()
        
        emitter.emit(DriftEvent(
            observation=Observation(type="test", result="non-compliant"),
            abom_serial="urn:uuid:12345"
        ))
        emitter.emit(ViolationEvent(
            observation=Observation(type="test", result="non-compliant"),
            abom_serial="urn:uuid:12345"
        ))
        
        stats = emitter.get_statistics()
        assert stats["total_events"] == 2
        assert stats["drift_events"] == 1
        assert stats["violation_events"] == 1
    
    def test_fail_on_critical(self):
        """AI-SCS 7.3: MUST NOT continue without policy approval."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, Observation
        from ai_scrm.validation.exceptions import ValidationError
        
        emitter = RADEEmitter(fail_on_critical=True)
        
        event = DriftEvent(
            observation=Observation(type="test", result="non-compliant"),
            abom_serial="urn:uuid:12345",
            severity="critical"
        )
        
        with pytest.raises(ValidationError, match="Critical"):
            emitter.emit(event)


class TestPolicyEngine:
    """Test PolicyEngine for AI-SCS 7.2.1."""
    
    def test_policy_rule_evaluation(self):
        """AI-SCS 7.2.1: Enforcement expectations."""
        from ai_scrm.validation import RADEEmitter, DriftEvent, Observation
        from ai_scrm.validation.emitter import PolicyEngine
        
        actions_taken = []
        
        def block_action(event):
            actions_taken.append("blocked")
        
        def alert_action(event):
            actions_taken.append("alerted")
        
        engine = PolicyEngine()
        engine.add_rule(
            lambda e: e.severity == "critical",
            block_action
        )
        engine.add_rule(
            lambda e: e.event_type == "drift",
            alert_action
        )
        
        # Critical event - should trigger block
        event = DriftEvent(
            observation=Observation(type="test", result="non-compliant"),
            abom_serial="urn:uuid:12345",
            severity="critical"
        )
        engine.evaluate(event)
        
        assert "blocked" in actions_taken
        assert "alerted" not in actions_taken  # First match wins
    
    def test_policy_default_action(self):
        """Test default action when no rules match."""
        from ai_scrm.validation import AttestationEvent, Observation
        from ai_scrm.validation.emitter import PolicyEngine
        
        default_called = []
        
        engine = PolicyEngine(
            default_action=lambda e: default_called.append(True)
        )
        
        event = AttestationEvent(
            observation=Observation(type="test", result="compliant"),
            abom_serial="urn:uuid:12345"
        )
        engine.evaluate(event)
        
        assert len(default_called) == 1


class TestEnforcementAction:
    """Test EnforcementAction enum for AI-SCS 7.2.1."""
    
    def test_enforcement_actions_defined(self):
        """AI-SCS 7.2.1: Required enforcement actions."""
        from ai_scrm.validation import EnforcementAction
        
        # Prevent execution
        assert EnforcementAction.BLOCK
        assert EnforcementAction.PREVENT_EXECUTION
        
        # Disable components
        assert EnforcementAction.DISABLE_TOOL
        assert EnforcementAction.DISABLE_MCP
        
        # Revert
        assert EnforcementAction.REVERT
        assert EnforcementAction.ROLLBACK
        
        # Fail closed
        assert EnforcementAction.FAIL_CLOSED
        
        # Alert
        assert EnforcementAction.ALERT


class TestConformanceLevels:
    """Test AI-SCS Section 8 Conformance Levels."""
    
    def test_level1_visibility(self):
        """Level 1: ABOM generation, static provenance tracking."""
        from ai_scrm.abom import ABOMBuilder
        
        # Can generate ABOM
        builder = ABOMBuilder()
        builder.add_model(name="test", version="1.0", hash_value="abc", format="safetensors", supplier="Test")
        abom = builder.finalize(system_name="test")
        
        # Has provenance (supplier, hash)
        assert abom.components[0].supplier is not None
        assert len(abom.components[0].hashes) > 0
    
    def test_level2_integrity(self):
        """Level 2: Artifact signing, verification enforcement."""
        pytest.importorskip("cryptography")
        
        from ai_scrm.abom import ABOMBuilder
        from ai_scrm.trust import Signer, Verifier
        
        builder = ABOMBuilder()
        builder.add_model(name="test", version="1.0", hash_value="abc", format="safetensors", supplier="Test")
        abom = builder.finalize(system_name="test")
        
        # Can sign
        signer = Signer.generate("ed25519")
        signer.sign(abom)
        assert abom.signature is not None
        
        # Can verify
        verifier = Verifier()
        assert verifier.verify(abom)
    
    def test_level3_continuous_assurance(self):
        """Level 3: Runtime validation, automated detection."""
        from ai_scrm.abom import ABOMBuilder
        from ai_scrm.validation import DriftDetector, RADEEmitter
        
        builder = ABOMBuilder()
        builder.add_model(name="test", version="1.0", hash_value="abc123", format="safetensors", supplier="Test")
        abom = builder.finalize(system_name="test")
        
        # Can detect drift
        detector = DriftDetector(abom)
        event = detector.check_component("model:test@1.0", "xyz789")
        assert event.event_type == "drift"
        
        # Can emit events
        emitter = RADEEmitter()
        events_emitted = []
        emitter.add_handler(lambda e: events_emitted.append(e))
        emitter.emit(event)
        assert len(events_emitted) == 1
