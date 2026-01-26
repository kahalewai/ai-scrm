"""
RADE Events - Runtime Attestation & Drift Events

This module implements the event structures for AI-SCS Section 7 (Control Domain 3).
RADE events are structured notifications emitted during continuous validation.

AI-SCS Compliance:
    - Section 7.2: Runtime validation detection events
    - Section 7.3: Structured event emission requirements
    - Section 7.4: Response integration support (SIEM, SOAR, etc.)

AI-SCS 7.3 Event Emission Requirements:
    Systems MUST emit structured events for:
    - Verification failures of models, dependencies, or runtime libraries
    - ABOM deviations (undeclared MCP servers, tools, prompts, etc.)
    - Trust expiration of cryptographic or attested artifacts
    - Policy violations (unauthorized execution of tools, agents, services)

Event Types:
    - AttestationEvent: System is compliant with ABOM
    - DriftEvent: Deviation from ABOM detected
    - ViolationEvent: Policy violation detected
    - ExpirationEvent: Trust assertion expired

Usage:
    >>> from ai_scrm.validation import DriftEvent, Observation
    >>> 
    >>> event = DriftEvent(
    ...     abom_serial="urn:uuid:...",
    ...     observation=Observation(
    ...         type="model-integrity",
    ...         result="non-compliant",
    ...         details="Hash mismatch detected"
    ...     ),
    ...     severity="critical"
    ... )
    >>> print(event.to_json())

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import json
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


def _generate_uuid() -> str:
    """Generate URN UUID for event ID."""
    return f"urn:uuid:{uuid.uuid4()}"


def _now_iso() -> str:
    """Generate ISO 8601 timestamp in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventType(str, Enum):
    """
    RADE event types.
    
    Types align with AI-SCS Section 7 validation objectives.
    """
    ATTESTATION = "attestation"      # System compliant
    DRIFT = "drift"                  # Deviation detected (7.2)
    VIOLATION = "violation"          # Policy violation (7.3)
    EXPIRATION = "expiration"        # Trust expired (7.3)


class Severity(str, Enum):
    """
    Event severity levels.
    
    Severity indicates urgency and required response.
    """
    INFO = "info"           # Informational (attestation)
    LOW = "low"             # Minor deviation
    MEDIUM = "medium"       # Significant deviation
    HIGH = "high"           # Critical deviation requiring attention
    CRITICAL = "critical"   # Immediate action required (7.2.1)


class ObservationType(str, Enum):
    """
    Types of observations that can trigger events.
    
    Based on AI-SCS 7.2 Runtime Validation Objectives.
    """
    # Model integrity (7.2)
    MODEL_INTEGRITY = "model-integrity"
    MODEL_SUBSTITUTION = "model-substitution"
    
    # Dependency drift (7.2)
    DEPENDENCY_DRIFT = "dependency-drift"
    LIBRARY_DRIFT = "library-drift"
    
    # Tool/MCP validation (7.2)
    TOOL_UNAUTHORIZED = "tool-unauthorized"
    MCP_UNAUTHORIZED = "mcp-unauthorized"
    TOOL_ROUTER_UNAUTHORIZED = "tool-router-unauthorized"
    
    # Behavioral artifacts (7.2)
    PROMPT_MODIFIED = "prompt-modified"
    POLICY_MODIFIED = "policy-modified"
    CONFIG_MODIFIED = "config-modified"
    
    # Provenance (7.2)
    PROVENANCE_MISMATCH = "provenance-mismatch"
    
    # Trust (7.3)
    TRUST_EXPIRED = "trust-expired"
    SIGNATURE_INVALID = "signature-invalid"
    
    # Policy (7.3)
    POLICY_VIOLATION = "policy-violation"
    
    # System-level
    SYSTEM_INTEGRITY = "system-integrity"
    COMPONENT_INTEGRITY = "component-integrity"


@dataclass
class Observation:
    """
    Observation that triggered a RADE event.
    
    Captures the details of what was detected during validation.
    
    Attributes:
        type: Type of observation (from ObservationType)
        result: Validation result ("compliant", "non-compliant", "error")
        component_ref: Optional bom-ref of affected component
        details: Human-readable description
        expected: Expected value (for comparisons)
        actual: Actual value found
        evidence: Additional evidence data
    
    Example:
        >>> obs = Observation(
        ...     type="model-integrity",
        ...     result="non-compliant",
        ...     component_ref="model:llama@7b",
        ...     details="Hash mismatch",
        ...     expected="abc123...",
        ...     actual="xyz789..."
        ... )
    
    Test Cases:
        Input: Observation(type="model-integrity", result="compliant")
        Expected: Valid observation with minimal fields
        
        Input: Observation(type="", result="compliant")
        Expected: ValueError("type cannot be empty")
    """
    type: str
    result: str
    component_ref: Optional[str] = None
    details: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    
    def __post_init__(self) -> None:
        """Validate observation fields."""
        if not self.type:
            raise ValueError("Observation type cannot be empty")
        if not self.result:
            raise ValueError("Observation result cannot be empty")
        
        # Normalize result
        valid_results = ("compliant", "non-compliant", "error", "unknown")
        if self.result.lower() not in valid_results:
            logger.warning(f"Non-standard result value: {self.result}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result: Dict[str, Any] = {
            "type": self.type,
            "result": self.result,
        }
        
        if self.component_ref:
            result["componentRef"] = self.component_ref
        if self.details:
            result["details"] = self.details
        if self.expected:
            result["expected"] = self.expected
        if self.actual:
            result["actual"] = self.actual
        if self.evidence:
            result["evidence"] = self.evidence
        
        return result
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Observation":
        """Create Observation from dictionary."""
        return cls(
            type=d["type"],
            result=d["result"],
            component_ref=d.get("componentRef"),
            details=d.get("details"),
            expected=d.get("expected"),
            actual=d.get("actual"),
            evidence=d.get("evidence"),
        )


@dataclass
class RADEEvent:
    """
    Base RADE (Runtime Attestation & Drift Event) class.
    
    AI-SCS 7.3 requires structured event emission for all validation
    failures. This class provides the base structure for all RADE events.
    
    Attributes:
        observation: Observation that triggered the event
        abom_serial: Serial number of the ABOM being validated
        event_type: Type of event (attestation, drift, violation, expiration)
        event_id: Unique URN UUID for this event
        timestamp: ISO 8601 timestamp of event creation
        severity: Event severity level
        system_name: Name of the system being validated
        environment: Environment (production, staging, development)
        action_taken: Action taken in response (for 7.2.1)
        action_required: Whether further action is required
    
    Example:
        >>> event = RADEEvent(
        ...     observation=Observation(type="model-integrity", result="non-compliant"),
        ...     abom_serial="urn:uuid:...",
        ...     event_type="drift",
        ...     severity="critical"
        ... )
    """
    observation: Observation
    abom_serial: str
    event_type: str = "event"
    event_id: str = field(default_factory=_generate_uuid)
    timestamp: str = field(default_factory=_now_iso)
    severity: str = "info"
    system_name: Optional[str] = None
    environment: Optional[str] = None
    action_taken: Optional[str] = None
    action_required: bool = False
    
    def __post_init__(self) -> None:
        """Validate and normalize event fields."""
        if not self.abom_serial:
            raise ValueError("abom_serial is required")
        
        # Convert dict observation to Observation object
        if isinstance(self.observation, dict):
            self.observation = Observation.from_dict(self.observation)
        
        # Normalize severity
        self.severity = self.severity.lower()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format.
        
        Returns:
            dict: Event in standard RADE format for SIEM/SOAR integration
        """
        result: Dict[str, Any] = {
            "eventVersion": "1.0",
            "eventId": self.event_id,
            "eventType": self.event_type,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "abomBinding": {
                "serialNumber": self.abom_serial,
            },
            "observation": self.observation.to_dict(),
        }
        
        if self.system_name:
            result["systemName"] = self.system_name
        if self.environment:
            result["environment"] = self.environment
        if self.action_taken:
            result["actionTaken"] = self.action_taken
        if self.action_required:
            result["actionRequired"] = self.action_required
        
        return result
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RADEEvent":
        """Create RADEEvent from dictionary."""
        return cls(
            observation=Observation.from_dict(d["observation"]),
            abom_serial=d["abomBinding"]["serialNumber"],
            event_type=d["eventType"],
            event_id=d.get("eventId", _generate_uuid()),
            timestamp=d.get("timestamp", _now_iso()),
            severity=d.get("severity", "info"),
            system_name=d.get("systemName"),
            environment=d.get("environment"),
            action_taken=d.get("actionTaken"),
            action_required=d.get("actionRequired", False),
        )
    
    def to_json(self, pretty: bool = False) -> str:
        """
        Serialize to JSON string.
        
        Args:
            pretty: Whether to format with indentation
        
        Returns:
            JSON string suitable for SIEM ingestion
        """
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            ensure_ascii=False
        )
    
    def is_compliant(self) -> bool:
        """Check if event indicates compliance."""
        return self.observation.result == "compliant"
    
    def requires_action(self) -> bool:
        """Check if event requires immediate action."""
        return (
            self.action_required or 
            self.severity in ("high", "critical") or
            self.event_type in ("drift", "violation")
        )


@dataclass
class AttestationEvent(RADEEvent):
    """
    Attestation event - system is compliant with ABOM.
    
    Emitted when validation confirms system matches ABOM declaration.
    
    Example:
        >>> event = AttestationEvent(
        ...     observation=Observation(
        ...         type="system-integrity",
        ...         result="compliant",
        ...         details="All 15 components verified"
        ...     ),
        ...     abom_serial="urn:uuid:..."
        ... )
    """
    
    def __post_init__(self) -> None:
        """Set event type to attestation."""
        self.event_type = "attestation"
        super().__post_init__()


@dataclass
class DriftEvent(RADEEvent):
    """
    Drift event - deviation from ABOM detected.
    
    AI-SCS 7.2 requires detection of:
    - Model substitution or replacement
    - Dependency or library drift
    - Unauthorized tool activation
    - Undeclared or modified prompts/templates/policies
    - Provenance mismatch
    
    Example:
        >>> event = DriftEvent(
        ...     observation=Observation(
        ...         type="model-substitution",
        ...         result="non-compliant",
        ...         component_ref="model:llama@7b",
        ...         details="Model file hash does not match ABOM declaration"
        ...     ),
        ...     abom_serial="urn:uuid:...",
        ...     severity="critical"
        ... )
    """
    
    def __post_init__(self) -> None:
        """Set event type to drift."""
        self.event_type = "drift"
        super().__post_init__()
        
        # Drift events typically require action
        if self.severity in ("high", "critical"):
            self.action_required = True


@dataclass
class ViolationEvent(RADEEvent):
    """
    Policy violation event.
    
    AI-SCS 7.3 requires detection of policy violations including
    unauthorized execution of tools, agents, or services.
    
    Example:
        >>> event = ViolationEvent(
        ...     observation=Observation(
        ...         type="policy-violation",
        ...         result="non-compliant",
        ...         details="Attempted to use undeclared tool 'shell-exec'"
        ...     ),
        ...     abom_serial="urn:uuid:...",
        ...     severity="critical",
        ...     action_taken="blocked"
        ... )
    """
    
    def __post_init__(self) -> None:
        """Set event type to violation."""
        self.event_type = "violation"
        super().__post_init__()
        
        # Violations always require action
        self.action_required = True


@dataclass
class ExpirationEvent(RADEEvent):
    """
    Trust expiration event.
    
    AI-SCS 7.3 requires detection of trust expiration for
    cryptographic or attested artifacts.
    
    Example:
        >>> event = ExpirationEvent(
        ...     observation=Observation(
        ...         type="trust-expired",
        ...         result="non-compliant",
        ...         component_ref="model:llama@7b",
        ...         details="Trust assertion expired on 2024-01-01"
        ...     ),
        ...     abom_serial="urn:uuid:...",
        ...     severity="high"
        ... )
    """
    
    def __post_init__(self) -> None:
        """Set event type to expiration."""
        self.event_type = "expiration"
        super().__post_init__()


class EnforcementAction(str, Enum):
    """
    Enforcement actions per AI-SCS 7.2.1.
    
    Upon detection of validation failure, implementations MUST
    support one or more enforcement actions.
    """
    # Prevent execution
    BLOCK = "block"
    PREVENT_EXECUTION = "prevent-execution"
    
    # Disable components
    DISABLE_TOOL = "disable-tool"
    DISABLE_MCP = "disable-mcp"
    DISABLE_AGENT = "disable-agent"
    
    # Revert changes
    REVERT = "revert"
    ROLLBACK = "rollback"
    
    # Fail closed
    FAIL_CLOSED = "fail-closed"
    SHUTDOWN = "shutdown"
    
    # Alert
    ALERT = "alert"
    ESCALATE = "escalate"
    
    # Log only (not sufficient for full conformance per 7.2.1)
    LOG_ONLY = "log-only"
