"""
AI-SCRM Control Domain 3: Validation - Continuous AI Supply Chain Validation

AI-SCS Section 7 Implementation.

AI systems MUST support continuous validation and enforcement of all
AI Supply Chain Assets declared in the ABOM during execution and runtime.

Classes:
    DriftDetector - Detect drift from declared ABOM (7.2)
    RADEEmitter - Emit structured events (7.3, 7.4)
    PolicyEngine - Automated policy response (7.2.1)
    
Event Classes:
    RADEEvent - Base event class
    AttestationEvent - System compliant
    DriftEvent - Deviation detected
    ViolationEvent - Policy violation
    ExpirationEvent - Trust expired
    Observation - Event observation details

Enums:
    EventType - Event type classification
    Severity - Event severity levels
    ObservationType - Types of observations
    EnforcementAction - Available enforcement actions (7.2.1)

AI-SCS 7.2 Detection Requirements:
    - Model substitution or replacement
    - Dependency or library drift
    - Unauthorized tool activation (including MCP servers)
    - Undeclared or modified prompts/templates/policies
    - Provenance mismatch

AI-SCS 7.2.1 Enforcement Requirements:
    - Prevent execution of affected components
    - Disable compromised tools/MCP servers
    - Block or revert modified artifacts
    - Fail closed on trust violations
    - Trigger automated containment/rollback/alerting

Usage:
    >>> from ai_scrm.validation import DriftDetector, RADEEmitter
    >>> from ai_scrm.abom import ABOM
    >>>
    >>> abom = ABOM.from_file("abom.json")
    >>> detector = DriftDetector(abom, system_name="my-agent")
    >>> events = detector.check("./deployed-system")
    >>>
    >>> emitter = RADEEmitter()
    >>> emitter.add_file_handler("events.jsonl")
    >>> emitter.emit_all(events)

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from ai_scrm.validation.detector import DriftDetector
from ai_scrm.validation.emitter import RADEEmitter, PolicyEngine
from ai_scrm.validation.events import (
    RADEEvent,
    AttestationEvent,
    DriftEvent,
    ViolationEvent,
    ExpirationEvent,
    Observation,
    EventType,
    Severity,
    ObservationType,
    EnforcementAction,
)
from ai_scrm.validation.exceptions import ValidationError

__all__ = [
    # Detector
    "DriftDetector",
    # Emitter
    "RADEEmitter",
    "PolicyEngine",
    # Events
    "RADEEvent",
    "AttestationEvent",
    "DriftEvent",
    "ViolationEvent",
    "ExpirationEvent",
    "Observation",
    # Enums
    "EventType",
    "Severity",
    "ObservationType",
    "EnforcementAction",
    # Exceptions
    "ValidationError",
]
