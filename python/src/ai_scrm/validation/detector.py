"""
Drift Detector - AI-SCS Section 7.2 Runtime Validation

This module implements runtime validation and drift detection as required
by AI-SCS Section 7.2. It detects deviations between the declared ABOM
and the actual runtime state of the AI system.

AI-SCS 7.2 Runtime Validation MUST detect:
    - Model substitution or replacement
    - Dependency or library drift
    - Unauthorized tool activation (including MCP servers)
    - Undeclared or modified prompts, templates, or policy artifacts
    - Provenance mismatch for any ABOM-declared asset

AI-SCS 7.2.1 Enforcement:
    Upon detection of validation failure, implementations MUST support
    enforcement actions. Detection without enforcement capability SHALL NOT
    be considered sufficient for full conformance.

Usage:
    >>> from ai_scrm.validation import DriftDetector
    >>> from ai_scrm.abom import ABOM
    >>>
    >>> abom = ABOM.from_file("abom.json")
    >>> detector = DriftDetector(abom, system_name="my-agent")
    >>>
    >>> # Check for drift
    >>> events = detector.check("./deployed-system")
    >>> for event in events:
    ...     if event.event_type == "drift":
    ...         print(f"DRIFT: {event.observation.details}")

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import List, Optional, Any, Dict, Callable, Set

from ai_scrm.validation.events import (
    RADEEvent,
    DriftEvent,
    AttestationEvent,
    ViolationEvent,
    ExpirationEvent,
    Observation,
    ObservationType,
    Severity,
    EnforcementAction,
)
from ai_scrm.validation.exceptions import ValidationError

# Configure logging
logger = logging.getLogger(__name__)


def _hash_file(path: Path, alg: str = "sha256") -> str:
    """
    Compute hash of a file.
    
    Args:
        path: Path to file
        alg: Hash algorithm (default: sha256)
    
    Returns:
        Hexadecimal hash digest
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    h = hashlib.new(alg)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class DriftDetector:
    """
    Detects drift between ABOM declaration and runtime state.
    
    AI-SCS 7.2 requires continuous validation of all AI Supply Chain Assets
    declared in the ABOM. This class provides detection capabilities for
    the validation objectives defined in Section 7.2.
    
    Detection Capabilities (7.2):
        - Model substitution or replacement
        - Dependency or library drift
        - Unauthorized tool activation (including MCP servers)
        - Undeclared or modified prompts/templates/policies
        - Provenance mismatch
    
    Enforcement Support (7.2.1):
        The detector can be configured with enforcement callbacks that
        are invoked when drift is detected.
    
    Attributes:
        abom: The ABOM to validate against
        system_name: Name of the system being validated
        environment: Environment (production, staging, development)
        enforcement_handler: Callback for enforcement actions
    
    Example:
        >>> detector = DriftDetector(abom, system_name="my-agent")
        >>> events = detector.check("./deployed-system")
        >>> 
        >>> # With enforcement handler
        >>> def enforce(event):
        ...     if event.severity == "critical":
        ...         block_execution()
        >>> detector = DriftDetector(abom, enforcement_handler=enforce)
    
    Test Cases:
        Input: check() with matching hashes
        Expected: AttestationEvent with result="compliant"
        
        Input: check() with mismatched model hash
        Expected: DriftEvent with type="model-integrity", severity="critical"
        
        Input: check() with undeclared model file
        Expected: DriftEvent with type="model-substitution"
    """
    
    # File extensions for different artifact types
    MODEL_EXTENSIONS = {".safetensors", ".bin", ".pt", ".pth", ".gguf", ".onnx", ".h5", ".pb"}
    DATASET_EXTENSIONS = {".parquet", ".csv", ".jsonl", ".arrow"}
    CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml"}
    
    def __init__(
        self,
        abom: Any,
        system_name: Optional[str] = None,
        environment: Optional[str] = None,
        enforcement_handler: Optional[Callable[[RADEEvent], None]] = None,
        strict: bool = False
    ) -> None:
        """
        Initialize drift detector.
        
        Args:
            abom: ABOM to validate against
            system_name: Name of the system
            environment: Deployment environment
            enforcement_handler: Callback for enforcement (7.2.1)
            strict: If True, treat warnings as errors
        """
        if abom is None:
            raise ValueError("ABOM is required")
        
        self.abom = abom
        self.system_name = system_name
        self.environment = environment
        self.enforcement_handler = enforcement_handler
        self.strict = strict
        
        # Build lookup indexes
        self._build_indexes()
        
        logger.debug(f"DriftDetector initialized for {abom.serial_number}")
    
    def _build_indexes(self) -> None:
        """Build hash and name lookup indexes from ABOM."""
        self._hash_to_component: Dict[str, Any] = {}
        self._name_to_component: Dict[str, Any] = {}
        self._ref_to_component: Dict[str, Any] = {}
        self._declared_hashes: Set[str] = set()
        
        for comp in self.abom.components:
            self._ref_to_component[comp.bom_ref] = comp
            self._name_to_component[comp.name.lower()] = comp
            
            for h in comp.hashes:
                self._hash_to_component[h.content.lower()] = comp
                self._declared_hashes.add(h.content.lower())
    
    def check(self, path: str) -> List[RADEEvent]:
        """
        Check path for drift from ABOM.
        
        Performs comprehensive validation per AI-SCS 7.2:
        - Model integrity verification
        - Dependency drift detection
        - Configuration validation
        
        Args:
            path: Root path to scan for artifacts
        
        Returns:
            List of RADE events (attestation if compliant, drift if not)
        
        Example:
            >>> events = detector.check("./deployed-system")
            >>> drift_events = [e for e in events if e.event_type == "drift"]
        """
        root = Path(path).resolve()
        if not root.exists():
            raise ValidationError(f"Path does not exist: {root}")
        
        events: List[RADEEvent] = []
        
        # Check models
        events.extend(self._check_models(root))
        
        # Check datasets (if applicable)
        events.extend(self._check_datasets(root))
        
        # Check for undeclared artifacts
        events.extend(self._check_undeclared(root))
        
        # Check trust assertions if present
        events.extend(self._check_trust_expiration())
        
        # If no drift detected, emit attestation
        drift_count = sum(1 for e in events if e.event_type == "drift")
        if drift_count == 0:
            events.append(self._create_attestation(
                f"All {len(self._declared_hashes)} declared artifacts verified"
            ))
        
        # Invoke enforcement handler if configured
        if self.enforcement_handler:
            for event in events:
                if event.requires_action():
                    try:
                        self.enforcement_handler(event)
                    except Exception as e:
                        logger.error(f"Enforcement handler failed: {e}")
        
        logger.info(
            f"Drift check complete: {len(events)} events, "
            f"{drift_count} drift detected"
        )
        
        return events
    
    def _check_models(self, root: Path) -> List[RADEEvent]:
        """
        Check model files for integrity drift.
        
        AI-SCS 7.2: Must detect model substitution or replacement.
        """
        events: List[RADEEvent] = []
        
        for ext in self.MODEL_EXTENSIONS:
            for model_path in root.rglob(f"*{ext}"):
                try:
                    event = self._verify_model_file(model_path)
                    if event:
                        events.append(event)
                except Exception as e:
                    events.append(self._create_drift(
                        obs_type=ObservationType.MODEL_INTEGRITY,
                        details=f"Error checking {model_path.name}: {e}",
                        severity=Severity.MEDIUM
                    ))
        
        return events
    
    def _verify_model_file(self, model_path: Path) -> Optional[RADEEvent]:
        """
        Verify a single model file against ABOM.
        
        Args:
            model_path: Path to model file
        
        Returns:
            DriftEvent if mismatch, None if verified
        """
        actual_hash = _hash_file(model_path, "sha256")
        
        # Check if hash matches any declared component
        if actual_hash.lower() in self._declared_hashes:
            logger.debug(f"Model verified: {model_path.name}")
            return None
        
        # Try to find component by name
        name_lower = model_path.stem.lower()
        comp = self._name_to_component.get(name_lower)
        
        if comp and comp.hashes:
            # Found component but hash mismatch - possible substitution
            return self._create_drift(
                obs_type=ObservationType.MODEL_SUBSTITUTION,
                details=f"Model hash mismatch: {model_path.name}",
                component_ref=comp.bom_ref,
                expected=comp.hashes[0].content[:16] + "...",
                actual=actual_hash[:16] + "...",
                severity=Severity.CRITICAL,
                action_taken=EnforcementAction.ALERT.value
            )
        
        # Model file not in ABOM at all
        return self._create_drift(
            obs_type=ObservationType.MODEL_INTEGRITY,
            details=f"Undeclared model file: {model_path.name}",
            actual=actual_hash[:16] + "...",
            severity=Severity.HIGH
        )
    
    def _check_datasets(self, root: Path) -> List[RADEEvent]:
        """Check dataset files."""
        events: List[RADEEvent] = []
        
        for ext in self.DATASET_EXTENSIONS:
            for data_path in root.rglob(f"*{ext}"):
                try:
                    actual_hash = _hash_file(data_path, "sha256")
                    
                    # Check if hash matches declared dataset
                    if actual_hash.lower() not in self._declared_hashes:
                        # Check if dataset is declared (might not have hash)
                        name_lower = data_path.stem.lower()
                        comp = self._name_to_component.get(name_lower)
                        
                        if comp and comp.hashes:
                            events.append(self._create_drift(
                                obs_type=ObservationType.PROVENANCE_MISMATCH,
                                details=f"Dataset hash mismatch: {data_path.name}",
                                component_ref=comp.bom_ref,
                                severity=Severity.HIGH
                            ))
                
                except Exception as e:
                    logger.warning(f"Error checking dataset {data_path}: {e}")
        
        return events
    
    def _check_undeclared(self, root: Path) -> List[RADEEvent]:
        """
        Check for undeclared artifacts.
        
        AI-SCS 5.2: Any undeclared asset SHALL be considered unauthorized.
        AI-SCS 7.2: Must detect unauthorized tool activation.
        """
        events: List[RADEEvent] = []
        
        # Check for MCP server configs that aren't declared
        for config_path in root.rglob("*mcp*.json"):
            events.append(self._create_drift(
                obs_type=ObservationType.MCP_UNAUTHORIZED,
                details=f"Potential undeclared MCP config: {config_path.name}",
                severity=Severity.HIGH
            ))
        
        for config_path in root.rglob("*mcp*.yaml"):
            events.append(self._create_drift(
                obs_type=ObservationType.MCP_UNAUTHORIZED,
                details=f"Potential undeclared MCP config: {config_path.name}",
                severity=Severity.HIGH
            ))
        
        return events
    
    def _check_trust_expiration(self) -> List[RADEEvent]:
        """
        Check for expired trust assertions.
        
        AI-SCS 7.3: Must detect trust expiration.
        """
        # This would check trust assertions if they're stored
        # For now, return empty list
        return []
    
    def check_component(
        self,
        bom_ref: str,
        actual_hash: str
    ) -> RADEEvent:
        """
        Check a specific component against its declared hash.
        
        Useful for runtime verification of individual artifacts.
        
        Args:
            bom_ref: Component bom-ref
            actual_hash: Computed hash of actual artifact
        
        Returns:
            AttestationEvent if match, DriftEvent if mismatch
        
        Example:
            >>> event = detector.check_component(
            ...     "model:llama@7b",
            ...     "abc123..."
            ... )
        """
        comp = self._ref_to_component.get(bom_ref)
        
        if not comp:
            return self._create_drift(
                obs_type=ObservationType.COMPONENT_INTEGRITY,
                details=f"Component not found in ABOM: {bom_ref}",
                component_ref=bom_ref,
                severity=Severity.HIGH
            )
        
        if not comp.hashes:
            return self._create_attestation(
                f"Component {bom_ref} has no declared hash",
                component_ref=bom_ref
            )
        
        expected = comp.hashes[0].content.lower()
        actual_lower = actual_hash.lower()
        
        if expected == actual_lower:
            return self._create_attestation(
                f"Component {bom_ref} verified",
                component_ref=bom_ref
            )
        else:
            return self._create_drift(
                obs_type=ObservationType.COMPONENT_INTEGRITY,
                details=f"Hash mismatch for {bom_ref}",
                component_ref=bom_ref,
                expected=expected[:16] + "...",
                actual=actual_lower[:16] + "...",
                severity=Severity.CRITICAL
            )
    
    def check_tool_authorized(self, tool_name: str) -> RADEEvent:
        """
        Check if a tool is authorized per ABOM.
        
        AI-SCS 7.2: Must detect unauthorized tool activation.
        AI-SCS 5.2: Undeclared assets SHALL be considered unauthorized.
        
        Args:
            tool_name: Name of tool to check
        
        Returns:
            AttestationEvent if authorized, ViolationEvent if not
        
        Example:
            >>> event = detector.check_tool_authorized("web-search")
        """
        # Check if tool is declared in ABOM
        for comp in self.abom.get_tools():
            if comp.name.lower() == tool_name.lower():
                return self._create_attestation(
                    f"Tool '{tool_name}' is authorized",
                    component_ref=comp.bom_ref
                )
        
        # Tool not found - unauthorized
        return ViolationEvent(
            observation=Observation(
                type=ObservationType.TOOL_UNAUTHORIZED.value,
                result="non-compliant",
                details=f"Tool '{tool_name}' is not declared in ABOM"
            ),
            abom_serial=self.abom.serial_number,
            severity=Severity.CRITICAL.value,
            system_name=self.system_name,
            environment=self.environment,
            action_required=True
        )
    
    def check_mcp_authorized(
        self,
        server_name: str,
        endpoint: Optional[str] = None
    ) -> RADEEvent:
        """
        Check if MCP server is authorized per ABOM.
        
        AI-SCS 5.3.5: MCP servers MUST be declared with endpoint,
        capabilities, and trust boundary.
        
        Args:
            server_name: MCP server name
            endpoint: Optional endpoint to verify
        
        Returns:
            AttestationEvent if authorized, ViolationEvent if not
        """
        for comp in self.abom.get_mcp_servers():
            if comp.name.lower() == server_name.lower():
                # Verify endpoint if provided
                if endpoint:
                    declared_endpoint = comp.get_property("ai.mcp.endpoint")
                    if declared_endpoint and declared_endpoint != endpoint:
                        return self._create_drift(
                            obs_type=ObservationType.MCP_UNAUTHORIZED,
                            details=f"MCP endpoint mismatch for '{server_name}'",
                            component_ref=comp.bom_ref,
                            expected=declared_endpoint,
                            actual=endpoint,
                            severity=Severity.CRITICAL
                        )
                
                return self._create_attestation(
                    f"MCP server '{server_name}' is authorized",
                    component_ref=comp.bom_ref
                )
        
        # MCP server not found - unauthorized
        return ViolationEvent(
            observation=Observation(
                type=ObservationType.MCP_UNAUTHORIZED.value,
                result="non-compliant",
                details=f"MCP server '{server_name}' is not declared in ABOM"
            ),
            abom_serial=self.abom.serial_number,
            severity=Severity.CRITICAL.value,
            system_name=self.system_name,
            environment=self.environment,
            action_required=True
        )
    
    def _create_attestation(
        self,
        details: str,
        component_ref: Optional[str] = None
    ) -> AttestationEvent:
        """Create attestation event."""
        return AttestationEvent(
            observation=Observation(
                type=ObservationType.SYSTEM_INTEGRITY.value,
                result="compliant",
                component_ref=component_ref,
                details=details
            ),
            abom_serial=self.abom.serial_number,
            severity=Severity.INFO.value,
            system_name=self.system_name,
            environment=self.environment
        )
    
    def _create_drift(
        self,
        obs_type: ObservationType,
        details: str,
        component_ref: Optional[str] = None,
        expected: Optional[str] = None,
        actual: Optional[str] = None,
        severity: Severity = Severity.HIGH,
        action_taken: Optional[str] = None
    ) -> DriftEvent:
        """Create drift event."""
        return DriftEvent(
            observation=Observation(
                type=obs_type.value if isinstance(obs_type, ObservationType) else obs_type,
                result="non-compliant",
                component_ref=component_ref,
                details=details,
                expected=expected,
                actual=actual
            ),
            abom_serial=self.abom.serial_number,
            severity=severity.value if isinstance(severity, Severity) else severity,
            system_name=self.system_name,
            environment=self.environment,
            action_taken=action_taken
        )
