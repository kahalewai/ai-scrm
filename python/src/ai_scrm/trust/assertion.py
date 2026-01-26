"""
Trust Assertion Module - AI-SCS Section 6.3

This module implements Trust Assertions as defined in AI-SCS Section 6.3.
A Trust Assertion is a cryptographically verifiable statement that serves
as a trust anchor for an AI artifact's authenticity, integrity, and
authorized use within an AI system.

AI-SCS 6.3 Required Fields:
    - Artifact identifier
    - Cryptographic hash
    - Signing entity
    - Signing timestamp
    - Validity period
    - Reference to ABOM entry

Usage:
    >>> from ai_scrm.trust import TrustAssertion, TrustAssertionBuilder
    >>> from ai_scrm.abom import ABOM
    >>>
    >>> # Create assertion for a component
    >>> abom = ABOM.from_file("abom.json")
    >>> builder = TrustAssertionBuilder(
    ...     issuer_name="My Organization",
    ...     issuer_id="urn:ai-scs:issuer:my-org"
    ... )
    >>> model = abom.get_models()[0]
    >>> assertion = builder.create_for_component(model, abom)
    >>> assertion.to_file("model-assertion.json")

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
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Union, List
from pathlib import Path

from ai_scrm.trust.exceptions import TrustError

# Configure logging
logger = logging.getLogger(__name__)


def _generate_uuid() -> str:
    """Generate URN UUID for assertion ID."""
    return f"urn:uuid:{uuid.uuid4()}"


def _now_iso() -> str:
    """Generate ISO 8601 timestamp in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _future_iso(days: int) -> str:
    """Generate future ISO 8601 timestamp."""
    future = datetime.now(timezone.utc) + timedelta(days=days)
    return future.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TrustAssertion:
    """
    Artifact Trust Assertion (ATA) - AI-SCS Section 6.3.
    
    A Trust Assertion is a cryptographically verifiable statement that
    binds an artifact to its ABOM entry and certifies its authenticity.
    
    AI-SCS 6.3 Required Fields:
        - Artifact identifier (artifact_name, artifact_version)
        - Cryptographic hash (artifact_hash, artifact_hash_alg)
        - Signing entity (issuer_name, issuer_id)
        - Signing timestamp (issued_at)
        - Validity period (expires_at)
        - Reference to ABOM entry (abom_serial, bom_ref)
    
    Attributes:
        assertion_id: Unique URN UUID for this assertion
        assertion_version: Assertion format version
        artifact_type: Type of artifact (model, dataset, tool, etc.)
        artifact_name: Artifact name
        artifact_version: Artifact version
        artifact_hash: Cryptographic hash of artifact
        artifact_hash_alg: Hash algorithm used
        bom_ref: Reference to ABOM component
        abom_serial: Serial number of containing ABOM
        abom_hash: Hash of ABOM at time of assertion
        issuer_name: Name of signing entity
        issuer_id: URN identifier of signing entity
        issued_at: ISO timestamp of assertion creation
        expires_at: ISO timestamp of assertion expiration
        signature_alg: Algorithm used for assertion signature
        signature_value: Base64-encoded signature
    
    Example:
        >>> assertion = TrustAssertion(
        ...     artifact_type="model",
        ...     artifact_name="llama-7b",
        ...     artifact_version="1.0.0",
        ...     artifact_hash="abc123...",
        ...     artifact_hash_alg="SHA-256",
        ...     abom_serial="urn:uuid:...",
        ...     abom_hash="xyz789...",
        ...     issuer_name="My Org",
        ...     issuer_id="urn:ai-scs:issuer:my-org"
        ... )
        >>> assertion.to_file("assertion.json")
    
    Test Cases:
        Input: TrustAssertion with all required fields
        Expected: Valid assertion with auto-generated ID and timestamps
        
        Input: assertion.is_expired() when expires_at is in past
        Expected: True
    """
    # Artifact information
    artifact_type: str
    artifact_name: str
    artifact_version: str
    artifact_hash: str
    artifact_hash_alg: str
    
    # ABOM binding
    abom_serial: str
    abom_hash: str
    
    # Issuer information
    issuer_name: str
    issuer_id: str
    
    # Assertion metadata
    assertion_id: str = field(default_factory=_generate_uuid)
    assertion_version: str = "1.0"
    bom_ref: Optional[str] = None
    issued_at: str = field(default_factory=_now_iso)
    expires_at: Optional[str] = None
    
    # Signature (optional - can be added after creation)
    signature_alg: Optional[str] = None
    signature_value: Optional[str] = None
    
    # Additional metadata
    scope: Optional[str] = None  # "production", "development", "testing"
    conditions: Optional[List[str]] = None  # Usage conditions
    
    def __post_init__(self) -> None:
        """Validate required fields."""
        required = [
            ("artifact_type", self.artifact_type),
            ("artifact_name", self.artifact_name),
            ("artifact_version", self.artifact_version),
            ("artifact_hash", self.artifact_hash),
            ("artifact_hash_alg", self.artifact_hash_alg),
            ("abom_serial", self.abom_serial),
            ("abom_hash", self.abom_hash),
            ("issuer_name", self.issuer_name),
            ("issuer_id", self.issuer_id),
        ]
        
        missing = [name for name, value in required if not value]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format.
        
        Returns:
            dict: Trust assertion in standard format
        """
        result: Dict[str, Any] = {
            "assertionVersion": self.assertion_version,
            "assertionId": self.assertion_id,
            "artifact": {
                "type": self.artifact_type,
                "name": self.artifact_name,
                "version": self.artifact_version,
                "hash": {
                    "alg": self.artifact_hash_alg,
                    "content": self.artifact_hash,
                },
            },
            "abomBinding": {
                "serialNumber": self.abom_serial,
                "hash": self.abom_hash,
            },
            "issuer": {
                "name": self.issuer_name,
                "identity": self.issuer_id,
            },
            "issuedAt": self.issued_at,
        }
        
        if self.bom_ref:
            result["artifact"]["bomRef"] = self.bom_ref
        
        if self.expires_at:
            result["expiresAt"] = self.expires_at
        
        if self.signature_alg and self.signature_value:
            result["signature"] = {
                "algorithm": self.signature_alg,
                "value": self.signature_value,
            }
        
        if self.scope:
            result["scope"] = self.scope
        
        if self.conditions:
            result["conditions"] = self.conditions
        
        return result
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TrustAssertion":
        """
        Create TrustAssertion from dictionary.
        
        Args:
            d: Dictionary with assertion data
        
        Returns:
            TrustAssertion instance
        
        Raises:
            KeyError: If required fields missing
        """
        artifact = d["artifact"]
        abom_binding = d["abomBinding"]
        issuer = d["issuer"]
        signature = d.get("signature", {})
        
        return cls(
            assertion_id=d.get("assertionId", _generate_uuid()),
            assertion_version=d.get("assertionVersion", "1.0"),
            artifact_type=artifact["type"],
            artifact_name=artifact["name"],
            artifact_version=artifact["version"],
            artifact_hash=artifact["hash"]["content"],
            artifact_hash_alg=artifact["hash"]["alg"],
            bom_ref=artifact.get("bomRef"),
            abom_serial=abom_binding["serialNumber"],
            abom_hash=abom_binding["hash"],
            issuer_name=issuer["name"],
            issuer_id=issuer["identity"],
            issued_at=d.get("issuedAt", _now_iso()),
            expires_at=d.get("expiresAt"),
            signature_alg=signature.get("algorithm"),
            signature_value=signature.get("value"),
            scope=d.get("scope"),
            conditions=d.get("conditions"),
        )
    
    def to_json(self, pretty: bool = True) -> str:
        """Serialize to JSON string."""
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            ensure_ascii=False
        )
    
    def to_file(self, path: Union[str, Path]) -> None:
        """
        Save assertion to JSON file.
        
        Args:
            path: Output file path
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"Trust assertion saved: {path}")
    
    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "TrustAssertion":
        """
        Load assertion from JSON file.
        
        Args:
            path: Path to assertion file
        
        Returns:
            TrustAssertion instance
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Assertion file not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))
    
    def is_expired(self) -> bool:
        """
        Check if assertion has expired.
        
        AI-SCS 7.3 requires detection of trust expiration.
        
        Returns:
            bool: True if expired, False if still valid or no expiration set
        """
        if not self.expires_at:
            return False
        
        try:
            # Parse ISO timestamp
            expires = datetime.fromisoformat(
                self.expires_at.replace("Z", "+00:00")
            )
            return datetime.now(timezone.utc) > expires
        except Exception:
            logger.warning(f"Could not parse expiration date: {self.expires_at}")
            return False
    
    def is_valid_for_abom(self, abom: Any) -> bool:
        """
        Check if assertion is valid for given ABOM.
        
        Verifies:
        - ABOM serial number matches
        - ABOM hash matches (if ABOM hasn't changed)
        - Assertion not expired
        
        Args:
            abom: ABOM to validate against
        
        Returns:
            bool: True if assertion is valid for ABOM
        """
        if self.is_expired():
            return False
        
        if abom.serial_number != self.abom_serial:
            return False
        
        # Check hash if we can compute it
        try:
            current_hash = abom.compute_hash()
            if current_hash != self.abom_hash:
                logger.warning("ABOM hash mismatch - ABOM may have been modified")
                return False
        except Exception:
            pass  # Can't verify hash, continue
        
        return True


class TrustAssertionBuilder:
    """
    Builder for creating Trust Assertions.
    
    Simplifies creation of Trust Assertions for ABOM components
    with consistent issuer information and validity periods.
    
    Attributes:
        issuer_name: Name of the issuing organization
        issuer_id: URN identifier for the issuer
        validity_days: Default validity period in days
        scope: Default scope for assertions
    
    Example:
        >>> builder = TrustAssertionBuilder(
        ...     issuer_name="My Organization",
        ...     issuer_id="urn:ai-scs:issuer:my-org",
        ...     validity_days=365
        ... )
        >>> assertion = builder.create_for_component(model_component, abom)
    """
    
    def __init__(
        self,
        issuer_name: str,
        issuer_id: str,
        validity_days: int = 365,
        scope: Optional[str] = None
    ) -> None:
        """
        Initialize builder.
        
        Args:
            issuer_name: Organization name
            issuer_id: Issuer URN (e.g., "urn:ai-scs:issuer:my-org")
            validity_days: Days until assertion expires
            scope: Default scope (production, development, testing)
        """
        if not issuer_name:
            raise ValueError("issuer_name is required")
        if not issuer_id:
            raise ValueError("issuer_id is required")
        
        self.issuer_name = issuer_name
        self.issuer_id = issuer_id
        self.validity_days = validity_days
        self.scope = scope
    
    def create_for_component(
        self,
        component: Any,
        abom: Any,
        conditions: Optional[List[str]] = None
    ) -> TrustAssertion:
        """
        Create Trust Assertion for an ABOM component.
        
        AI-SCS 6.3: Each covered artifact MUST support a Trust Assertion.
        
        Args:
            component: ABOMComponent to create assertion for
            abom: ABOM containing the component
            conditions: Optional usage conditions
        
        Returns:
            TrustAssertion for the component
        
        Raises:
            ValueError: If component has no hash (required for models)
        
        Example:
            >>> model = abom.get_models()[0]
            >>> assertion = builder.create_for_component(model, abom)
        """
        # Verify component has hash
        if not component.hashes:
            raise ValueError(
                f"Component '{component.bom_ref}' has no hash. "
                f"AI-SCS 6.3 requires cryptographic hash for Trust Assertions."
            )
        
        # Map component type to artifact type
        type_map = {
            "machine-learning-model": "model",
            "data": "dataset",
            "service": "tool",
            "application": "agent",
            "library": "library",
            "platform": "infrastructure",
            "device": "infrastructure",
        }
        artifact_type = type_map.get(component.type, component.type)
        
        # Calculate expiration
        expires_at = _future_iso(self.validity_days)
        
        return TrustAssertion(
            artifact_type=artifact_type,
            artifact_name=component.name,
            artifact_version=component.version,
            artifact_hash=component.hashes[0].content,
            artifact_hash_alg=component.hashes[0].alg,
            bom_ref=component.bom_ref,
            abom_serial=abom.serial_number,
            abom_hash=abom.compute_hash(),
            issuer_name=self.issuer_name,
            issuer_id=self.issuer_id,
            expires_at=expires_at,
            scope=self.scope,
            conditions=conditions,
        )
    
    def create_for_all_components(
        self,
        abom: Any,
        include_without_hash: bool = False
    ) -> List[TrustAssertion]:
        """
        Create Trust Assertions for all components in ABOM.
        
        Args:
            abom: ABOM to process
            include_without_hash: Whether to skip components without hashes
        
        Returns:
            List of TrustAssertion instances
        """
        assertions = []
        
        for component in abom.components:
            if not component.hashes:
                if include_without_hash:
                    logger.warning(
                        f"Skipping {component.bom_ref}: no hash available"
                    )
                continue
            
            try:
                assertion = self.create_for_component(component, abom)
                assertions.append(assertion)
            except Exception as e:
                logger.error(f"Failed to create assertion for {component.bom_ref}: {e}")
        
        logger.info(f"Created {len(assertions)} trust assertions")
        return assertions
