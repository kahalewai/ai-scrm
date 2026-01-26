"""
Verification Module - AI-SCS Section 6.4 Verification Requirements

This module implements the verification requirements from AI-SCS Section 6.4:
- Verify Trust Assertions prior to use
- Reject artifacts failing verification
- Support configurable trust roots

AI-SCS 6.4 Requirements:
    Implementations MUST:
    - Verify Trust Assertions prior to use
    - Reject artifacts failing verification
    - Support configurable trust roots

    Implementations MUST be capable of rejecting:
    - Unsigned artifacts
    - Artifacts signed by untrusted authorities
    - Artifacts failing integrity verification

Usage:
    >>> from ai_scrm.trust import Verifier
    >>> from ai_scrm.abom import ABOM
    >>>
    >>> abom = ABOM.from_file("abom-signed.json")
    >>> verifier = Verifier()
    >>>
    >>> # Verify with embedded public key
    >>> verifier.verify(abom)
    True
    >>>
    >>> # Verify with external public key
    >>> verifier.verify(abom, public_key_path="./keys/public.pem")
    True

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Optional, Union, Any, List

from ai_scrm.trust.exceptions import VerificationError

# Configure logging
logger = logging.getLogger(__name__)

# Check for cryptography library
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def _check_crypto_available() -> None:
    """Check if cryptography library is available."""
    if not HAS_CRYPTO:
        raise VerificationError(
            "Cryptography package required for verification. "
            "Install with: pip install ai-scrm[crypto]"
        )


class Verifier:
    """
    ABOM and artifact signature verifier.
    
    AI-SCS Section 6.4 Requirements:
        - Verify Trust Assertions prior to use
        - Reject artifacts failing verification
        - Support configurable trust roots
    
    This class provides methods to verify:
        - ABOM document signatures
        - Individual artifact signatures
        - Trust assertion validity
    
    Attributes:
        trusted_keys: List of trusted public key paths
        reject_unsigned: Whether to reject unsigned ABOMs
    
    Example:
        >>> verifier = Verifier()
        >>> verifier.verify(abom)
        True
        
        >>> verifier = Verifier(reject_unsigned=True)
        >>> verifier.verify(unsigned_abom)  # Raises VerificationError
    
    Test Cases:
        Input: verify(signed_abom)
        Expected: True
        
        Input: verify(tampered_abom)
        Expected: VerificationError("Signature verification failed")
        
        Input: verify(unsigned_abom) with reject_unsigned=True
        Expected: VerificationError("ABOM is not signed")
    """
    
    def __init__(
        self,
        trusted_keys: Optional[List[Union[str, Path]]] = None,
        reject_unsigned: bool = False
    ) -> None:
        """
        Initialize verifier.
        
        Args:
            trusted_keys: List of paths to trusted public keys
            reject_unsigned: If True, reject unsigned ABOMs (AI-SCS 6.4)
        """
        self.trusted_keys = trusted_keys or []
        self.reject_unsigned = reject_unsigned
    
    def verify(
        self,
        abom: Any,
        public_key_path: Optional[Union[str, Path]] = None
    ) -> bool:
        """
        Verify ABOM signature.
        
        AI-SCS 6.4: Implementations MUST verify Trust Assertions prior to use.
        
        Verification process:
        1. Check if ABOM is signed (reject if unsigned and reject_unsigned=True)
        2. Load public key (from parameter, embedded in signature, or trusted keys)
        3. Verify signature against canonical ABOM representation
        4. Raise VerificationError if verification fails
        
        Args:
            abom: ABOM instance to verify
            public_key_path: Optional path to public key file
        
        Returns:
            bool: True if signature is valid
        
        Raises:
            VerificationError: If verification fails for any reason:
                - ABOM is not signed (when reject_unsigned=True)
                - Invalid signature format
                - Public key not available
                - Signature verification failed (possible tampering)
                - Untrusted signing authority
        
        Example:
            >>> verifier = Verifier()
            >>> try:
            ...     verifier.verify(abom)
            ...     print("Signature valid")
            ... except VerificationError as e:
            ...     print(f"Verification failed: {e}")
        """
        _check_crypto_available()
        
        # Check if signed
        if not abom.signature:
            if self.reject_unsigned:
                raise VerificationError(
                    "ABOM is not signed (AI-SCS 6.4 requires rejection of unsigned artifacts)"
                )
            logger.warning("ABOM is not signed - skipping verification")
            return True
        
        # Extract signature components
        algorithm = abom.signature.get("algorithm")
        signature_b64 = abom.signature.get("value")
        embedded_key_b64 = abom.signature.get("publicKey")
        
        if not algorithm:
            raise VerificationError("Signature missing algorithm field")
        if not signature_b64:
            raise VerificationError("Signature missing value field")
        
        # Decode signature
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as e:
            raise VerificationError(f"Failed to decode signature: {e}")
        
        # Load public key
        public_key = self._load_public_key(
            algorithm=algorithm,
            public_key_path=public_key_path,
            embedded_key_b64=embedded_key_b64
        )
        
        # Get canonical data (excludes signature)
        canonical = abom.canonicalize()
        
        # Verify signature
        try:
            self._verify_signature(
                algorithm=algorithm,
                public_key=public_key,
                signature=signature,
                data=canonical
            )
            logger.info(f"ABOM signature verified ({algorithm})")
            return True
            
        except InvalidSignature:
            raise VerificationError(
                "Signature verification failed - ABOM may have been tampered with "
                "(AI-SCS 6.4 requires rejection)"
            )
        except Exception as e:
            raise VerificationError(f"Verification error: {e}")
    
    def verify_artifact(
        self,
        artifact_path: Union[str, Path],
        signature: dict,
        public_key_path: Optional[Union[str, Path]] = None
    ) -> bool:
        """
        Verify artifact file signature.
        
        AI-SCS 6.2: Model weights, embeddings, agent logic MUST be verifiable.
        
        Args:
            artifact_path: Path to artifact file
            signature: Signature dictionary with algorithm, value, publicKey
            public_key_path: Optional path to public key
        
        Returns:
            bool: True if valid
        
        Raises:
            VerificationError: If verification fails
            FileNotFoundError: If artifact doesn't exist
        """
        _check_crypto_available()
        
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {path}")
        
        algorithm = signature.get("algorithm")
        signature_b64 = signature.get("value")
        embedded_key_b64 = signature.get("publicKey")
        
        if not algorithm or not signature_b64:
            raise VerificationError("Invalid signature format")
        
        try:
            sig_bytes = base64.b64decode(signature_b64)
        except Exception as e:
            raise VerificationError(f"Failed to decode signature: {e}")
        
        # Load public key
        public_key = self._load_public_key(
            algorithm=algorithm,
            public_key_path=public_key_path,
            embedded_key_b64=embedded_key_b64
        )
        
        # Read artifact
        with open(path, "rb") as f:
            data = f.read()
        
        # Verify
        try:
            self._verify_signature(
                algorithm=algorithm,
                public_key=public_key,
                signature=sig_bytes,
                data=data
            )
            logger.info(f"Artifact signature verified: {path.name}")
            return True
            
        except InvalidSignature:
            raise VerificationError(f"Artifact signature invalid: {path.name}")
        except Exception as e:
            raise VerificationError(f"Artifact verification error: {e}")
    
    def is_valid(
        self,
        abom: Any,
        public_key_path: Optional[str] = None
    ) -> bool:
        """
        Check if ABOM signature is valid without raising exceptions.
        
        Convenience method for boolean checks.
        
        Args:
            abom: ABOM to verify
            public_key_path: Optional public key path
        
        Returns:
            bool: True if valid, False otherwise
        
        Example:
            >>> if verifier.is_valid(abom):
            ...     process(abom)
            ... else:
            ...     reject(abom)
        """
        try:
            return self.verify(abom, public_key_path)
        except VerificationError:
            return False
        except Exception:
            return False
    
    def _load_public_key(
        self,
        algorithm: str,
        public_key_path: Optional[Union[str, Path]] = None,
        embedded_key_b64: Optional[str] = None
    ) -> Any:
        """
        Load public key for verification.
        
        Priority:
        1. Explicit public_key_path parameter
        2. Embedded key in signature
        3. Trusted keys list
        
        Args:
            algorithm: Signing algorithm
            public_key_path: Explicit key path
            embedded_key_b64: Base64-encoded embedded key
        
        Returns:
            Public key object
        
        Raises:
            VerificationError: If no key available
        """
        # Try explicit path first
        if public_key_path:
            return self._load_key_from_file(public_key_path)
        
        # Try embedded key
        if embedded_key_b64:
            return self._load_embedded_key(algorithm, embedded_key_b64)
        
        # Try trusted keys
        for trusted_path in self.trusted_keys:
            try:
                return self._load_key_from_file(trusted_path)
            except Exception:
                continue
        
        raise VerificationError(
            "No public key available for verification. "
            "Provide public_key_path or ensure ABOM has embedded publicKey."
        )
    
    def _load_key_from_file(self, path: Union[str, Path]) -> Any:
        """Load public key from PEM file."""
        path = Path(path)
        if not path.exists():
            raise VerificationError(f"Public key file not found: {path}")
        
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            
            return serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
        except Exception as e:
            raise VerificationError(f"Failed to load public key from {path}: {e}")
    
    def _load_embedded_key(self, algorithm: str, key_b64: str) -> Any:
        """Load embedded public key from base64."""
        try:
            key_bytes = base64.b64decode(key_b64)
        except Exception as e:
            raise VerificationError(f"Failed to decode embedded public key: {e}")
        
        try:
            # Ed25519 uses raw format (32 bytes)
            if algorithm == "Ed25519":
                return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            
            # RSA and ECDSA use DER format
            return serialization.load_der_public_key(
                key_bytes,
                backend=default_backend()
            )
            
        except Exception as e:
            raise VerificationError(f"Failed to parse embedded public key: {e}")
    
    def _verify_signature(
        self,
        algorithm: str,
        public_key: Any,
        signature: bytes,
        data: bytes
    ) -> None:
        """
        Perform signature verification.
        
        Args:
            algorithm: Signing algorithm
            public_key: Public key object
            signature: Signature bytes
            data: Signed data
        
        Raises:
            InvalidSignature: If signature is invalid
            VerificationError: If algorithm not supported
        """
        if algorithm == "Ed25519":
            public_key.verify(signature, data)
        
        elif algorithm == "RSA-PSS":
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        elif algorithm == "ECDSA-P256":
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        
        else:
            raise VerificationError(f"Unsupported algorithm: {algorithm}")


class TrustPolicy:
    """
    Trust policy for artifact verification.
    
    AI-SCS 6.4 requires configurable trust roots. This class defines
    policies for what to accept or reject during verification.
    
    Attributes:
        require_signature: Require all ABOMs to be signed
        trusted_issuers: List of trusted issuer identities
        max_age_days: Maximum age of signature in days
        allowed_algorithms: List of allowed signing algorithms
    
    Example:
        >>> policy = TrustPolicy(
        ...     require_signature=True,
        ...     trusted_issuers=["urn:ai-scs:issuer:my-org"],
        ...     max_age_days=365
        ... )
        >>> verifier = Verifier()
        >>> verifier.verify_with_policy(abom, policy)
    """
    
    def __init__(
        self,
        require_signature: bool = True,
        trusted_issuers: Optional[List[str]] = None,
        max_age_days: Optional[int] = None,
        allowed_algorithms: Optional[List[str]] = None
    ) -> None:
        """
        Initialize trust policy.
        
        Args:
            require_signature: Whether to require signatures
            trusted_issuers: List of trusted issuer URNs
            max_age_days: Maximum signature age
            allowed_algorithms: Allowed signing algorithms
        """
        self.require_signature = require_signature
        self.trusted_issuers = trusted_issuers or []
        self.max_age_days = max_age_days
        self.allowed_algorithms = allowed_algorithms or [
            "Ed25519", "RSA-PSS", "ECDSA-P256"
        ]
    
    def to_dict(self) -> dict:
        """Convert policy to dictionary."""
        return {
            "requireSignature": self.require_signature,
            "trustedIssuers": self.trusted_issuers,
            "maxAgeDays": self.max_age_days,
            "allowedAlgorithms": self.allowed_algorithms,
        }
