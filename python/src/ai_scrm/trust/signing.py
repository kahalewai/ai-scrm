"""
Signing Module - AI-SCS Section 6 Cryptographic Trust

This module implements Control Domain 2 (Section 6) of the AI Supply Chain Standard.
It provides cryptographic signing capabilities for ABOM documents and artifacts.

AI-SCS Compliance:
    - Section 6.1: Critical AI artifacts MUST support integrity verification
    - Section 6.2: Covered artifacts (models, embeddings, agent logic, etc.) MUST be verifiable
    - Section 6.3: Trust Assertions with all required fields
    - Section 6.4: Verification prior to use, rejection of invalid artifacts

Supported Algorithms:
    - Ed25519 (recommended for performance)
    - RSA-PSS (RSA with Probabilistic Signature Scheme)
    - ECDSA-P256 (Elliptic Curve)

Usage:
    >>> from ai_scrm.trust import Signer
    >>> from ai_scrm.abom import ABOM
    >>> 
    >>> # Generate new signing keys
    >>> signer = Signer.generate("ed25519")
    >>> signer.save_keys("./keys")
    >>> 
    >>> # Sign an ABOM
    >>> abom = ABOM.from_file("abom.json")
    >>> signer.sign(abom)
    >>> abom.to_file("abom-signed.json")
    >>> 
    >>> # Load existing keys
    >>> signer = Signer.from_file("./keys/private.pem", algorithm="ed25519")

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import base64
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union, Any, Dict

from ai_scrm.trust.exceptions import SigningError

# Configure logging
logger = logging.getLogger(__name__)

# Check for cryptography library
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def _check_crypto_available() -> None:
    """
    Check if cryptography library is available.
    
    Raises:
        SigningError: If cryptography is not installed
    """
    if not HAS_CRYPTO:
        raise SigningError(
            "Cryptography package required for signing. "
            "Install with: pip install ai-scrm[crypto]"
        )


class Signer(ABC):
    """
    Abstract base class for ABOM signers.
    
    AI-SCS Section 6.1 requires critical AI artifacts to support integrity
    and authenticity verification. This class defines the interface for
    signing implementations.
    
    Subclasses:
        Ed25519Signer: Ed25519 signature scheme (fast, secure)
        RSASigner: RSA-PSS signature scheme (widely compatible)
        ECDSASigner: ECDSA with P-256 curve
    
    Example:
        >>> signer = Signer.generate("ed25519")
        >>> signer.sign(abom)
        >>> signer.save_keys("./keys")
    """
    
    @abstractmethod
    def algorithm(self) -> str:
        """
        Get the signing algorithm name.
        
        Returns:
            str: Algorithm name (Ed25519, RSA-PSS, ECDSA-P256)
        """
        pass
    
    @abstractmethod
    def sign_bytes(self, data: bytes) -> bytes:
        """
        Sign raw bytes.
        
        Args:
            data: Bytes to sign
        
        Returns:
            bytes: Signature
        
        Raises:
            SigningError: If signing fails
        """
        pass
    
    @abstractmethod
    def get_public_key_bytes(self) -> bytes:
        """
        Get public key as bytes.
        
        Returns:
            bytes: Public key in appropriate format
        """
        pass
    
    @abstractmethod
    def get_public_key_pem(self) -> bytes:
        """
        Get public key in PEM format.
        
        Returns:
            bytes: PEM-encoded public key
        """
        pass
    
    @abstractmethod
    def save_keys(self, directory: Union[str, Path]) -> None:
        """
        Save key pair to directory.
        
        Args:
            directory: Output directory path
        """
        pass
    
    def sign(self, abom: Any) -> Dict[str, Any]:
        """
        Sign an ABOM document in place.
        
        AI-SCS 5.4 requires ABOM to be cryptographically verifiable.
        This method computes a signature over the canonical ABOM
        representation and embeds it in the document.
        
        Args:
            abom: ABOM instance to sign
        
        Returns:
            dict: Signature dictionary that was added to ABOM
        
        Raises:
            SigningError: If signing fails
        
        Example:
            >>> signer = Signer.generate("ed25519")
            >>> sig = signer.sign(abom)
            >>> print(sig["algorithm"])
            Ed25519
        """
        try:
            # Get canonical representation (excludes existing signature)
            canonical = abom.canonicalize()
            
            # Sign the canonical data
            signature = self.sign_bytes(canonical)
            
            # Create signature object
            sig_dict: Dict[str, Any] = {
                "algorithm": self.algorithm(),
                "value": base64.b64encode(signature).decode("ascii"),
                "publicKey": base64.b64encode(self.get_public_key_bytes()).decode("ascii"),
            }
            
            # Embed signature in ABOM
            abom.signature = sig_dict
            
            logger.info(f"ABOM signed with {self.algorithm()}")
            return sig_dict
            
        except Exception as e:
            raise SigningError(f"Failed to sign ABOM: {e}")
    
    def sign_artifact(self, artifact_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Sign an artifact file.
        
        AI-SCS 6.2 requires model weights, embeddings, and agent logic
        to be verifiable.
        
        Args:
            artifact_path: Path to artifact file
        
        Returns:
            dict: Signature information
        
        Raises:
            SigningError: If signing fails
            FileNotFoundError: If artifact doesn't exist
        """
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {path}")
        
        try:
            # Read and sign file contents
            with open(path, "rb") as f:
                data = f.read()
            
            signature = self.sign_bytes(data)
            
            return {
                "algorithm": self.algorithm(),
                "value": base64.b64encode(signature).decode("ascii"),
                "publicKey": base64.b64encode(self.get_public_key_bytes()).decode("ascii"),
                "artifact": str(path.name),
            }
            
        except Exception as e:
            raise SigningError(f"Failed to sign artifact {path}: {e}")
    
    @classmethod
    def generate(cls, algorithm: str = "ed25519") -> "Signer":
        """
        Generate a new signer with fresh key pair.
        
        Args:
            algorithm: One of "ed25519", "rsa", "ecdsa"
        
        Returns:
            Signer: New signer instance with generated keys
        
        Raises:
            SigningError: If algorithm not supported or crypto unavailable
        
        Example:
            >>> signer = Signer.generate("ed25519")
            >>> print(signer.algorithm())
            Ed25519
        """
        _check_crypto_available()
        
        algorithm = algorithm.lower().replace("-", "").replace("_", "")
        
        if algorithm == "ed25519":
            return Ed25519Signer.generate()
        elif algorithm in ("rsa", "rsapss"):
            return RSASigner.generate()
        elif algorithm in ("ecdsa", "ecdsap256", "ec"):
            return ECDSASigner.generate()
        else:
            raise SigningError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported: ed25519, rsa, ecdsa"
            )
    
    @classmethod
    def from_file(
        cls,
        private_key_path: Union[str, Path],
        algorithm: str = "ed25519",
        password: Optional[bytes] = None
    ) -> "Signer":
        """
        Load signer from private key file.
        
        Args:
            private_key_path: Path to PEM-encoded private key
            algorithm: Algorithm type
            password: Optional key password
        
        Returns:
            Signer: Signer instance with loaded key
        
        Raises:
            SigningError: If loading fails
            FileNotFoundError: If key file doesn't exist
        """
        _check_crypto_available()
        
        path = Path(private_key_path)
        if not path.exists():
            raise FileNotFoundError(f"Private key not found: {path}")
        
        algorithm = algorithm.lower().replace("-", "").replace("_", "")
        
        if algorithm == "ed25519":
            return Ed25519Signer.from_file(path, password)
        elif algorithm in ("rsa", "rsapss"):
            return RSASigner.from_file(path, password)
        elif algorithm in ("ecdsa", "ecdsap256", "ec"):
            return ECDSASigner.from_file(path, password)
        else:
            raise SigningError(f"Unsupported algorithm: {algorithm}")


class Ed25519Signer(Signer):
    """
    Ed25519 signature scheme implementation.
    
    Ed25519 is recommended for AI-SCS implementations due to:
    - Fast signing and verification
    - Small key and signature sizes
    - Strong security guarantees
    - Resistance to timing attacks
    
    Attributes:
        _private_key: Ed25519 private key
        _public_key: Ed25519 public key
    
    Example:
        >>> signer = Ed25519Signer.generate()
        >>> signer.sign(abom)
        >>> signer.save_keys("./keys")
    
    Test Cases:
        Input: Ed25519Signer.generate()
        Expected: Valid signer with 32-byte public key
        
        Input: signer.sign_bytes(b"test data")
        Expected: 64-byte signature
    """
    
    def __init__(self, private_key: Any) -> None:
        """
        Initialize with Ed25519 private key.
        
        Args:
            private_key: Ed25519PrivateKey instance
        
        Raises:
            SigningError: If key is invalid
        """
        _check_crypto_available()
        
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise SigningError("Invalid Ed25519 private key")
        
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls) -> "Ed25519Signer":
        """
        Generate new Ed25519 key pair.
        
        Returns:
            Ed25519Signer: New signer with fresh keys
        """
        _check_crypto_available()
        private_key = ed25519.Ed25519PrivateKey.generate()
        logger.debug("Generated new Ed25519 key pair")
        return cls(private_key)
    
    @classmethod
    def from_file(
        cls,
        path: Union[str, Path],
        password: Optional[bytes] = None
    ) -> "Ed25519Signer":
        """
        Load Ed25519 signer from PEM file.
        
        Args:
            path: Path to private key PEM file
            password: Optional password for encrypted key
        
        Returns:
            Ed25519Signer: Signer with loaded key
        
        Raises:
            SigningError: If loading fails
        """
        _check_crypto_available()
        
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
            
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise SigningError("Key file does not contain Ed25519 key")
            
            logger.debug(f"Loaded Ed25519 key from {path}")
            return cls(private_key)
            
        except Exception as e:
            raise SigningError(f"Failed to load Ed25519 key from {path}: {e}")
    
    def algorithm(self) -> str:
        """Get algorithm name."""
        return "Ed25519"
    
    def sign_bytes(self, data: bytes) -> bytes:
        """
        Sign bytes with Ed25519.
        
        Args:
            data: Data to sign
        
        Returns:
            bytes: 64-byte signature
        """
        try:
            return self._private_key.sign(data)
        except Exception as e:
            raise SigningError(f"Ed25519 signing failed: {e}")
    
    def get_public_key_bytes(self) -> bytes:
        """Get raw 32-byte public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
    
    def get_public_key_pem(self) -> bytes:
        """Get PEM-encoded public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def save_keys(self, directory: Union[str, Path]) -> None:
        """
        Save key pair to directory.
        
        Creates:
            - private.pem: PKCS8 private key
            - public.pem: SubjectPublicKeyInfo public key
        
        Args:
            directory: Output directory
        """
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        
        # Save private key
        private_pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        (d / "private.pem").write_bytes(private_pem)
        
        # Save public key
        public_pem = self.get_public_key_pem()
        (d / "public.pem").write_bytes(public_pem)
        
        logger.info(f"Ed25519 keys saved to {d}")


class RSASigner(Signer):
    """
    RSA-PSS signature scheme implementation.
    
    RSA-PSS (Probabilistic Signature Scheme) provides:
    - Wide compatibility with existing infrastructure
    - Provable security reduction
    - Configurable salt length
    
    Default key size is 4096 bits for long-term security.
    
    Example:
        >>> signer = RSASigner.generate(key_size=4096)
        >>> signer.sign(abom)
    """
    
    def __init__(self, private_key: Any) -> None:
        """
        Initialize with RSA private key.
        
        Args:
            private_key: RSAPrivateKey instance
        """
        _check_crypto_available()
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls, key_size: int = 4096) -> "RSASigner":
        """
        Generate new RSA key pair.
        
        Args:
            key_size: Key size in bits (default: 4096)
        
        Returns:
            RSASigner: New signer with fresh keys
        """
        _check_crypto_available()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        logger.debug(f"Generated new RSA-{key_size} key pair")
        return cls(private_key)
    
    @classmethod
    def from_file(
        cls,
        path: Union[str, Path],
        password: Optional[bytes] = None
    ) -> "RSASigner":
        """Load RSA signer from PEM file."""
        _check_crypto_available()
        
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
            
            logger.debug(f"Loaded RSA key from {path}")
            return cls(private_key)
            
        except Exception as e:
            raise SigningError(f"Failed to load RSA key from {path}: {e}")
    
    def algorithm(self) -> str:
        """Get algorithm name."""
        return "RSA-PSS"
    
    def sign_bytes(self, data: bytes) -> bytes:
        """Sign bytes with RSA-PSS."""
        try:
            return self._private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            raise SigningError(f"RSA-PSS signing failed: {e}")
    
    def get_public_key_bytes(self) -> bytes:
        """Get DER-encoded public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_public_key_pem(self) -> bytes:
        """Get PEM-encoded public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def save_keys(self, directory: Union[str, Path]) -> None:
        """Save key pair to directory."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        
        private_pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        (d / "private.pem").write_bytes(private_pem)
        
        public_pem = self.get_public_key_pem()
        (d / "public.pem").write_bytes(public_pem)
        
        logger.info(f"RSA keys saved to {d}")


class ECDSASigner(Signer):
    """
    ECDSA-P256 signature scheme implementation.
    
    ECDSA with P-256 curve provides:
    - Good balance of security and performance
    - Smaller signatures than RSA
    - Wide hardware support
    
    Example:
        >>> signer = ECDSASigner.generate()
        >>> signer.sign(abom)
    """
    
    def __init__(self, private_key: Any) -> None:
        """Initialize with EC private key."""
        _check_crypto_available()
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls) -> "ECDSASigner":
        """Generate new ECDSA key pair with P-256 curve."""
        _check_crypto_available()
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        logger.debug("Generated new ECDSA-P256 key pair")
        return cls(private_key)
    
    @classmethod
    def from_file(
        cls,
        path: Union[str, Path],
        password: Optional[bytes] = None
    ) -> "ECDSASigner":
        """Load ECDSA signer from PEM file."""
        _check_crypto_available()
        
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
            
            logger.debug(f"Loaded ECDSA key from {path}")
            return cls(private_key)
            
        except Exception as e:
            raise SigningError(f"Failed to load ECDSA key from {path}: {e}")
    
    def algorithm(self) -> str:
        """Get algorithm name."""
        return "ECDSA-P256"
    
    def sign_bytes(self, data: bytes) -> bytes:
        """Sign bytes with ECDSA."""
        try:
            return self._private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            raise SigningError(f"ECDSA signing failed: {e}")
    
    def get_public_key_bytes(self) -> bytes:
        """Get DER-encoded public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_public_key_pem(self) -> bytes:
        """Get PEM-encoded public key."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def save_keys(self, directory: Union[str, Path]) -> None:
        """Save key pair to directory."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        
        private_pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        (d / "private.pem").write_bytes(private_pem)
        
        public_pem = self.get_public_key_pem()
        (d / "public.pem").write_bytes(public_pem)
        
        logger.info(f"ECDSA keys saved to {d}")
