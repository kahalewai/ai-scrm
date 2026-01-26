"""
Test Suite - Control Domain 2: Trust (AI-SCS Section 6)

Tests for AI Artifact Integrity & Authenticity Assurance.

AI-SCS Requirements Tested:
    - Section 6.1: Integrity and authenticity verification support
    - Section 6.2: Covered artifacts (models, embeddings, agent logic)
    - Section 6.3: Trust Assertion fields
    - Section 6.4: Verification requirements

Run with: pytest tests/test_trust.py -v
"""
import pytest
import tempfile
from pathlib import Path

# Skip all tests if cryptography not available
try:
    import cryptography
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package required")
class TestSigning:
    """Test signing functionality for AI-SCS Section 6."""
    
    def test_generate_ed25519_signer(self):
        """Test Ed25519 key generation."""
        from ai_scrm.trust import Signer
        
        signer = Signer.generate("ed25519")
        assert signer.algorithm() == "Ed25519"
    
    def test_generate_rsa_signer(self):
        """Test RSA key generation."""
        from ai_scrm.trust import Signer
        
        signer = Signer.generate("rsa")
        assert signer.algorithm() == "RSA-PSS"
    
    def test_generate_ecdsa_signer(self):
        """Test ECDSA key generation."""
        from ai_scrm.trust import Signer
        
        signer = Signer.generate("ecdsa")
        assert signer.algorithm() == "ECDSA-P256"
    
    def test_sign_bytes(self):
        """Test signing raw bytes."""
        from ai_scrm.trust import Signer
        
        signer = Signer.generate("ed25519")
        signature = signer.sign_bytes(b"test data")
        
        assert signature is not None
        assert len(signature) == 64  # Ed25519 signature size
    
    def test_sign_abom(self):
        """Test signing ABOM document."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Signer
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        signer = Signer.generate("ed25519")
        sig = signer.sign(abom)
        
        assert abom.signature is not None
        assert abom.signature["algorithm"] == "Ed25519"
        assert "value" in abom.signature
        assert "publicKey" in abom.signature
    
    def test_save_and_load_keys(self):
        """Test saving and loading key pair."""
        from ai_scrm.trust import Signer, Ed25519Signer
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate and save
            signer = Signer.generate("ed25519")
            signer.save_keys(tmpdir)
            
            # Verify files exist
            assert (Path(tmpdir) / "private.pem").exists()
            assert (Path(tmpdir) / "public.pem").exists()
            
            # Load and verify
            loaded = Ed25519Signer.from_file(Path(tmpdir) / "private.pem")
            assert loaded.algorithm() == "Ed25519"
    
    def test_unsupported_algorithm_raises(self):
        """Test unsupported algorithm raises error."""
        from ai_scrm.trust import Signer
        from ai_scrm.trust.exceptions import SigningError
        
        with pytest.raises(SigningError, match="Unsupported"):
            Signer.generate("invalid-algorithm")


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package required")
class TestVerification:
    """Test verification functionality for AI-SCS 6.4."""
    
    def test_verify_signed_abom(self):
        """AI-SCS 6.4: Verify Trust Assertions prior to use."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Signer, Verifier
        
        # Create and sign ABOM
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        signer = Signer.generate("ed25519")
        signer.sign(abom)
        
        # Verify
        verifier = Verifier()
        assert verifier.verify(abom) is True
    
    def test_reject_tampered_abom(self):
        """AI-SCS 6.4: Reject artifacts failing verification."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Signer, Verifier
        from ai_scrm.trust.exceptions import VerificationError
        
        # Create and sign ABOM
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        signer = Signer.generate("ed25519")
        signer.sign(abom)
        
        # Tamper with ABOM
        abom.components[0].version = "2.0"
        
        # Verify should fail
        verifier = Verifier()
        with pytest.raises(VerificationError, match="tampered"):
            verifier.verify(abom)
    
    def test_reject_unsigned_when_required(self):
        """AI-SCS 6.4: Reject unsigned artifacts when required."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Verifier
        from ai_scrm.trust.exceptions import VerificationError
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        verifier = Verifier(reject_unsigned=True)
        with pytest.raises(VerificationError, match="not signed"):
            verifier.verify(abom)
    
    def test_allow_unsigned_when_not_required(self):
        """Test unsigned ABOM passes when not required."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Verifier
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        verifier = Verifier(reject_unsigned=False)
        assert verifier.verify(abom) is True
    
    def test_is_valid_returns_bool(self):
        """Test is_valid convenience method."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import Signer, Verifier
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="test",
            version="1.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        signer = Signer.generate("ed25519")
        signer.sign(abom)
        
        verifier = Verifier()
        assert verifier.is_valid(abom) is True
        
        # Tamper
        abom.components[0].version = "2.0"
        assert verifier.is_valid(abom) is False


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package required")
class TestTrustAssertion:
    """Test Trust Assertions for AI-SCS 6.3."""
    
    def test_create_trust_assertion(self):
        """AI-SCS 6.3: Trust Assertion with required fields."""
        from ai_scrm.trust import TrustAssertion
        
        assertion = TrustAssertion(
            artifact_type="model",
            artifact_name="llama-7b",
            artifact_version="1.0.0",
            artifact_hash="abc123def456",
            artifact_hash_alg="SHA-256",
            abom_serial="urn:uuid:12345678-1234-1234-1234-123456789012",
            abom_hash="xyz789",
            issuer_name="Test Org",
            issuer_id="urn:ai-scs:issuer:test-org"
        )
        
        assert assertion.artifact_name == "llama-7b"
        assert assertion.assertion_id.startswith("urn:uuid:")
    
    def test_assertion_has_all_required_fields(self):
        """AI-SCS 6.3: Verify all required fields are present."""
        from ai_scrm.trust import TrustAssertion
        
        assertion = TrustAssertion(
            artifact_type="model",
            artifact_name="test",
            artifact_version="1.0",
            artifact_hash="abc123",
            artifact_hash_alg="SHA-256",
            abom_serial="urn:uuid:test",
            abom_hash="xyz789",
            issuer_name="Test",
            issuer_id="urn:ai-scs:issuer:test"
        )
        
        d = assertion.to_dict()
        
        # 6.3 Required fields
        assert "artifact" in d
        assert "name" in d["artifact"]  # Artifact identifier
        assert "hash" in d["artifact"]  # Cryptographic hash
        assert "issuer" in d  # Signing entity
        assert "issuedAt" in d  # Signing timestamp
        assert "abomBinding" in d  # Reference to ABOM
    
    def test_assertion_serialization_roundtrip(self):
        """Test assertion JSON roundtrip."""
        from ai_scrm.trust import TrustAssertion
        
        assertion = TrustAssertion(
            artifact_type="model",
            artifact_name="test",
            artifact_version="1.0",
            artifact_hash="abc123",
            artifact_hash_alg="SHA-256",
            abom_serial="urn:uuid:test",
            abom_hash="xyz789",
            issuer_name="Test",
            issuer_id="urn:ai-scs:issuer:test",
            expires_at="2025-12-31T23:59:59Z"
        )
        
        json_str = assertion.to_json()
        loaded = TrustAssertion.from_dict(__import__("json").loads(json_str))
        
        assert loaded.artifact_name == assertion.artifact_name
        assert loaded.expires_at == assertion.expires_at
    
    def test_assertion_file_roundtrip(self):
        """Test assertion file save/load."""
        from ai_scrm.trust import TrustAssertion
        
        assertion = TrustAssertion(
            artifact_type="model",
            artifact_name="test",
            artifact_version="1.0",
            artifact_hash="abc123",
            artifact_hash_alg="SHA-256",
            abom_serial="urn:uuid:test",
            abom_hash="xyz789",
            issuer_name="Test",
            issuer_id="urn:ai-scs:issuer:test"
        )
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        
        try:
            assertion.to_file(path)
            loaded = TrustAssertion.from_file(path)
            assert loaded.artifact_name == "test"
        finally:
            path.unlink()
    
    def test_assertion_missing_required_fields(self):
        """Test assertion fails without required fields."""
        from ai_scrm.trust import TrustAssertion
        
        with pytest.raises(ValueError, match="Missing required"):
            TrustAssertion(
                artifact_type="model",
                artifact_name="",  # Empty
                artifact_version="1.0",
                artifact_hash="abc123",
                artifact_hash_alg="SHA-256",
                abom_serial="urn:uuid:test",
                abom_hash="xyz789",
                issuer_name="Test",
                issuer_id="urn:ai-scs:issuer:test"
            )


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package required")
class TestTrustAssertionBuilder:
    """Test TrustAssertionBuilder."""
    
    def test_create_for_component(self):
        """Test creating assertion for ABOM component."""
        from ai_scrm.abom import ABOM, ABOMComponent, Hash
        from ai_scrm.trust import TrustAssertionBuilder
        
        comp = ABOMComponent(
            type="machine-learning-model",
            name="llama-7b",
            version="1.0.0",
            hashes=[Hash(alg="SHA-256", content="abc123")]
        )
        abom = ABOM(components=[comp])
        
        builder = TrustAssertionBuilder(
            issuer_name="Test Org",
            issuer_id="urn:ai-scs:issuer:test"
        )
        
        assertion = builder.create_for_component(comp, abom)
        
        assert assertion.artifact_name == "llama-7b"
        assert assertion.artifact_hash == "abc123"
        assert assertion.abom_serial == abom.serial_number
    
    def test_create_for_component_without_hash_fails(self):
        """Test component without hash raises error."""
        from ai_scrm.abom import ABOM, ABOMComponent
        from ai_scrm.trust import TrustAssertionBuilder
        
        comp = ABOMComponent(
            type="service",
            name="tool",
            version="1.0"
        )
        abom = ABOM(components=[comp])
        
        builder = TrustAssertionBuilder(
            issuer_name="Test",
            issuer_id="urn:ai-scs:issuer:test"
        )
        
        with pytest.raises(ValueError, match="no hash"):
            builder.create_for_component(comp, abom)
