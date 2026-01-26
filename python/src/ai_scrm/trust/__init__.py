"""
AI-SCRM Control Domain 2: Trust - AI Artifact Integrity & Authenticity

AI-SCS Section 6 Implementation.

Critical AI artifacts MUST support integrity and authenticity verification.

Classes:
    Signer - Sign ABOMs and artifacts
    Verifier - Verify signatures
    TrustAssertion - Artifact trust assertions (6.3)

Usage:
    from ai_scrm.trust import Signer, Verifier
    
    signer = Signer.generate()
    signer.sign(abom)
    
    verifier = Verifier()
    verifier.verify(abom)

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from ai_scrm.trust.signing import Signer, Ed25519Signer, RSASigner, ECDSASigner
from ai_scrm.trust.verification import Verifier, TrustPolicy
from ai_scrm.trust.assertion import TrustAssertion, TrustAssertionBuilder
from ai_scrm.trust.exceptions import TrustError, SigningError, VerificationError

__all__ = [
    "Signer",
    "Ed25519Signer",
    "RSASigner",
    "ECDSASigner",
    "Verifier",
    "TrustPolicy",
    "TrustAssertion",
    "TrustAssertionBuilder",
    "TrustError",
    "SigningError",
    "VerificationError",
]
