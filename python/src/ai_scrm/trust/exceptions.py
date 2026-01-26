"""Trust module exceptions.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""


class TrustError(Exception):
    """Base trust error."""
    pass


class SigningError(TrustError):
    """Signing failed."""
    pass


class VerificationError(TrustError):
    """Verification failed."""
    pass
