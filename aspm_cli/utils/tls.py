"""TLS for the scanner's own downloads (tool installs) made with urllib."""
from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def download_context() -> ssl.SSLContext:
    """Verify against the system's CAs plus certifi's bundle.

    Python on macOS does not read the system keychain, so the frozen macOS binary has no CA
    certificates of its own and every HTTPS download failed with CERTIFICATE_VERIFY_FAILED.
    certifi (already shipped for requests) is added to, not substituted for, the system store,
    so corporate CAs from the OS or SSL_CERT_FILE / SSL_CERT_DIR keep working. Verification
    always stays on.
    """
    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError):
        pass
    return context
