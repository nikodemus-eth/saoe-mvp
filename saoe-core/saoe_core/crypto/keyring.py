"""Ed25519 key management with pinned key hash guards.

FT-001: Pinned dispatcher key hash — abort if loaded key does not match.
FT-006: Pinned plan issuer key hash — same mechanism for over_agent.

Key storage format: raw 32-byte binary files.
  - Signing key file: 32-byte seed (PyNaCl native)
  - Verify key file:  32-byte public key bytes
"""
import hashlib
import stat
from pathlib import Path

import nacl.signing


# ---------------------------------------------------------------------------
# Sentinel value — replace after running setup_demo.py
# ---------------------------------------------------------------------------

#: Hex SHA-256 of the dispatcher verify key bytes.
#: Set to the value printed by ``examples/demo/setup_demo.py``.
#: Runtime aborts (DispatcherKeyMismatchError) if the loaded key does not match.
DISPATCHER_KEY_HASH_PIN: str = "UNSET_PIN_REPLACE_AFTER_RUNNING_SETUP_DEMO"


class DispatcherKeyMismatchError(RuntimeError):
    """Raised when a loaded verify key does not match its pinned SHA-256 hash."""


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[nacl.signing.SigningKey, nacl.signing.VerifyKey]:
    """Generate a fresh Ed25519 keypair."""
    sk = nacl.signing.SigningKey.generate()
    return sk, sk.verify_key


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------


def save_signing_key(sk: nacl.signing.SigningKey, path: Path) -> None:
    """Write raw 32-byte signing key seed to *path* with mode 0600."""
    path.write_bytes(bytes(sk))
    path.chmod(0o600)


def save_verify_key(vk: nacl.signing.VerifyKey, path: Path) -> None:
    """Write raw 32-byte verify key to *path*."""
    path.write_bytes(bytes(vk))


def load_signing_key(path: Path) -> nacl.signing.SigningKey:
    """Load a signing key from a 32-byte seed file."""
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"Signing key file must be 32 bytes, got {len(raw)}: {path}")
    return nacl.signing.SigningKey(raw)


def load_verify_key(path: Path) -> nacl.signing.VerifyKey:
    """Load a verify key from a 32-byte public key file."""
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"Verify key file must be 32 bytes, got {len(raw)}: {path}")
    return nacl.signing.VerifyKey(raw)


# ---------------------------------------------------------------------------
# Cryptographic operations
# ---------------------------------------------------------------------------


def sign_bytes(sk: nacl.signing.SigningKey, data: bytes) -> bytes:
    """Sign *data* with *sk*; return the 64-byte Ed25519 signature."""
    signed = sk.sign(data)
    return signed.signature


def verify_bytes(
    vk: nacl.signing.VerifyKey,
    data: bytes,
    signature: bytes,
) -> None:
    """Verify *signature* over *data* with *vk*.

    Raises
    ------
    nacl.exceptions.BadSignatureError
        If the signature is invalid.
    """
    vk.verify(data, signature)


# ---------------------------------------------------------------------------
# Pinning helpers
# ---------------------------------------------------------------------------


def hash_verify_key(vk: nacl.signing.VerifyKey) -> str:
    """Return the hex SHA-256 digest of the raw 32-byte verify key bytes."""
    return hashlib.sha256(bytes(vk)).hexdigest()


def assert_key_pin(vk: nacl.signing.VerifyKey, expected_pin: str) -> None:
    """Assert that *vk* matches *expected_pin* (hex SHA-256 of its bytes).

    Parameters
    ----------
    vk:
        The verify key to check.
    expected_pin:
        Hex SHA-256 that was pinned in source or config.

    Raises
    ------
    DispatcherKeyMismatchError
        If the hash does not match.
    """
    actual = hash_verify_key(vk)
    if actual != expected_pin:
        raise DispatcherKeyMismatchError(
            f"Pinned key hash mismatch.\n"
            f"  Expected: {expected_pin}\n"
            f"  Got:      {actual}\n"
            "Re-run setup_demo.py and paste the printed hash into the appropriate constant."
        )
