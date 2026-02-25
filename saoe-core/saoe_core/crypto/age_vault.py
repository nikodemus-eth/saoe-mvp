"""Read-only template and capability set vault using age encryption.

FT-001: Dispatcher verify key is checked against pinned hash at init.

Runtime behaviour:
- Templates and capability sets are stored as age-encrypted JSON files.
- AgeVault decrypts on demand via the ``age`` CLI (subprocess).
- The vault directory must be read-only for all runtime processes.
- Write access is restricted to the ``saoe-publish-template`` command.

Unit test behaviour:
- Use ``AgeVault._from_mock(entries, ...)`` to bypass the age CLI.
"""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import nacl.signing

from saoe_core.crypto.keyring import DispatcherKeyMismatchError, assert_key_pin

# Path to age binary — checked at import time for helpful error messages.
_AGE_BIN: str | None = shutil.which("age") or "/opt/homebrew/bin/age" if Path(
    "/opt/homebrew/bin/age"
).exists() else None


class VaultEntryNotFoundError(KeyError):
    """Raised when a template or capability set cannot be found in the vault."""


class AgeDecryptError(RuntimeError):
    """Raised when age decryption fails."""


class AgeVault:
    """Read-only view of the age-encrypted SAOE vault.

    Typical vault layout::

        vault/
          templates/<template_id>_v<version>.json.age
          capsets/<cap_set_id>_v<version>.json.age
          keys/dispatcher_verify.pub   (raw 32-byte public key, plaintext)

    Parameters
    ----------
    vault_dir:
        Path to the vault directory (must be read-only at runtime).
    identity_file:
        age identity file (private key) used for decryption.
        Must have file mode 0600.
    dispatcher_pin:
        Hex SHA-256 of the dispatcher verify key.  Loaded key is checked against
        this at construction time (FT-001).  Pass ``None`` to skip (tests only).
    """

    def __init__(
        self,
        vault_dir: Path,
        identity_file: Path,
        dispatcher_pin: str,
    ) -> None:
        self._vault_dir = Path(vault_dir)
        self._identity_file = Path(identity_file)
        self._mock_entries: dict[str, str] | None = None

        self._validate_identity_file_permissions()
        self._dispatcher_vk: nacl.signing.VerifyKey = self._load_dispatcher_key(dispatcher_pin)

    @classmethod
    def _from_mock(
        cls,
        entries: dict[str, str],
        *,
        dispatcher_vk: nacl.signing.VerifyKey,
        dispatcher_pin: str,
    ) -> "AgeVault":
        """Construct a vault backed by in-memory entries (for unit tests only)."""
        # FT-001: still enforce pin check even in mock mode.
        assert_key_pin(dispatcher_vk, dispatcher_pin)

        instance = object.__new__(cls)
        instance._vault_dir = Path("/nonexistent/mock")
        instance._identity_file = Path("/nonexistent/mock.key")
        instance._mock_entries = dict(entries)
        instance._dispatcher_vk = dispatcher_vk
        return instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_template(self, template_id: str, version: str) -> dict[str, Any]:
        """Decrypt and return the template JSON for the given id and version."""
        key = f"template:{template_id}:{version}"
        raw = self._get_entry(key)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgeDecryptError(f"Template JSON parse error for {key}: {exc}") from exc

    def get_capability_set(self, cap_set_id: str, version: str) -> dict[str, Any]:
        """Decrypt and return the capability set JSON for the given id and version."""
        key = f"capset:{cap_set_id}:{version}"
        raw = self._get_entry(key)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgeDecryptError(f"CapSet JSON parse error for {key}: {exc}") from exc

    def get_dispatcher_verify_key(self) -> nacl.signing.VerifyKey:
        """Return the pinned dispatcher verify key."""
        return self._dispatcher_vk

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_entry(self, key: str) -> str:
        """Return raw plaintext JSON string for *key*."""
        if self._mock_entries is not None:
            if key not in self._mock_entries:
                raise VaultEntryNotFoundError(f"No vault entry for key: {key!r}")
            return self._mock_entries[key]

        # Real vault: derive file path from key.
        # key format: "template:blog_article_intent:1"
        kind, name, version = key.split(":", 2)
        subdir = "templates" if kind == "template" else "capsets"
        age_file = self._vault_dir / subdir / f"{name}_v{version}.json.age"

        if not age_file.exists():
            raise VaultEntryNotFoundError(f"Vault file not found: {age_file}")

        return self._decrypt(age_file).decode("utf-8")

    def _decrypt(self, age_file: Path) -> bytes:
        """Run age decrypt on *age_file* and return plaintext bytes."""
        if _AGE_BIN is None:
            raise AgeDecryptError(
                "age binary not found. Install with: brew install age"
            )
        try:
            result = subprocess.run(
                [_AGE_BIN, "--decrypt", "-i", str(self._identity_file), str(age_file)],
                capture_output=True,
                timeout=10,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as exc:
            raise AgeDecryptError(
                f"age decryption failed for {age_file}: "
                f"{exc.stderr.decode('utf-8', errors='replace')}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AgeDecryptError(f"age decryption timed out for {age_file}") from exc

    def _load_dispatcher_key(self, dispatcher_pin: str) -> nacl.signing.VerifyKey:
        """Load the dispatcher verify key from vault and assert pin (FT-001)."""
        key_file = self._vault_dir / "keys" / "dispatcher_verify.pub"
        if not key_file.exists():
            raise FileNotFoundError(f"Dispatcher verify key not found: {key_file}")
        raw = key_file.read_bytes()
        if len(raw) != 32:
            raise ValueError(f"Dispatcher verify key must be 32 bytes, got {len(raw)}")
        vk = nacl.signing.VerifyKey(raw)
        assert_key_pin(vk, dispatcher_pin)
        return vk

    def _validate_identity_file_permissions(self) -> None:
        """Check that the identity file has mode 0600."""
        try:
            st = os.stat(self._identity_file)
        except FileNotFoundError:
            raise FileNotFoundError(f"age identity file not found: {self._identity_file}")
        mode = stat.S_IMODE(st.st_mode)
        if mode != 0o600:
            raise PermissionError(
                f"age identity file {self._identity_file} must have mode 0600, "
                f"got {oct(mode)}"
            )
