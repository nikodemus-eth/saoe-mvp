"""Tests for saoe_core.crypto.keyring — Ed25519 sign/verify and pinned key hash guards."""
import pytest
import nacl.exceptions

from saoe_core.crypto.keyring import (
    DispatcherKeyMismatchError,
    assert_key_pin,
    generate_keypair,
    hash_verify_key,
    load_signing_key,
    load_verify_key,
    sign_bytes,
    verify_bytes,
)


def test_generate_keypair_returns_valid_keys() -> None:
    sk, vk = generate_keypair()
    assert sk is not None
    assert vk is not None


def test_sign_and_verify_round_trip() -> None:
    sk, vk = generate_keypair()
    data = b"hello world"
    sig = sign_bytes(sk, data)
    verify_bytes(vk, data, sig)  # must not raise


def test_tampered_data_fails_verification() -> None:
    sk, vk = generate_keypair()
    data = b"authentic message"
    sig = sign_bytes(sk, data)
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_bytes(vk, b"tampered message", sig)


def test_tampered_signature_fails_verification() -> None:
    sk, vk = generate_keypair()
    data = b"authentic message"
    sig = sign_bytes(sk, data)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]  # flip one byte
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_bytes(vk, data, bad_sig)


def test_wrong_key_fails_verification() -> None:
    sk1, _ = generate_keypair()
    _, vk2 = generate_keypair()
    data = b"signed with key 1"
    sig = sign_bytes(sk1, data)
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_bytes(vk2, data, sig)


def test_hash_verify_key_is_hex_64_chars() -> None:
    _, vk = generate_keypair()
    h = hash_verify_key(vk)
    assert isinstance(h, str)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_verify_key_is_deterministic() -> None:
    _, vk = generate_keypair()
    assert hash_verify_key(vk) == hash_verify_key(vk)


def test_assert_key_pin_matches() -> None:
    _, vk = generate_keypair()
    pin = hash_verify_key(vk)
    assert_key_pin(vk, pin)  # must not raise


def test_assert_key_pin_mismatch_raises() -> None:
    _, vk = generate_keypair()
    _, vk2 = generate_keypair()
    wrong_pin = hash_verify_key(vk2)
    with pytest.raises(DispatcherKeyMismatchError):
        assert_key_pin(vk, wrong_pin)


def test_save_and_load_keypair_round_trip(tmp_path) -> None:
    from saoe_core.crypto.keyring import save_signing_key, save_verify_key

    sk, vk = generate_keypair()
    sk_path = tmp_path / "test.key"
    vk_path = tmp_path / "test.pub"
    save_signing_key(sk, sk_path)
    save_verify_key(vk, vk_path)

    sk2 = load_signing_key(sk_path)
    vk2 = load_verify_key(vk_path)

    # Verify same keys: sign with loaded sk, verify with loaded vk
    data = b"round trip test"
    sig = sign_bytes(sk2, data)
    verify_bytes(vk2, data, sig)

    # Also cross-verify with originals
    sig2 = sign_bytes(sk, data)
    verify_bytes(vk2, data, sig2)
