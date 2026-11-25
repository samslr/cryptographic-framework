import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_bytes(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt arbitrary bytes with AES-256-GCM.
    Returns (12-byte nonce, ciphertext_with_tag).
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte (256-bit) key.")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Authenticate and decrypt AES-256-GCM ciphertext.
    Raises ValueError if nonce length is invalid or authentication tag check fails.
    """
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes.")
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte (256-bit) key.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed: authentication tag mismatch or corrupted ciphertext.") from exc


def encrypt_file_payload(file_content: bytes, key: bytes) -> bytes:
    """
    Pack encrypted file into standard container:
    [12 bytes Nonce] + [AES-GCM Ciphertext + 16 bytes Tag]
    """
    nonce, ciphertext = encrypt_bytes(file_content, key)
    return nonce + ciphertext


def decrypt_file_payload(package: bytes, key: bytes) -> bytes:
    """
    Unpack and authenticate encrypted file container.
    """
    if len(package) < 28:  # 12-byte nonce + 16-byte tag minimum
        raise ValueError("File payload is too small to be a valid encrypted container.")
    nonce = package[:12]
    ciphertext = package[12:]
    return decrypt_bytes(nonce, ciphertext, key)
