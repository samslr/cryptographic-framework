import hashlib
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

INSTANCE_DIR = Path(__file__).resolve().parent.parent / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
MASTER_KEY_PATH = INSTANCE_DIR / "master.key"


def get_master_vault() -> Fernet:
    """Retrieve or initialize the local Fernet master vault key."""
    env_key = os.environ.get("APP_MASTER_KEY", "").strip()
    if env_key:
        key_bytes = env_key.encode("utf-8")
    else:
        if not MASTER_KEY_PATH.exists():
            new_key = Fernet.generate_key()
            MASTER_KEY_PATH.write_bytes(new_key)
            try:
                os.chmod(MASTER_KEY_PATH, 0o600)
            except OSError:
                pass
        key_bytes = MASTER_KEY_PATH.read_bytes().strip()

    try:
        return Fernet(key_bytes)
    except Exception as exc:
        raise RuntimeError("APP_MASTER_KEY is invalid. Supply a valid 32-byte url-safe base64 Fernet key.") from exc


VAULT = get_master_vault()


def encrypt_secret(data: bytes) -> bytes:
    """Encrypt sensitive key material using the master vault key."""
    return VAULT.encrypt(data)


def decrypt_secret(encrypted_data: bytes) -> bytes:
    """Decrypt sensitive key material using the master vault key."""
    return VAULT.decrypt(encrypted_data)


def compute_fingerprint(material: bytes) -> str:
    """Compute a standard hexadecimal SHA-256 fingerprint for cryptographic material."""
    digest = hashlib.sha256(material).hexdigest()
    # Format into pairs: SHA256:xx:xx:xx...
    formatted = ":".join(digest[i:i+2] for i in range(0, min(len(digest), 32), 2))
    return f"SHA256:{formatted.upper()}"
