import hashlib
import secrets
import time
from typing import Dict, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LATEST_BENCHMARK_CACHE: Dict = {}


def run_comprehensive_benchmark() -> Dict:
    """
    Execute real, microsecond-accurate cryptographic performance benchmarks on local hardware.
    Benchmarks algorithms according to their actual purpose:
    - Symmetric Authenticated Encryption (AES-GCM)
    - Asymmetric Key Gen & Hybrid Encryption (RSA-2048)
    - Digital Signatures (RSA-PSS)
    - Hashing Throughput (SHA-256 vs SHA-512)
    """
    results: Dict = {
        "timestamp": time.time(),
        "symmetric_aes_gcm": [],
        "asymmetric_rsa": {},
        "signatures_rsa_pss": {},
        "hashing": []
    }

    # 1. Symmetric AES-256-GCM Across Different Payload Sizes
    aes_key = AESGCM.generate_key(bit_length=256)
    aes_cipher = AESGCM(aes_key)
    sizes = [
        ("1 KB", 1024),
        ("64 KB", 64 * 1024),
        ("512 KB", 512 * 1024),
        ("1 MB", 1024 * 1024)
    ]

    for label, byte_count in sizes:
        sample_data = secrets.token_bytes(byte_count)
        nonce = secrets.token_bytes(12)

        # Encrypt
        t0 = time.perf_counter()
        ct = aes_cipher.encrypt(nonce, sample_data, None)
        enc_dur = time.perf_counter() - t0
        enc_mb_s = (byte_count / (1024 * 1024)) / enc_dur if enc_dur > 0 else 0

        # Decrypt
        t0 = time.perf_counter()
        pt = aes_cipher.decrypt(nonce, ct, None)
        dec_dur = time.perf_counter() - t0
        dec_mb_s = (byte_count / (1024 * 1024)) / dec_dur if dec_dur > 0 else 0

        results["symmetric_aes_gcm"].append({
            "size_label": label,
            "bytes": byte_count,
            "encrypt_ms": round(enc_dur * 1000, 3),
            "decrypt_ms": round(dec_dur * 1000, 3),
            "encrypt_mb_s": round(enc_mb_s, 2),
            "decrypt_mb_s": round(dec_mb_s, 2)
        })

    # 2. Asymmetric RSA-2048 Operations
    t0 = time.perf_counter()
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keygen_ms = (time.perf_counter() - t0) * 1000
    rsa_pub = rsa_priv.public_key()

    # Hybrid Encrypt (Wrapping 256-bit AES key + encrypting 16 KB payload)
    hybrid_payload = secrets.token_bytes(16 * 1024)
    content_key = AESGCM.generate_key(bit_length=256)
    content_nonce = secrets.token_bytes(12)

    t0 = time.perf_counter()
    wrapped = rsa_pub.encrypt(
        content_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    hybrid_ct = AESGCM(content_key).encrypt(content_nonce, hybrid_payload, None)
    hybrid_enc_ms = (time.perf_counter() - t0) * 1000

    # Hybrid Decrypt
    t0 = time.perf_counter()
    recovered_content_key = rsa_priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    recovered_payload = AESGCM(recovered_content_key).decrypt(content_nonce, hybrid_ct, None)
    hybrid_dec_ms = (time.perf_counter() - t0) * 1000

    results["asymmetric_rsa"] = {
        "key_size": "2048-bit",
        "keygen_ms": round(keygen_ms, 2),
        "hybrid_encrypt_ms": round(hybrid_enc_ms, 3),
        "hybrid_decrypt_ms": round(hybrid_dec_ms, 3),
        "sample_size": "16 KB"
    }

    # 3. RSA-PSS Digital Signatures (1 KB message)
    sig_message = secrets.token_bytes(1024)
    t0 = time.perf_counter()
    signature = rsa_priv.sign(
        sig_message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sign_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    rsa_pub.verify(
        signature,
        sig_message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    verify_ms = (time.perf_counter() - t0) * 1000

    results["signatures_rsa_pss"] = {
        "algorithm": "RSA-PSS-SHA256",
        "sign_ms": round(sign_ms, 3),
        "verify_ms": round(verify_ms, 3),
        "sign_ops_per_sec": round(1000 / sign_ms, 1) if sign_ms > 0 else 0,
        "verify_ops_per_sec": round(1000 / verify_ms, 1) if verify_ms > 0 else 0
    }

    # 4. Hashing Throughput (SHA-256 vs SHA-512)
    for label, byte_count in sizes:
        test_data = secrets.token_bytes(byte_count)

        # SHA-256
        t0 = time.perf_counter()
        _ = hashlib.sha256(test_data).hexdigest()
        sha256_dur = time.perf_counter() - t0
        sha256_mb_s = (byte_count / (1024 * 1024)) / sha256_dur if sha256_dur > 0 else 0

        # SHA-512
        t0 = time.perf_counter()
        _ = hashlib.sha512(test_data).hexdigest()
        sha512_dur = time.perf_counter() - t0
        sha512_mb_s = (byte_count / (1024 * 1024)) / sha512_dur if sha512_dur > 0 else 0

        results["hashing"].append({
            "size_label": label,
            "bytes": byte_count,
            "sha256_ms": round(sha256_dur * 1000, 3),
            "sha256_mb_s": round(sha256_mb_s, 2),
            "sha512_ms": round(sha512_dur * 1000, 3),
            "sha512_mb_s": round(sha512_mb_s, 2)
        })

    global LATEST_BENCHMARK_CACHE
    LATEST_BENCHMARK_CACHE = results
    return results


def get_latest_benchmark() -> Dict:
    """Return cached benchmark results or run a fresh suite if empty."""
    global LATEST_BENCHMARK_CACHE
    if not LATEST_BENCHMARK_CACHE:
        return run_comprehensive_benchmark()
    return LATEST_BENCHMARK_CACHE
