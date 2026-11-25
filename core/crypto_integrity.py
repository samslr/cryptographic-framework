import hashlib
from typing import Dict, List


def flip_one_bit(text: str) -> str:
    """Flip exactly one bit in the input string to showcase strict avalanche effect."""
    if not text:
        return "a"
    raw = bytearray(text.encode("utf-8"))
    raw[0] ^= 0x01  # Flip lowest bit of first byte
    return raw.decode("utf-8", errors="replace")


def compute_avalanche(input_a: str, input_b: str, algorithm: str = "SHA-256") -> Dict:
    """
    Demonstrate the cryptographic Avalanche Effect:
    A minimal change in the input (e.g. 1 bit) should cause an unpredictable
    change of roughly 50% of the output digest bits (Strict Avalanche Criterion).
    """
    algo_name = algorithm.upper().replace("_", "-")
    if algo_name not in ("SHA-256", "SHA-512"):
        raise ValueError("Avalanche analysis supports SHA-256 or SHA-512.")

    digest_type = "sha256" if algo_name == "SHA-256" else "sha512"
    hash_a_bytes = hashlib.new(digest_type, input_a.encode("utf-8")).digest()
    hash_b_bytes = hashlib.new(digest_type, input_b.encode("utf-8")).digest()

    hash_a_hex = hash_a_bytes.hex()
    hash_b_hex = hash_b_bytes.hex()

    total_bits = len(hash_a_bytes) * 8
    changed_bits = 0
    bit_map: List[int] = []  # 1 if bit changed, 0 if unchanged

    for byte_a, byte_b in zip(hash_a_bytes, hash_b_bytes):
        diff = byte_a ^ byte_b
        for bit_idx in range(7, -1, -1):
            is_diff = (diff >> bit_idx) & 1
            if is_diff:
                changed_bits += 1
            bit_map.append(is_diff)

    percentage = round((changed_bits / total_bits) * 100, 2)

    return {
        "algorithm": algo_name,
        "input_a": input_a,
        "input_b": input_b,
        "hash_a": hash_a_hex,
        "hash_b": hash_b_hex,
        "total_bits": total_bits,
        "changed_bits": changed_bits,
        "unchanged_bits": total_bits - changed_bits,
        "change_percentage": percentage,
        "avalanche_quality": "OPTIMAL (≈50%)" if 45.0 <= percentage <= 55.0 else ("STRONG" if 40.0 <= percentage <= 60.0 else "SUBOPTIMAL"),
        "bit_map": bit_map[:128]  # First 128 bits for clean visual grid display
    }
