"""
Safe Demo Database Initializer for CyberVault
Creates an automatic timestamped backup of your current database before initializing
clean sample keys and seed user accounts for demonstration.
"""

import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.crypto_vault import compute_fingerprint, encrypt_secret
from core.database import DB_PATH, INSTANCE_DIR, seed_default_users


def reset_demo_database():
    print("=" * 60)
    print("CYBERVAULT DEMO DATABASE INITIALIZATION")
    print("=" * 60)

    # 1. Safe Backup of existing database
    if DB_PATH.exists():
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = INSTANCE_DIR / f"framework.sqlite3.backup_{timestamp_str}"
        shutil.copy2(DB_PATH, backup_path)
        print(f"[+] Safety Backup Created: {backup_path.name}")
    else:
        print("[+] Creating fresh instance directory and database.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    with conn:
        # Recreate tables cleanly
        conn.execute("DROP TABLE IF EXISTS audit_logs")
        conn.execute("DROP TABLE IF EXISTS keys")
        conn.execute("DROP TABLE IF EXISTS users")

        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                secret_enc BLOB,
                public_pem TEXT,
                fingerprint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                usage_count INTEGER NOT NULL DEFAULT 0,
                created_by TEXT NOT NULL DEFAULT 'system',
                created_at TEXT NOT NULL,
                rotated_from INTEGER,
                FOREIGN KEY(rotated_from) REFERENCES keys(id) ON DELETE SET NULL
            )
        """)

        conn.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                status TEXT NOT NULL,
                duration_ms REAL NOT NULL DEFAULT 0.0,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Seed Users
        seed_default_users(conn)
        print("[+] Seeded Default Accounts:")
        print("    - admin    (Role: Administrator, Pwd: Admin@SecVault2026!)")
        print("    - operator (Role: Operator,      Pwd: Operator@SecVault2026!)")
        print("    - auditor  (Role: Viewer,        Pwd: Auditor@SecVault2026!)")

        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # Seed 1 Sample AES Key
        raw_aes = AESGCM.generate_key(bit_length=256)
        fp_aes = compute_fingerprint(raw_aes)
        cur = conn.execute("""
            INSERT INTO keys(name, key_type, algorithm, secret_enc, fingerprint, created_by, created_at)
            VALUES ('Demo-Primary-AES256', 'SYMMETRIC', 'AES-256-GCM', ?, ?, 'admin', ?)
        """, (encrypt_secret(raw_aes), fp_aes, now_iso))
        aes_id = cur.lastrowid
        print(f"[+] Generated Sample AES Key: #{aes_id} ({fp_aes})")

        # Seed 1 Sample RSA Key Pair
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem_bytes = rsa_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fp_rsa = compute_fingerprint(pub_pem_bytes)
        cur = conn.execute("""
            INSERT INTO keys(name, key_type, algorithm, secret_enc, public_pem, fingerprint, created_by, created_at)
            VALUES ('Demo-Identity-RSA2048', 'ASYMMETRIC', 'RSA-2048-OAEP/PSS', ?, ?, ?, 'admin', ?)
        """, (encrypt_secret(priv_pem), pub_pem_bytes.decode("ascii"), fp_rsa, now_iso))
        rsa_id = cur.lastrowid
        print(f"[+] Generated Sample RSA Key Pair: #{rsa_id} ({fp_rsa})")

        # Seed Initial Audit Log
        conn.execute("""
            INSERT INTO audit_logs(operation_id, user_id, action, algorithm, status, duration_ms, details, created_at)
            VALUES ('init-0000-0000', 'system', 'SYSTEM_INITIALIZATION', 'SYSTEM', 'SUCCESS', 0.0, 'Demo database initialized with baseline keys', ?)
        """, (now_iso,))

    conn.close()
    print("=" * 60)
    print("DEMO DATABASE READY FOR FACULTY PRESENTATION")
    print("=" * 60)


if __name__ == "__main__":
    reset_demo_database()
