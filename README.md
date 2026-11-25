# CyberVault: A Modular Multi-Algorithm Cryptographic Framework

**A Modular Multi-Algorithm Cryptographic Framework for Secure Data Protection, Privacy Preservation, and Access Control.**

CyberVault is a fully functional, enterprise-grade cybersecurity operations platform and academic research framework built with **Python Flask**, **SQLite**, and the Python **`cryptography`** library. It demonstrates genuine cryptographic operations, envelope key management, data integrity verification, server-side role-based access control (RBAC), and hardware-measured performance telemetry.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [System Architecture](#system-architecture)
4. [Cryptographic Modules & Features](#cryptographic-modules--features)
5. [Installation & Execution](#installation--execution)
6. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
7. [API Specification](#api-specification)
8. [Automated Test Suite & Verification](#automated-test-suite--verification)
9. [Faculty Demonstration Walkthrough](#faculty-demonstration-walkthrough)
10. [Database Management & Demo Reset](#database-management--demo-reset)
11. [Security Considerations & Limitations](#security-considerations--limitations)

---

## 1. Project Overview

Modern secure systems require more than isolated cryptographic algorithms; they demand integrated key lifecycle management, authenticated cipher modes, provable message signing, strict data integrity verification, and access governance.

CyberVault provides a unified operations console inspired by modern Security Operations Center (SOC) platforms. It implements:
- **Authenticated Symmetric Encryption:** AES-256 in Galois/Counter Mode (GCM) for confidential and tamper-proof text and file encryption.
- **Asymmetric Hybrid Encryption:** RSA-2048 with Optimal Asymmetric Encryption Padding (OAEP) wrapping ephemeral AES content keys.
- **Provably Secure Digital Signatures:** RSA Probabilistic Signature Scheme (RSA-PSS) with SHA-256 and maximal salt length.
- **Integrity & Strict Avalanche Analysis:** FIPS 180-4 SHA-256/SHA-512 digests, constant-time verification, and interactive bit-level Hamming distance calculations.
- **KMS Envelope Key Management:** Master vault key protection (Fernet/AES-CBC + HMAC), automated key lineage tracking, and SHA-256 key fingerprints.
- **Server-Side Access Control:** Scrypt password hashing with unique salts, session management, CSRF defense, and strict role permissions (`Administrator`, `Operator`, `Viewer`).
- **Audit Logging & Telemetry:** UUID4 correlation identifiers, microsecond execution timings, status filtering, and streaming CSV export.

---

## 2. Technology Stack

- **Backend Framework:** Python Flask 3.1.3 (WSGI-compliant micro-framework)
- **Database:** SQLite 3 (Thread-safe, request-scoped lifecycle via `flask.g`)
- **Cryptographic Engine:** Python `cryptography` 50.0.2 (OpenSSL-backed primitives)
- **Password KDF:** Scrypt KDF (`n=32768, r=8, p=1`, 64 MB memory limit)
- **Frontend Architecture:** Vanilla HTML5, Modern SOC CSS3, and JavaScript ES6+ (Zero external UI dependencies or paid CDNs)
- **Test Runner:** Pytest 9.2.0

---

## 3. System Architecture

```
[ Client Presentation Layer ]
  └── Vanilla HTML5 / Custom SOC CSS3 / ES6+ Dashboard (app.js)
         │
         ▼  (REST JSON / Multipart Form-Data / X-CSRF-Token)
[ Flask Application Gateway (app.py) ]
  ├── Rate Limiter (Sliding Window per IP)
  ├── CSRF Validator & Session Manager
  └── Exception Sanitizer (@api_errors)
         │
         ▼
[ Security & Access Control Layer (core/security.py) ]
  ├── Scrypt KDF Password Hasher & Constant-Time Verifier
  └── Server-Side Role-Based Access Control (@require_role)
         │
         ▼
[ Cryptographic Core Engines ]
  ├── Symmetric Engine (core/crypto_symmetric.py): AES-256-GCM
  ├── Asymmetric Engine (app.py): RSA-2048 OAEP Hybrid & RSA-PSS
  ├── Integrity Engine (core/crypto_integrity.py): SHA-256/512 & Avalanche Lab
  └── Benchmark Engine (core/crypto_benchmarks.py): Live CPU Throughput
         │
         ▼
[ Key Vault & KMS Layer (core/crypto_vault.py) ]
  ├── Master Key Envelope Encryption (`instance/master.key` via Fernet)
  └── SHA-256 Key Fingerprinting
         │
         ▼
[ Relational Persistence Layer (core/database.py) ]
  └── SQLite 3 Database (`instance/framework.sqlite3`)
      ├── `users` Table (Scrypt hashed credentials, roles)
      ├── `keys` Table (Encrypted private material, public PEM, fingerprints)
      └── `audit_logs` Table (UUID4 trace IDs, latency, user attribution)
```

---

## 4. Cryptographic Modules & Features

### Module 01: Symmetric Encryption (AES-256-GCM)
- **Authenticated Cipher:** Uses AES-256 in Galois/Counter Mode (NIST SP 800-38D).
- **Nonce Freshness:** Cryptographically secure 96-bit random nonce generated per operation via `secrets.token_bytes(12)`.
- **Integrity Tag:** Embedded 128-bit authentication tag. Tampering with even a single bit of ciphertext triggers immediate rejection during decryption.
- **Text & File Containers:** Encrypts text payloads to JSON and arbitrary binary files up to 20 MB into downloadable `.enc` container packages (`[12-byte Nonce] + [Ciphertext + 16-byte Tag]`).

### Module 02: Asymmetric Encryption & Digital Signatures
- **RSA-OAEP Hybrid Encryption:** Solves the RSA plaintext size constraint by generating an ephemeral 256-bit AES content key, encrypting the message with AES-GCM, and wrapping the content key with RSA-2048 OAEP (SHA-256 + MGF1).
- **RSA-PSS Digital Signatures:** Generates probabilistic signatures compliant with RFC 8017 using SHA-256 and `salt_length=PSS.MAX_LENGTH`.
- **Public Key Export:** Public keys can be inspected and exported in SubjectPublicKeyInfo (`.pem`) format along with their SHA-256 fingerprint.

### Module 03: Hashing, Integrity & Avalanche Effect Lab
- **Cryptographic Digests:** Computes FIPS 180-4 SHA-256 (256-bit) and SHA-512 (512-bit) hashes for text and streamed file uploads.
- **Constant-Time Verification:** Uses `secrets.compare_digest()` to eliminate timing side-channel attacks during integrity checks.
- **Strict Avalanche Effect Lab:** Computes the bitwise Hamming distance between two inputs:
  $$\text{Avalanche Metric} = \frac{\sum (b_{1,i} \oplus b_{2,i})}{\text{Total Digest Bits}} \times 100\%$$
  Includes a single-bit perturbation tool and a 128-cell visual matrix rendering flipped vs unchanged bits.

### Module 04: Key Management & Storage
- **Envelope Encryption at Rest:** Private keys and raw symmetric keys are never stored in plaintext. They are encrypted using an external 256-bit Fernet master key before being written to SQLite.
- **Lifecycle Tracking:** Keys transition from `ACTIVE` to `ROTATED`. Rotated keys cannot be used for new encryptions but remain available for historical decryption.
- **Safe Key Deletion:** Key deletion requires explicit two-step modal confirmation, preventing accidental loss of decryption capability.

### Module 05: Cryptographic Performance Analytics
- **Genuine Hardware Benchmarks:** Measures actual CPU execution time across 1 KB, 64 KB, 512 KB, and 1 MB blocks.
- **Objective Evaluation:** Benchmarks algorithms according to their purpose (AES-GCM throughput, RSA hybrid latency, signature operations per second, SHA-256 vs SHA-512 throughput) without misleading cross-algorithm rankings.

### Module 06: System Architecture Visualizer
- **Interactive 7-Stage Pipeline:** Visualizes the journey of data through UI, API, RBAC, Crypto, Key Vault, Database, and Audit Trail. Clickable nodes display security standards and implementation parameters.

### Module 07: Audit Trail & Compliance
- **Forensic Traceability:** Every cryptographic event records a UUID4 operation ID, user identity, action, algorithm, duration in milliseconds, and status (`SUCCESS` / `FAILURE`).
- **Compliance Export:** Full audit trail can be filtered, searched, and exported to CSV.

---

## 5. Installation & Execution

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Quick Start (Windows)
Double-click `start.bat` in the project root folder. The script will:
1. Detect or create the local `.venv` virtual environment.
2. Install required dependencies from `requirements.txt`.
3. Launch the application server on `http://127.0.0.1:5000`.
4. Automatically open your default web browser to the dashboard.

### Manual Setup (PowerShell / Command Prompt)
```powershell
# Navigate to the project directory
cd cryptographic_framework

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Run the application
python app.py
```

### Manual Setup (Linux / macOS)
```bash
cd cryptographic_framework
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python3 app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

---

## 6. Role-Based Access Control (RBAC)

CyberVault implements server-side role-based access control with three pre-seeded accounts:

| Username | Default Password | Role | Permissions |
|---|---|---|---|
| **`admin`** | `Admin@SecVault2026!` | **Administrator** | Full system access: generate keys, rotate keys, delete keys, encrypt, decrypt, sign, verify, hash, run benchmarks, export audit logs. |
| **`operator`** | `Operator@SecVault2026!` | **Operator** | Operational access: generate keys, rotate keys, encrypt text/files, decrypt text/files, sign messages, verify signatures, hash, run benchmarks, export audit logs. *(Cannot permanently delete keys).* |
| **`auditor`** | `Auditor@SecVault2026!` | **Viewer** | Read-only compliance access: view key inventory, export public keys, verify hashes, verify signatures, view audit logs, view benchmarks. *(Cannot encrypt, decrypt, sign, rotate, or delete keys).* |

### Role Permissions Matrix

| Capability / API Endpoint | Administrator | Operator | Viewer |
|---|:---:|:---:|:---:|
| View Dashboard & Key Inventory | Yes | Yes | Yes |
| View Audit Logs & Benchmarks | Yes | Yes | Yes |
| Verify Hash / Verify Digital Signature | Yes | Yes | Yes |
| Export Public Key PEM | Yes | Yes | Yes |
| AES Encrypt / Decrypt (Text & File) | Yes | Yes | **No (403)** |
| RSA Hybrid Encrypt / Decrypt | Yes | Yes | **No (403)** |
| RSA-PSS Digital Sign | Yes | Yes | **No (403)** |
| Generate AES / RSA Keys | Yes | Yes | **No (403)** |
| Rotate Existing Keys | Yes | Yes | **No (403)** |
| Permanently Delete Keys | Yes | **No (403)** | **No (403)** |

---

## 7. API Specification

| Method | Endpoint | Required Role | Payload / Parameters | Description |
|---|---|:---:|---|---|
| `GET` | `/` | Open | None | Serves Single Page SOC Dashboard |
| `GET` | `/api/health` | Open | None | System health check and status |
| `POST` | `/api/auth/login` | Open | `{"username": str, "password": str}` | Authenticates user and sets session |
| `POST` | `/api/auth/logout` | Open | None | Terminates active session |
| `GET` | `/api/auth/me` | Open | None | Returns active user and CSRF token |
| `GET` | `/api/keys` | Open | None | Returns key inventory metadata |
| `POST` | `/api/keys/aes` | Operator / Admin | `{"name": str}` | Generates 256-bit AES-GCM key |
| `POST` | `/api/keys/rsa` | Operator / Admin | `{"name": str}` | Generates 2048-bit RSA key pair |
| `POST` | `/api/keys/<id>/rotate` | Operator / Admin | None | Rotates key and marks predecessor `ROTATED` |
| `DELETE` | `/api/keys/<id>` | **Admin Only** | None | Securely purges key from database |
| `GET` | `/api/keys/<id>/public` | Open | None | Exports public PEM and SHA-256 fingerprint |
| `POST` | `/api/symmetric/encrypt` | Operator / Admin | `{"key_id": int, "text": str}` | Encrypts text using AES-256-GCM |
| `POST` | `/api/symmetric/decrypt` | Operator / Admin | `{"key_id": int, "nonce": b64, "ciphertext": b64}` | Decrypts and authenticates ciphertext |
| `POST` | `/api/symmetric/encrypt-file` | Operator / Admin | `multipart/form-data` (`file`, `key_id`) | Encrypts file to `.enc` package |
| `POST` | `/api/symmetric/decrypt-file` | Operator / Admin | `multipart/form-data` (`file`, `key_id`) | Decrypts `.enc` package to original file |
| `POST` | `/api/asymmetric/encrypt` | Operator / Admin | `{"key_id": int, "text": str}` | Hybrid RSA-OAEP + AES-GCM encryption |
| `POST` | `/api/asymmetric/decrypt` | Operator / Admin | `{"key_id": int, "wrapped_key": b64, "nonce": b64, "ciphertext": b64}` | Hybrid RSA-OAEP decryption |
| `POST` | `/api/sign` | Operator / Admin | `{"key_id": int, "text": str}` | Generates RSA-PSS digital signature |
| `POST` | `/api/verify` | Open | `{"key_id": int, "text": str, "signature": b64}` | Verifies RSA-PSS digital signature |
| `POST` | `/api/hash` | Open | `{"text": str, "algorithm": "SHA-256"\|"SHA-512"}` | Generates cryptographic hash |
| `POST` | `/api/hash/verify` | Open | `{"text": str, "expected_hash": str, "algorithm": str}` | Constant-time integrity check |
| `POST` | `/api/hash/file` | Open | `multipart/form-data` (`file`, `algorithm`) | Streams and hashes file up to 20 MB |
| `POST` | `/api/hash/avalanche` | Open | `{"input_a": str, "input_b": str, "algorithm": str}` | Bitwise Hamming distance analysis |
| `GET` | `/api/benchmarks/latest` | Open | None | Retrieves latest hardware benchmarks |
| `POST` | `/api/benchmarks/run` | Operator / Admin | None | Executes fresh server CPU benchmark |
| `GET` | `/api/audit` | Open | `limit`, `offset`, `search`, `status`, `action` | Returns filtered audit log entries |
| `GET` | `/api/audit/export` | Operator / Admin | None | Streams audit trail in CSV format |
| `GET` | `/api/stats` | Open | None | Operational telemetry and counts |

---

## 8. Automated Test Suite & Verification

The framework includes a comprehensive automated test suite in `tests/` covering cryptographic correctness, tamper rejection, key lifecycle, authentication, and role enforcement.

### Execute Automated Tests
```powershell
& ".\.venv\Scripts\pytest.exe" "tests" -v
```

### Test Suite Inventory (16 Tests)
1. `test_audit_stats.py::test_audit_logging_and_filtering` — Verifies UUID4 audit log creation, filtering, and CSV export.
2. `test_audit_stats.py::test_stats_telemetry` — Validates real-time dashboard counts and success rate calculation.
3. `test_auth_rbac.py::test_password_hashing` — Tests Scrypt password hashing, salt uniqueness, and constant-time verification.
4. `test_auth_rbac.py::test_auth_login_success` — Tests successful login, session establishment, and CSRF token issuance.
5. `test_auth_rbac.py::test_auth_login_failure` — Tests authentication rejection for invalid passwords.
6. `test_auth_rbac.py::test_auth_me_authenticated` — Validates user profile and role resolution.
7. `test_auth_rbac.py::test_auth_logout` — Confirms session destruction on logout.
8. `test_auth_rbac.py::test_rbac_role_enforcement` — Tests that Viewers are blocked from encrypting (403), Operators are blocked from deleting keys (403), and Administrators have full access.
9. `test_avalanche.py::test_avalanche_analysis_endpoint` — Validates Strict Avalanche Criterion calculation and bit difference mapping.
10. `test_benchmarks.py::test_crypto_benchmarking_endpoints` — Validates CPU benchmark execution across payload sizes.
11. `test_crypto_operations.py::test_aes_gcm_roundtrip_and_tamper_rejection` — Tests AES-GCM round-trip and verifies that bit-flipped ciphertext fails authentication.
12. `test_crypto_operations.py::test_rsa_hybrid_and_signatures` — Tests RSA-OAEP hybrid encryption/decryption, RSA-PSS signing, and tamper rejection.
13. `test_crypto_operations.py::test_hashing_and_integrity` — Tests NIST standard test vectors for SHA-256 ("abc") and constant-time integrity verification.
14. `test_file_crypto.py::test_file_encryption_and_decryption_roundtrip` — Tests binary file encryption to `.enc` and verifies corrupted `.enc` packages are rejected.
15. `test_keys_vault.py::test_aes_key_lifecycle` — Verifies AES generation, encrypted storage, rotation, and deletion.
16. `test_keys_vault.py::test_rsa_key_lifecycle_and_export` — Verifies RSA generation, public PEM export, and zero secret leakage.

---

## 9. Faculty Demonstration Walkthrough

Follow this step-by-step procedure during academic evaluations or project presentations:

### Step 1: System Startup & Architecture Briefing
1. Launch the platform using `start.bat` or `python app.py`.
2. Open `http://127.0.0.1:5000`. Show that the application loads into the **Overview Dashboard** with active telemetry.
3. Navigate to **06 · System Architecture** to walk the evaluator through the 7-stage data pipeline (UI ➔ Flask API ➔ RBAC ➔ Crypto Engine ➔ Key Vault ➔ SQLite ➔ Audit Trail). Click on the nodes to display algorithm standards (NIST SP 800-38D, RFC 8017).

### Step 2: Role-Based Access Control (RBAC) Demonstration
1. Note the active role in the topbar (`Role: Administrator`).
2. Click **Role: Administrator** in the topbar to open the role modal. Click **Auditor (Read-Only)** and click **Authenticate**.
3. The topbar now indicates `Role: Viewer`.
4. Navigate to **01 · Symmetric (AES)** and click **Encrypt Plaintext**. Demonstrate that the operation is blocked with a red toast: *"Access denied. Requires one of roles: Operator, Administrator. Your role is 'Viewer'."*
5. Switch back to **Admin** or **Operator** to restore operational access.

### Step 3: Module 01 — Symmetric Authenticated Encryption (AES-GCM)
1. In **01 · Symmetric (AES)**, select an active AES key.
2. Enter a confidential message (e.g. `"Final Year Project Defense — Classified Document"`) and click **Encrypt Plaintext**.
3. Note the microsecond latency, input size, output size, and the generated JSON payload (`nonce`, `ciphertext`).
4. Click **Decrypt & Authenticate**. Show that the original plaintext is recovered with tag verification confirmed.
5. **Tamper Test:** Alter one character in the ciphertext field in the decrypt box and click **Decrypt & Authenticate**. Demonstrate that decryption fails immediately with: *"Decryption failed: authentication tag mismatch or invalid key."*
6. Switch to the **File Container Encryption** tab. Upload a file, click **Encrypt & Download .enc**, then upload the `.enc` file in the decrypt card and recover the original file.

### Step 4: Module 02 — Asymmetric Hybrid Encryption & RSA-PSS Signatures
1. Navigate to **02 · Asymmetric & Sign**. Select an RSA key pair and encrypt text. Explain that the app uses RSA-OAEP to wrap an ephemeral 256-bit AES content key, allowing unlimited message sizes.
2. Decrypt the message using the private key.
3. Switch to the **RSA-PSS Digital Signatures** tab. Enter a message (e.g. `"Approved by Examination Committee"`) and click **Generate Digital Signature**.
4. Click **Verify Authenticity & Integrity** to show the green `VALID` badge.
5. Alter one character in the message box and verify again. Show that it immediately turns red: `INVALID — Verification failed.`

### Step 5: Module 03 — Strict Avalanche Effect Demonstration
1. Navigate to **03 · Hashing & Avalanche** and switch to the **Strict Avalanche Effect Lab**.
2. Note Input A (`CyberSecurityCapstone2026`). Click **Flip 1 Bit** to perturb the first bit in Input B (`ByberSecurityCapstone2026`).
3. Click **Execute Avalanche Analysis**. Show that flipping a single bit results in **~50% of the output digest bits flipping** (demonstrating the Strict Avalanche Criterion). Point out the 128-cell visual matrix highlighting changed bits in cyan.

### Step 6: Module 04 — Key Lifecycle & Vault Security
1. Navigate to **04 · Key Vault & Storage**. Show the key inventory with unique SHA-256 key fingerprints.
2. Click **Export PEM** on an RSA key pair to demonstrate public key export without leaking the private key.
3. Click **Rotate** on an active key. Explain that the old key transitions to `ROTATED` (retained for decrypting historical records) while a new child key is generated.
4. Click **Delete** on a key to demonstrate the safety confirmation modal explaining data recovery risks.

### Step 7: Module 05 — Hardware Performance Benchmarks
1. Navigate to **05 · Crypto Benchmarks**.
2. Click **⚡ Run Hardware Benchmark**. Show the real CPU measurements populate: AES-GCM throughput across 1 KB to 1 MB blocks (reaching >1,500 MB/s), RSA keygen latency (~17 ms), and RSA-PSS signature verification throughput (~17,000 ops/sec).

### Step 8: Module 07 — Forensic Audit Trail & CSV Export
1. Navigate to **07 · Audit Trail & Logs**.
2. Show that every action just performed (encryption, decryption, signing, verification, login, rotation) has an immutable trace with a UUID4 operation ID and duration.
3. Filter by `SUCCESS` or `FAILURE` to show failed tamper attempts.
4. Click **Export CSV** to download the structured forensic log file.

---

## 10. Database Management & Demo Reset

To prepare a clean database for an exam or demonstration without deleting existing keys or logs, use the safe reset utility:

```powershell
python reset_demo_db.py
```

This utility will:
1. Automatically create a safety backup of your existing database:
   `instance/framework.sqlite3.backup_YYYYMMDD_HHMMSS`
2. Initialize fresh database tables with zero data corruption.
3. Re-seed default accounts (`admin`, `operator`, `auditor`).
4. Generate one sample active AES-256 key and one sample active RSA-2048 key pair.

---

## 11. Security Considerations & Limitations

- **Master Key Security:** The master key is stored in `instance/master.key` with restricted permissions (`0o600`). For enterprise production deployments, this key should be managed by a Hardware Security Module (HSM) or cloud KMS (AWS KMS, Azure Key Vault, HashiCorp Vault).
- **Development Server:** Flask's built-in development server is designed for local demonstration and testing. For production deployments, serve CyberVault using Gunicorn or Waitress behind an Nginx reverse proxy with TLS 1.3 encryption.
- **Side-Channel Mitigations:** Digest comparisons utilize `secrets.compare_digest()` to mitigate timing attacks. However, memory dumps of the host process could expose ephemeral decrypted key material.
- **Nonce Uniqueness:** AES-GCM strictly requires that a nonce is never reused with the same key. CyberVault generates a cryptographically random 96-bit nonce via OS entropy for every encryption.
- **File Upload Boundaries:** File uploads are limited to 20 MB and processed in memory chunks to prevent denial-of-service memory exhaustion.

---

## License

This project is developed for educational and academic research purposes. All components use free, open-source software compliant with standard educational policies.
