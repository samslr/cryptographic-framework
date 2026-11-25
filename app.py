import base64
import hashlib
import io
import os
import secrets
import time
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, g, jsonify, render_template, request, send_file, session
from werkzeug.exceptions import BadRequest
from werkzeug.utils import secure_filename

from core.audit import export_audit_csv, query_audit_logs, record_audit
from core.crypto_benchmarks import get_latest_benchmark, run_comprehensive_benchmark
from core.crypto_integrity import compute_avalanche, flip_one_bit
from core.crypto_symmetric import decrypt_file_payload, encrypt_file_payload
from core.crypto_vault import (
    VAULT,
    compute_fingerprint,
    decrypt_secret,
    encrypt_secret,
)
from core.database import close_db, get_db, init_and_migrate_db, utc_now_iso
from core.security import (
    AUTH_RATE_LIMITER,
    CRYPTO_RATE_LIMITER,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    generate_csrf_token,
    get_current_role,
    get_current_user,
    get_current_username,
    require_auth,
    require_role,
    validate_csrf,
    verify_password,
)

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
INSTANCE.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB max file upload
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Auto-close database connection per request
app.teardown_appcontext(close_db)


def b64e(data: bytes) -> str:
    """Encode bytes to ASCII Base64 string."""
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    """Decode ASCII Base64 string to bytes with validation."""
    if not isinstance(value, str):
        raise ValueError("Payload must be a valid Base64 string.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid Base64 payload.") from exc


def api_errors(fn):
    """Centralized exception handling decorator returning consistent JSON responses."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        except BadRequest as exc:
            return jsonify(error=exc.description or "Malformed request payload.", code="BAD_REQUEST"), 400
        except Exception as exc:
            app.logger.exception("Cryptographic operation failed unexpectedly")
            return jsonify(error="An internal error occurred. Operation was aborted safely.", code="INTERNAL_ERROR"), 500
    return wrapper


def get_key(key_id: int, expected_type: str = None, allow_inactive: bool = False):
    """Retrieve key record from database and validate its status and type."""
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE id = ?", (key_id,)).fetchone()
    if not row:
        raise ValueError(f"Key #{key_id} not found in inventory.")
    if row["status"] != "ACTIVE" and not allow_inactive:
        raise ValueError(f"Key #{key_id} is {row['status']} and cannot be used for new operations.")
    if expected_type and row["key_type"] != expected_type:
        raise ValueError(f"Selected key #{key_id} is not a {expected_type} key.")

    # Increment key usage counter
    try:
        db.execute("UPDATE keys SET usage_count = usage_count + 1 WHERE id = ?", (key_id,))
        db.commit()
    except Exception:
        pass

    return row


def secret_for(row) -> bytes:
    """Decrypt the stored private key material using the master vault."""
    if not row["secret_enc"]:
        raise ValueError("This key entry does not contain private key material.")
    return decrypt_secret(row["secret_enc"])


# =====================================================================
# SYSTEM & AUTHENTICATION ENDPOINTS
# =====================================================================

@app.before_request
def check_rate_limits():
    """Apply rate limiting per client IP."""
    if app.config.get("TESTING"):
        return

    client_ip = request.remote_addr or "127.0.0.1"
    if request.path.startswith("/api/auth/login"):
        if not AUTH_RATE_LIMITER.is_allowed(client_ip):
            return jsonify(error="Too many authentication attempts. Please wait 1 minute.", code="RATE_LIMITED"), 429
    elif request.path.startswith("/api/") and request.method in ("POST", "DELETE"):
        if not CRYPTO_RATE_LIMITER.is_allowed(client_ip):
            return jsonify(error="Rate limit exceeded for cryptographic operations. Please slow down.", code="RATE_LIMITED"), 429


@app.get("/")
def index():
    """Serve the single-page application dashboard."""
    # Seed default session as Administrator if not logged in for instant demonstration
    if "user" not in session:
        session["user"] = {"id": 1, "username": "admin", "role": ROLE_ADMIN}
    csrf_token = generate_csrf_token()
    return render_template("index.html", csrf_token=csrf_token)


@app.get("/api/health")
def health():
    """System health check endpoint."""
    return jsonify(
        status="ok",
        service="Modular Cryptographic Framework",
        version="2.0.0",
        timestamp=utc_now_iso()
    )


@app.post("/api/auth/login")
@api_errors
def login():
    """Authenticate user and establish session with role assignment."""
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        raise ValueError("Username and password are required.")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        record_audit("USER_LOGIN_FAILED", "SECURITY", "FAILURE", f"Failed login attempt for username: {username}")
        return jsonify(error="Invalid username or password.", code="INVALID_CREDENTIALS"), 401

    # Set session state
    session.clear()
    session["user"] = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }
    csrf_token = generate_csrf_token()

    # Update last login timestamp
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (utc_now_iso(), user["id"]))
    db.commit()

    record_audit("USER_LOGIN", "SECURITY", "SUCCESS", f"User {username} authenticated successfully with role {user['role']}")

    return jsonify(
        message=f"Welcome, {user['username']}.",
        user={"id": user["id"], "username": user["username"], "role": user["role"]},
        csrf_token=csrf_token
    )


@app.post("/api/auth/logout")
def logout():
    """Terminate active user session."""
    username = get_current_username()
    session.clear()
    record_audit("USER_LOGOUT", "SECURITY", "SUCCESS", f"User {username} logged out.")
    return jsonify(message="Session terminated successfully.")


@app.get("/api/auth/me")
def current_user_info():
    """Return active session user identity, role, and CSRF token."""
    user = get_current_user()
    csrf_token = generate_csrf_token()
    if user:
        return jsonify(
            authenticated=True,
            user=user,
            csrf_token=csrf_token
        )
    return jsonify(
        authenticated=False,
        user={"username": "guest", "role": ROLE_VIEWER},
        csrf_token=csrf_token
    )


# =====================================================================
# MODULE 4: KEY MANAGEMENT & STORAGE
# =====================================================================

@app.get("/api/keys")
@api_errors
def list_keys():
    """Return key inventory metadata (fingerprints, algorithms, lifecycle status)."""
    db = get_db()
    rows = db.execute("""
        SELECT id, name, key_type, algorithm, fingerprint, status, usage_count, created_by, created_at, rotated_from
        FROM keys ORDER BY id DESC
    """).fetchall()
    return jsonify(keys=[dict(row) for row in rows])


@app.post("/api/keys/aes")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def create_aes_key():
    """Generate a 256-bit AES-GCM key, encrypt it with the master vault, and store."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "AES-256 Key").strip()[:80]
    raw_key = AESGCM.generate_key(bit_length=256)
    fingerprint = compute_fingerprint(raw_key)

    db = get_db()
    cur = db.execute("""
        INSERT INTO keys(name, key_type, algorithm, secret_enc, fingerprint, created_by, created_at)
        VALUES (?, 'SYMMETRIC', 'AES-256-GCM', ?, ?, ?, ?)
    """, (name, encrypt_secret(raw_key), fingerprint, get_current_username(), utc_now_iso()))
    db.commit()
    key_id = cur.lastrowid
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("KEY_CREATED", "AES-256-GCM", "SUCCESS", f"AES-256-GCM key #{key_id} ({fingerprint}) created", duration_ms)
    return jsonify(
        message="AES-256-GCM key generated successfully.",
        key_id=key_id,
        fingerprint=fingerprint,
        duration_ms=round(duration_ms, 2)
    ), 201


@app.post("/api/keys/rsa")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def create_rsa_key():
    """Generate a 2048-bit RSA key pair, store encrypted private key and plaintext public PEM."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "RSA-2048 Key Pair").strip()[:80]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem_str = public_pem_bytes.decode("ascii")
    fingerprint = compute_fingerprint(public_pem_bytes)

    db = get_db()
    cur = db.execute("""
        INSERT INTO keys(name, key_type, algorithm, secret_enc, public_pem, fingerprint, created_by, created_at)
        VALUES (?, 'ASYMMETRIC', 'RSA-2048-OAEP/PSS', ?, ?, ?, ?, ?)
    """, (name, encrypt_secret(private_pem), public_pem_str, fingerprint, get_current_username(), utc_now_iso()))
    db.commit()
    key_id = cur.lastrowid
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("KEY_CREATED", "RSA-2048", "SUCCESS", f"RSA-2048 key pair #{key_id} ({fingerprint}) created", duration_ms)
    return jsonify(
        message="RSA-2048 key pair generated successfully.",
        key_id=key_id,
        fingerprint=fingerprint,
        duration_ms=round(duration_ms, 2)
    ), 201


@app.post("/api/keys/<int:key_id>/rotate")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def rotate_key(key_id):
    """Rotate an existing cryptographic key, marking the old key as ROTATED."""
    t0 = time.perf_counter()
    old = get_key(key_id)
    db = get_db()
    current_user = get_current_username()

    if old["key_type"] == "SYMMETRIC":
        raw_key = AESGCM.generate_key(bit_length=256)
        fingerprint = compute_fingerprint(raw_key)
        cur = db.execute("""
            INSERT INTO keys(name, key_type, algorithm, secret_enc, fingerprint, created_by, created_at, rotated_from)
            VALUES (?, 'SYMMETRIC', 'AES-256-GCM', ?, ?, ?, ?, ?)
        """, (f"{old['name']} (rotated)", encrypt_secret(raw_key), fingerprint, current_user, utc_now_iso(), key_id))
        new_id = cur.lastrowid
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        public_pem_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_pem_str = public_pem_bytes.decode("ascii")
        fingerprint = compute_fingerprint(public_pem_bytes)
        cur = db.execute("""
            INSERT INTO keys(name, key_type, algorithm, secret_enc, public_pem, fingerprint, created_by, created_at, rotated_from)
            VALUES (?, 'ASYMMETRIC', 'RSA-2048-OAEP/PSS', ?, ?, ?, ?, ?, ?)
        """, (f"{old['name']} (rotated)", encrypt_secret(private_pem), public_pem_str, fingerprint, current_user, utc_now_iso(), key_id))
        new_id = cur.lastrowid

    # Mark the previous key as ROTATED
    db.execute("UPDATE keys SET status = 'ROTATED' WHERE id = ?", (key_id,))
    db.commit()
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("KEY_ROTATED", old["algorithm"], "SUCCESS", f"Key #{key_id} rotated to new Key #{new_id} ({fingerprint})", duration_ms)
    return jsonify(
        message="Key rotated. Old key remains available for historical decryption.",
        new_key_id=new_id,
        fingerprint=fingerprint,
        duration_ms=round(duration_ms, 2)
    )


@app.delete("/api/keys/<int:key_id>")
@api_errors
@require_role(ROLE_ADMIN)
def delete_key(key_id):
    """Securely purge a key record from the database inventory."""
    t0 = time.perf_counter()
    db = get_db()
    row = db.execute("SELECT id, name, key_type, algorithm, fingerprint FROM keys WHERE id = ?", (key_id,)).fetchone()
    if not row:
        raise ValueError(f"Key #{key_id} not found.")

    db.execute("DELETE FROM keys WHERE id = ?", (key_id,))
    db.commit()
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("KEY_DELETED", row["algorithm"], "SUCCESS", f"Key #{key_id} ({row['name']}, {row['fingerprint']}) permanently deleted", duration_ms)
    return jsonify(message=f"Key #{key_id} deleted successfully.")


@app.get("/api/keys/<int:key_id>/public")
@api_errors
def export_public_key(key_id):
    """Export public key PEM format for asymmetric key pairs."""
    row = get_key(key_id, expected_type="ASYMMETRIC", allow_inactive=True)
    if not row["public_pem"]:
        raise ValueError("No public key found for this record.")
    return jsonify(
        key_id=row["id"],
        name=row["name"],
        algorithm=row["algorithm"],
        fingerprint=row["fingerprint"],
        public_pem=row["public_pem"]
    )


# =====================================================================
# MODULE 1: SYMMETRIC ENCRYPTION (AES-256-GCM - TEXT & FILES)
# =====================================================================

@app.post("/api/symmetric/encrypt")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def symmetric_encrypt():
    """AES-256-GCM authenticated encryption for text payloads."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    text_content = data.get("text")
    if not text_content:
        raise ValueError("Please provide plaintext to encrypt.")

    key_id_raw = data.get("key_id")
    if not key_id_raw:
        raise ValueError("Please select an active symmetric key from the dropdown.")
    key_id = int(key_id_raw)
    row = get_key(key_id, expected_type="SYMMETRIC")
    key = secret_for(row)

    plaintext_bytes = text_content.encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext_bytes, None)
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("AES_ENCRYPT", "AES-256-GCM", "SUCCESS", f"Encrypted {len(plaintext_bytes)} bytes with Key #{row['id']}", duration_ms)

    return jsonify(
        algorithm="AES-256-GCM",
        key_id=row["id"],
        key_name=row["name"],
        nonce=b64e(nonce),
        ciphertext=b64e(ciphertext),
        input_bytes=len(plaintext_bytes),
        output_bytes=len(ciphertext),
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/symmetric/decrypt")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def symmetric_decrypt():
    """AES-256-GCM authenticated decryption with tag validation."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    key_id = int(data.get("key_id", 0))
    row = get_key(key_id, expected_type="SYMMETRIC", allow_inactive=True)
    key = secret_for(row)

    nonce = b64d(data.get("nonce", ""))
    ciphertext = b64d(data.get("ciphertext", ""))

    if len(nonce) != 12:
        raise ValueError("Invalid AES-GCM nonce: must be exactly 12 bytes.")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        duration_ms = (time.perf_counter() - t0) * 1000
        record_audit("AES_DECRYPT", "AES-256-GCM", "FAILURE", f"Decryption failed: tampered ciphertext or wrong Key #{row['id']}", duration_ms)
        raise ValueError("Decryption failed: authentication tag mismatch or invalid key. Ciphertext may have been modified.")

    duration_ms = (time.perf_counter() - t0) * 1000
    record_audit("AES_DECRYPT", "AES-256-GCM", "SUCCESS", f"Decrypted {len(plaintext)} bytes with Key #{row['id']}", duration_ms)

    return jsonify(
        plaintext=plaintext.decode("utf-8"),
        message="Authenticated decryption successful. Data integrity confirmed.",
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/symmetric/encrypt-file")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def symmetric_encrypt_file():
    """Encrypt uploaded file with AES-256-GCM and return downloadable .enc container."""
    t0 = time.perf_counter()
    uploaded = request.files.get("file")
    key_id = request.form.get("key_id")

    if not uploaded or not uploaded.filename:
        raise ValueError("Please select a file to encrypt.")
    if not key_id:
        raise ValueError("Please select a symmetric key.")

    row = get_key(int(key_id), expected_type="SYMMETRIC")
    key = secret_for(row)

    file_bytes = uploaded.read()
    if not file_bytes:
        raise ValueError("Cannot encrypt an empty file.")

    safe_name = secure_filename(uploaded.filename) or "document"
    encrypted_payload = encrypt_file_payload(file_bytes, key)
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("AES_FILE_ENCRYPT", "AES-256-GCM", "SUCCESS", f"Encrypted file '{safe_name}' ({len(file_bytes)} bytes) with Key #{row['id']}", duration_ms)

    return send_file(
        io.BytesIO(encrypted_payload),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{safe_name}.enc"
    )


@app.post("/api/symmetric/decrypt-file")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def symmetric_decrypt_file():
    """Decrypt uploaded .enc file container with AES-256-GCM."""
    t0 = time.perf_counter()
    uploaded = request.files.get("file")
    key_id = request.form.get("key_id")

    if not uploaded or not uploaded.filename:
        raise ValueError("Please select an encrypted (.enc) file to decrypt.")
    if not key_id:
        raise ValueError("Please select a symmetric key.")

    row = get_key(int(key_id), expected_type="SYMMETRIC", allow_inactive=True)
    key = secret_for(row)

    encrypted_bytes = uploaded.read()
    if len(encrypted_bytes) < 28:
        raise ValueError("Uploaded file is too small to be a valid encrypted container.")

    try:
        decrypted_bytes = decrypt_file_payload(encrypted_bytes, key)
    except Exception:
        duration_ms = (time.perf_counter() - t0) * 1000
        record_audit("AES_FILE_DECRYPT", "AES-256-GCM", "FAILURE", f"File decryption failed for Key #{row['id']}", duration_ms)
        raise ValueError("File decryption failed: authentication tag mismatch or invalid key.")

    duration_ms = (time.perf_counter() - t0) * 1000
    safe_name = secure_filename(uploaded.filename) or "decrypted_file.bin"
    output_name = safe_name[:-4] if safe_name.endswith(".enc") else f"recovered_{safe_name}"

    record_audit("AES_FILE_DECRYPT", "AES-256-GCM", "SUCCESS", f"Decrypted file '{safe_name}' ({len(decrypted_bytes)} bytes) with Key #{row['id']}", duration_ms)

    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=output_name
    )


# =====================================================================
# MODULE 2: ASYMMETRIC ENCRYPTION & DIGITAL SIGNATURES
# =====================================================================

@app.post("/api/asymmetric/encrypt")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def asymmetric_encrypt():
    """RSA-2048 OAEP + AES-256-GCM hybrid encryption for text."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    text_content = data.get("text")
    if not text_content:
        raise ValueError("Please provide plaintext to encrypt.")

    key_id_raw = data.get("key_id")
    if not key_id_raw:
        raise ValueError("Please select an active RSA key pair from the dropdown.")
    key_id = int(key_id_raw)
    row = get_key(key_id, expected_type="ASYMMETRIC")
    public_key = serialization.load_pem_public_key(row["public_pem"].encode("ascii"))

    content_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    plaintext_bytes = text_content.encode("utf-8")
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext_bytes, None)

    wrapped_key = public_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("RSA_HYBRID_ENCRYPT", "RSA-2048-OAEP + AES-GCM", "SUCCESS", f"Hybrid encrypted {len(plaintext_bytes)} bytes with RSA Key #{row['id']}", duration_ms)

    return jsonify(
        algorithm="RSA-2048-OAEP + AES-256-GCM",
        key_id=row["id"],
        wrapped_key=b64e(wrapped_key),
        nonce=b64e(nonce),
        ciphertext=b64e(ciphertext),
        input_bytes=len(plaintext_bytes),
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/asymmetric/decrypt")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def asymmetric_decrypt():
    """RSA-2048 OAEP + AES-256-GCM hybrid decryption."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    key_id = int(data.get("key_id", 0))
    row = get_key(key_id, expected_type="ASYMMETRIC", allow_inactive=True)
    private_key = serialization.load_pem_private_key(secret_for(row), password=None)

    wrapped_key = b64d(data.get("wrapped_key", ""))
    nonce = b64d(data.get("nonce", ""))
    ciphertext = b64d(data.get("ciphertext", ""))

    try:
        content_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintext = AESGCM(content_key).decrypt(nonce, ciphertext, None)
    except Exception:
        duration_ms = (time.perf_counter() - t0) * 1000
        record_audit("RSA_HYBRID_DECRYPT", "RSA-2048-OAEP", "FAILURE", f"Hybrid decryption failed with RSA Key #{row['id']}", duration_ms)
        raise ValueError("Hybrid decryption failed: invalid wrapped key, wrong private key, or modified ciphertext.")

    duration_ms = (time.perf_counter() - t0) * 1000
    record_audit("RSA_HYBRID_DECRYPT", "RSA-2048-OAEP + AES-GCM", "SUCCESS", f"Hybrid decrypted {len(plaintext)} bytes with RSA Key #{row['id']}", duration_ms)

    return jsonify(
        plaintext=plaintext.decode("utf-8"),
        message="Hybrid decryption successful.",
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/sign")
@api_errors
@require_role(ROLE_OPERATOR, ROLE_ADMIN)
def sign_message():
    """RSA-PSS digital signature generation with SHA-256."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    message = (data.get("text") or "").encode("utf-8")
    if not message:
        raise ValueError("Please provide a message to sign.")

    key_id_raw = data.get("key_id")
    if not key_id_raw:
        raise ValueError("Please select a signing RSA key pair from the dropdown.")
    key_id = int(key_id_raw)
    row = get_key(key_id, expected_type="ASYMMETRIC")
    private_key = serialization.load_pem_private_key(secret_for(row), password=None)

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("DIGITAL_SIGN", "RSA-PSS-SHA256", "SUCCESS", f"Generated digital signature for message ({len(message)} bytes) using Key #{row['id']}", duration_ms)

    return jsonify(
        algorithm="RSA-PSS with SHA-256",
        key_id=row["id"],
        signature=b64e(signature),
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/verify")
@api_errors
def verify_signature():
    """RSA-PSS digital signature verification."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    message = (data.get("text") or "").encode("utf-8")
    key_id_raw = data.get("key_id")
    if not key_id_raw:
        raise ValueError("Please select a verification RSA key pair from the dropdown.")
    key_id = int(key_id_raw)
    row = get_key(key_id, expected_type="ASYMMETRIC", allow_inactive=True)
    public_key = serialization.load_pem_public_key(row["public_pem"].encode("ascii"))
    signature = b64d(data.get("signature", ""))

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        valid = True
    except Exception:
        valid = False

    duration_ms = (time.perf_counter() - t0) * 1000
    status_str = "SUCCESS" if valid else "FAILURE"
    record_audit("SIGNATURE_VERIFY", "RSA-PSS-SHA256", status_str, f"Signature verification result for Key #{row['id']}: {'VALID' if valid else 'INVALID'}", duration_ms)

    return jsonify(
        valid=valid,
        result="VALID — Digital signature verified successfully. Sender authenticity & data integrity confirmed." if valid else "INVALID — Verification failed. The message or signature has been modified.",
        duration_ms=round(duration_ms, 3)
    )


# =====================================================================
# MODULE 3: HASHING, INTEGRITY & AVALANCHE EFFECT
# =====================================================================

@app.post("/api/hash")
@api_errors
def hash_text():
    """Compute cryptographic hash digest for text (SHA-256 or SHA-512)."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    text_content = data.get("text")
    if text_content is None:
        raise ValueError("Please provide text to hash.")

    algorithm = (data.get("algorithm") or "SHA-256").upper().replace("_", "-")
    if algorithm not in ("SHA-256", "SHA-512"):
        raise ValueError("Unsupported algorithm. Choose SHA-256 or SHA-512.")

    digest_name = "sha256" if algorithm == "SHA-256" else "sha512"
    digest = hashlib.new(digest_name, text_content.encode("utf-8")).hexdigest()
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("HASH_GENERATE", algorithm, "SUCCESS", f"{algorithm} hash generated for text payload", duration_ms)

    return jsonify(
        algorithm=algorithm,
        hash=digest,
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/hash/verify")
@api_errors
def verify_hash():
    """Verify text integrity by comparing computed hash with expected hash in constant time."""
    t0 = time.perf_counter()
    data = request.get_json(force=True) or {}
    text_content = data.get("text")
    expected_hash = (data.get("expected_hash") or "").strip().lower()
    algorithm = (data.get("algorithm") or "SHA-256").upper().replace("_", "-")

    if text_content is None or not expected_hash:
        raise ValueError("Provide both the input text and the expected hash value.")
    if algorithm not in ("SHA-256", "SHA-512"):
        raise ValueError("Choose SHA-256 or SHA-512.")

    digest_name = "sha256" if algorithm == "SHA-256" else "sha512"
    actual_hash = hashlib.new(digest_name, text_content.encode("utf-8")).hexdigest()
    valid = secrets.compare_digest(actual_hash, expected_hash)
    duration_ms = (time.perf_counter() - t0) * 1000

    record_audit("HASH_VERIFY", algorithm, "SUCCESS" if valid else "FAILURE", f"{algorithm} integrity check: {'MATCHED' if valid else 'TAMPERED'}", duration_ms)

    return jsonify(
        valid=valid,
        actual_hash=actual_hash,
        result="INTEGRITY VERIFIED — Data is authentic and unmodified." if valid else "INTEGRITY FAILED — Data tampering or corruption detected.",
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/hash/file")
@api_errors
def hash_file():
    """Streamed cryptographic hashing for uploaded files up to 20 MB."""
    t0 = time.perf_counter()
    uploaded = request.files.get("file")
    algorithm = (request.form.get("algorithm") or "SHA-256").upper()

    if not uploaded or not uploaded.filename:
        raise ValueError("Please select a file to hash.")
    if algorithm not in ("SHA-256", "SHA-512"):
        raise ValueError("Choose SHA-256 or SHA-512.")

    safe_name = secure_filename(uploaded.filename) or "uploaded-file"
    digest_name = "sha256" if algorithm == "SHA-256" else "sha512"
    hasher = hashlib.new(digest_name)
    size = 0

    while True:
        chunk = uploaded.stream.read(1024 * 1024)  # 1 MB chunk
        if not chunk:
            break
        size += len(chunk)
        hasher.update(chunk)

    duration_ms = (time.perf_counter() - t0) * 1000
    digest_str = hasher.hexdigest()

    record_audit("FILE_HASH", algorithm, "SUCCESS", f"{algorithm} computed for '{safe_name}' ({size} bytes)", duration_ms)

    return jsonify(
        filename=safe_name,
        size_bytes=size,
        algorithm=algorithm,
        hash=digest_str,
        duration_ms=round(duration_ms, 3)
    )


@app.post("/api/hash/avalanche")
@api_errors
def avalanche_analysis():
    """Educational endpoint demonstrating strict avalanche effect by comparing bit difference."""
    data = request.get_json(force=True) or {}
    input_a = data.get("input_a") or "CryptographicSecurity2026"
    input_b = data.get("input_b")
    algorithm = data.get("algorithm") or "SHA-256"

    # If input_b not provided or user requested 1-bit perturbation
    if input_b is None:
        input_b = flip_one_bit(input_a)

    result = compute_avalanche(input_a, input_b, algorithm)
    return jsonify(result)


# =====================================================================
# BENCHMARKING & PERFORMANCE ANALYTICS
# =====================================================================

@app.get("/api/benchmarks/latest")
@api_errors
def get_benchmarks():
    """Return the most recent cryptographic benchmark metrics."""
    return jsonify(get_latest_benchmark())


@app.post("/api/benchmarks/run")
@api_errors
def run_benchmarks():
    """Execute fresh hardware performance benchmark on the server."""
    t0 = time.perf_counter()
    bench_data = run_comprehensive_benchmark()
    duration_ms = (time.perf_counter() - t0) * 1000
    record_audit("BENCHMARK_EXECUTE", "MULTI-ALGORITHM", "SUCCESS", "Executed comprehensive hardware performance benchmark", duration_ms)
    return jsonify(bench_data)


# =====================================================================
# AUDIT & SYSTEM STATISTICS ENDPOINTS
# =====================================================================

@app.get("/api/audit")
@api_errors
def get_audit():
    """Query recent audit events with optional search, status filtering, and pagination."""
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = max(int(request.args.get("offset", 0)), 0)
    search = request.args.get("search", "")
    status = request.args.get("status", "")
    action = request.args.get("action", "")

    logs, total = query_audit_logs(limit=limit, offset=offset, search=search, status=status, action=action)
    return jsonify(logs=logs, total=total, limit=limit, offset=offset)


@app.get("/api/audit/export")
def export_audit():
    """Export the entire audit trail in CSV format."""
    csv_data = export_audit_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_trail_{int(time.time())}.csv"}
    )


@app.get("/api/stats")
@api_errors
def stats():
    """Return dashboard telemetry: active keys, total operations, success rate."""
    db = get_db()
    active_keys = db.execute("SELECT COUNT(*) FROM keys WHERE status = 'ACTIVE'").fetchone()[0]
    retired_keys = db.execute("SELECT COUNT(*) FROM keys WHERE status != 'ACTIVE'").fetchone()[0]
    total_ops = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    success_ops = db.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'SUCCESS'").fetchone()[0]
    failed_ops = db.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'FAILURE'").fetchone()[0]
    verification_checks = db.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%VERIFY%'").fetchone()[0]
    signatures = db.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'DIGITAL_SIGN'").fetchone()[0]
    encryptions = db.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%ENCRYPT%'").fetchone()[0]
    decryptions = db.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%DECRYPT%'").fetchone()[0]

    success_rate = round((success_ops / total_ops * 100), 1) if total_ops > 0 else 100.0

    return jsonify(
        active_keys=active_keys,
        retired_keys=retired_keys,
        operations=total_ops,
        successful_operations=success_ops,
        failed_operations=failed_ops,
        success_rate=success_rate,
        verification_checks=verification_checks,
        signatures_count=signatures,
        encryptions_count=encryptions,
        decryptions_count=decryptions
    )


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Uploaded file exceeds the maximum 20 MB size limit.", code="FILE_TOO_LARGE"), 413


# Initialize database schema and perform migrations
init_and_migrate_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
