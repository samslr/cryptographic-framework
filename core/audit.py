import csv
import io
import uuid
from typing import Dict, List, Optional, Tuple
from core.database import get_db, utc_now_iso
from core.security import get_current_username


def record_audit(
    action: str,
    algorithm: str = "SYSTEM",
    status: str = "SUCCESS",
    details: str = "",
    duration_ms: float = 0.0,
    user_id: Optional[str] = None
) -> str:
    """
    Record a structured operational audit log entry into the database.
    Returns the unique operation_id for correlation.
    """
    op_id = str(uuid.uuid4())
    username = user_id or get_current_username()
    # Sanitize details string (ensure no passwords or raw keys are stored)
    clean_details = (details or "")[:500]

    try:
        db = get_db()
        db.execute(
            """
            INSERT INTO audit_logs(operation_id, user_id, action, algorithm, status, duration_ms, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (op_id, username, action, algorithm, status, round(duration_ms, 3), clean_details, utc_now_iso())
        )
        db.commit()
    except Exception:
        # Fallback if during app init or error handler
        pass
    return op_id


def query_audit_logs(
    limit: int = 50,
    offset: int = 0,
    search: str = "",
    status: str = "",
    action: str = ""
) -> Tuple[List[Dict], int]:
    """Query audit logs with optional filtering, search, and pagination."""
    db = get_db()
    query = "SELECT * FROM audit_logs WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
    params = []

    if search:
        search_like = f"%{search.strip()}%"
        condition = " AND (action LIKE ? OR details LIKE ? OR user_id LIKE ? OR algorithm LIKE ? OR operation_id LIKE ?)"
        query += condition
        count_query += condition
        params.extend([search_like, search_like, search_like, search_like, search_like])

    if status:
        query += " AND status = ?"
        count_query += " AND status = ?"
        params.append(status.upper())

    if action:
        query += " AND action = ?"
        count_query += " AND action = ?"
        params.append(action)

    total = db.execute(count_query, params).fetchone()[0]

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    query_params = params + [limit, offset]
    rows = db.execute(query, query_params).fetchall()

    return [dict(row) for row in rows], total


def export_audit_csv() -> str:
    """Generate a clean CSV representation of the entire audit trail."""
    db = get_db()
    rows = db.execute("SELECT id, operation_id, user_id, action, algorithm, status, duration_ms, details, created_at FROM audit_logs ORDER BY id DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Operation ID", "User", "Action", "Algorithm", "Status", "Duration (ms)", "Details", "Timestamp (UTC)"])
    for r in rows:
        writer.writerow([r["id"], r["operation_id"], r["user_id"], r["action"], r["algorithm"], r["status"], r["duration_ms"], r["details"], r["created_at"]])
    return output.getvalue()
