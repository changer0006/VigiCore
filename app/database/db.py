
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "scan_history.db"
)


@contextmanager
def get_db_connection(db_path=DEFAULT_DB_PATH):
    """Context manager ensuring connection is always committed and closed cleanly."""
    conn = sqlite3.connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database(db_path=DEFAULT_DB_PATH):
    """Create the scan-history and assets tables if they do not exist."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with get_db_connection(path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                scan_status TEXT,
                device_type TEXT,
                vendor TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                result_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_target
            ON scans(target)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                device_category TEXT DEFAULT 'Unknown',
                model TEXT,
                confidence_level TEXT DEFAULT 'Low',
                confidence_score INTEGER DEFAULT 0,
                first_discovered TEXT NOT NULL,
                last_discovered TEXT NOT NULL,
                last_scanned TEXT,
                last_scan_id INTEGER,
                last_identified TEXT,
                status TEXT DEFAULT 'online',
                manual_override_category TEXT,
                open_ports_json TEXT,
                evidence_json TEXT,
                inconclusive_signals_json TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'INFO',
                FOREIGN KEY (last_scan_id) REFERENCES scans(id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_ip
            ON assets(ip)
        """)

        # Migration safety for existing assets tables
        cursor = connection.execute("PRAGMA table_info(assets)")
        existing_cols = {col_info[1] for col_info in cursor.fetchall()}
        migration_cols = [
            ("model", "TEXT"),
            ("evidence_json", "TEXT"),
            ("inconclusive_signals_json", "TEXT"),
            ("last_identified", "TEXT")
        ]
        for col_name, col_type in migration_cols:
            if col_name not in existing_cols:
                connection.execute(f"ALTER TABLE assets ADD COLUMN {col_name} {col_type}")

        # Dedicated customer PDF reports table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                scan_id INTEGER,
                target TEXT NOT NULL,
                customer_name TEXT,
                organization_name TEXT,
                assessment_scope TEXT,
                assessor_name TEXT,
                notes TEXT,
                generated_at TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'INFO',
                findings_count INTEGER DEFAULT 0,
                pdf_path TEXT NOT NULL,
                json_path TEXT,
                file_size_bytes INTEGER DEFAULT 0,
                summary_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_report_id
            ON reports(report_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_scan_id
            ON reports(scan_id)
        """)


def check_db_connectivity(db_path=DEFAULT_DB_PATH) -> dict:
    """Verify SQLite database connectivity and return metadata."""
    try:
        initialize_database(db_path)
        with get_db_connection(db_path) as connection:
            scans_count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            assets_count = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        return {
            "connected": True,
            "path": str(db_path),
            "scans_count": scans_count,
            "assets_count": assets_count
        }
    except Exception as e:
        return {
            "connected": False,
            "path": str(db_path),
            "error": str(e),
            "scans_count": 0,
            "assets_count": 0
        }


def _row_to_asset(row: sqlite3.Row) -> dict:
    """Format an SQLite row into an asset dict."""
    d = dict(row)
    ports = []
    if d.get("open_ports_json"):
        try:
            ports = json.loads(d["open_ports_json"])
        except Exception:
            ports = []
    d["open_ports"] = ports
    d["effective_category"] = d.get("manual_override_category") or d.get("device_category") or "Unknown"
    d["device_type"] = d["effective_category"]

    evidence = []
    if d.get("evidence_json"):
        try:
            evidence = json.loads(d["evidence_json"])
        except Exception:
            evidence = []
    d["evidence"] = evidence

    inconclusive = []
    if d.get("inconclusive_signals_json"):
        try:
            inconclusive = json.loads(d["inconclusive_signals_json"])
        except Exception:
            inconclusive = []
    d["inconclusive_signals"] = inconclusive
    d["model"] = d.get("model")
    d["last_identified"] = d.get("last_identified")

    return d


def upsert_asset(asset: dict, db_path=DEFAULT_DB_PATH) -> int:
    """Insert or update a network asset record by IP address."""
    initialize_database(db_path)
    ip = asset.get("ip")
    if not ip:
        raise ValueError("Asset 'ip' is required")

    now_iso = datetime.now(timezone.utc).isoformat()
    mac = asset.get("mac")
    vendor = asset.get("vendor")
    hostname = asset.get("hostname")
    device_category = asset.get("device_category") or asset.get("device_type") or "Unknown"
    model = asset.get("model")
    confidence_level = asset.get("confidence_level", "Low")
    confidence_score = int(asset.get("confidence_score") or asset.get("confidence") or 0)
    status = asset.get("status", "online")
    manual_override = asset.get("manual_override_category")
    last_scanned = asset.get("last_scanned")
    last_scan_id = asset.get("last_scan_id")
    last_identified = asset.get("last_identified")
    risk_score = int(asset.get("risk_score", 0))
    risk_level = asset.get("risk_level", "INFO")

    open_ports = asset.get("open_ports")
    open_ports_json = None
    if open_ports is not None:
        open_ports_json = json.dumps(open_ports)
    elif "open_ports_json" in asset:
        open_ports_json = asset["open_ports_json"]

    evidence = asset.get("evidence")
    evidence_json = json.dumps(evidence) if isinstance(evidence, list) else asset.get("evidence_json")

    inconclusive = asset.get("inconclusive_signals")
    inconclusive_json = json.dumps(inconclusive) if isinstance(inconclusive, list) else asset.get("inconclusive_signals_json")

    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        existing = connection.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()

        if existing:
            asset_id = existing["id"]
            new_mac = mac if (mac and mac != "Unknown") else existing["mac"]
            new_vendor = vendor if (vendor and vendor != "Unknown") else existing["vendor"]
            new_hostname = hostname if hostname else existing["hostname"]
            new_category = device_category if (device_category and device_category != "Unknown") else existing["device_category"]
            new_model = model if model else existing["model"]
            new_conf_level = confidence_level if confidence_level != "Low" else existing["confidence_level"]
            new_conf_score = max(confidence_score, existing["confidence_score"] or 0)
            new_status = status or existing["status"]
            new_override = manual_override if manual_override is not None else existing["manual_override_category"]
            new_last_scanned = last_scanned or existing["last_scanned"]
            new_last_scan_id = last_scan_id or existing["last_scan_id"]
            new_last_identified = last_identified or existing["last_identified"]
            new_ports_json = open_ports_json if open_ports_json is not None else existing["open_ports_json"]
            new_evidence_json = evidence_json if evidence_json is not None else existing["evidence_json"]
            new_inconclusive_json = inconclusive_json if inconclusive_json is not None else existing["inconclusive_signals_json"]
            new_risk_score = risk_score if risk_score > 0 else (existing["risk_score"] or 0)
            new_risk_level = risk_level if risk_level != "INFO" else (existing["risk_level"] or "INFO")

            connection.execute("""
                UPDATE assets SET
                    mac = ?,
                    vendor = ?,
                    hostname = ?,
                    device_category = ?,
                    model = ?,
                    confidence_level = ?,
                    confidence_score = ?,
                    last_discovered = ?,
                    last_scanned = ?,
                    last_scan_id = ?,
                    last_identified = ?,
                    status = ?,
                    manual_override_category = ?,
                    open_ports_json = ?,
                    evidence_json = ?,
                    inconclusive_signals_json = ?,
                    risk_score = ?,
                    risk_level = ?
                WHERE id = ?
            """, (
                new_mac,
                new_vendor,
                new_hostname,
                new_category,
                new_model,
                new_conf_level,
                new_conf_score,
                asset.get("last_discovered", now_iso),
                new_last_scanned,
                new_last_scan_id,
                new_last_identified,
                new_status,
                new_override,
                new_ports_json,
                new_evidence_json,
                new_inconclusive_json,
                new_risk_score,
                new_risk_level,
                asset_id
            ))
            return asset_id
        else:
            first_disc = asset.get("first_discovered", now_iso)
            last_disc = asset.get("last_discovered", now_iso)
            cursor = connection.execute("""
                INSERT INTO assets (
                    ip, mac, vendor, hostname, device_category, model,
                    confidence_level, confidence_score, first_discovered,
                    last_discovered, last_scanned, last_scan_id, last_identified, status,
                    manual_override_category, open_ports_json, evidence_json,
                    inconclusive_signals_json, risk_score, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                mac or "Unknown",
                vendor or "Unknown",
                hostname,
                device_category,
                model,
                confidence_level,
                confidence_score,
                first_disc,
                last_disc,
                last_scanned,
                last_scan_id,
                last_identified,
                status,
                manual_override,
                open_ports_json or "[]",
                evidence_json or "[]",
                inconclusive_json or "[]",
                risk_score,
                risk_level
            ))
            return cursor.lastrowid


def save_identification_result(asset_id: int, result: dict, db_path=DEFAULT_DB_PATH) -> bool:
    """
    Persist Phase 3 multi-vendor identification details.
    Preserves existing user manual override!
    """
    initialize_database(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    category = result.get("category", "Unknown")
    vendor = result.get("vendor", "Unknown")
    model = result.get("model")
    confidence_score = int(result.get("confidence_score", 0))
    confidence_level = result.get("confidence_level", "Unknown")
    evidence = result.get("evidence", [])
    inconclusive = result.get("inconclusive_signals", [])

    evidence_json = json.dumps(evidence) if isinstance(evidence, list) else (evidence or "[]")
    inconclusive_json = json.dumps(inconclusive) if isinstance(inconclusive, list) else (inconclusive or "[]")

    with get_db_connection(db_path) as connection:
        cursor = connection.execute("""
            UPDATE assets SET
                device_category = ?,
                vendor = CASE WHEN ? != 'Unknown' AND ? != '' THEN ? ELSE vendor END,
                model = ?,
                confidence_score = ?,
                confidence_level = ?,
                evidence_json = ?,
                inconclusive_signals_json = ?,
                last_identified = ?
            WHERE id = ?
        """, (
            category,
            vendor, vendor, vendor,
            model,
            confidence_score,
            confidence_level,
            evidence_json,
            inconclusive_json,
            now_iso,
            asset_id
        ))
        return cursor.rowcount > 0


def get_asset(asset_id: int, db_path=DEFAULT_DB_PATH) -> dict | None:
    """Retrieve an asset by ID."""
    initialize_database(db_path)
    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        return None
    return _row_to_asset(row)


def get_asset_by_ip(ip: str, db_path=DEFAULT_DB_PATH) -> dict | None:
    """Retrieve an asset by its IP address."""
    initialize_database(db_path)
    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
    if row is None:
        return None
    return _row_to_asset(row)


def list_assets(category_filter: str | None = None, status_filter: str | None = None, limit: int = 500, db_path=DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve all assets with optional filtering."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    initialize_database(db_path)
    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        query = "SELECT * FROM assets WHERE 1=1"
        params = []

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = connection.execute(query, tuple(params)).fetchall()

    results = [_row_to_asset(r) for r in rows]

    if category_filter and category_filter != "ALL":
        results = [r for r in results if r["effective_category"] == category_filter]

    return results


def update_asset_override(asset_id: int, category: str, db_path=DEFAULT_DB_PATH) -> bool:
    """Update user manual override category for an asset."""
    initialize_database(db_path)
    with get_db_connection(db_path) as connection:
        cursor = connection.execute(
            "UPDATE assets SET manual_override_category = ? WHERE id = ?",
            (category, asset_id)
        )
        return cursor.rowcount > 0


def delete_asset(asset_id: int, db_path=DEFAULT_DB_PATH) -> bool:
    """Delete an asset record."""
    initialize_database(db_path)
    with get_db_connection(db_path) as connection:
        cursor = connection.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        return cursor.rowcount > 0


def save_scan(result: dict, db_path=DEFAULT_DB_PATH) -> int:
    """Save one assessment and return its database ID."""

    initialize_database(db_path)

    fingerprint = result.get("fingerprint", {})
    risk = result.get("risk", {})

    with get_db_connection(db_path) as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                target,
                generated_at,
                scan_status,
                device_type,
                vendor,
                risk_score,
                risk_level,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("target", "unknown"),
            result.get("generated_at", ""),
            result.get("scan_status", "unknown"),
            fingerprint.get("device_type", "Unknown"),
            fingerprint.get("vendor", "Unknown"),
            risk.get("risk_score", 0),
            risk.get("risk_level", "INFO"),
            json.dumps(result, ensure_ascii=False),
        ))

        return cursor.lastrowid


def get_scan(scan_id: int, db_path=DEFAULT_DB_PATH):
    """Retrieve one saved assessment, or None if not found."""

    initialize_database(db_path)

    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    saved = dict(row)
    saved["result"] = json.loads(saved.pop("result_json"))
    return saved


def list_scans(limit: int = 50, db_path=DEFAULT_DB_PATH) -> list[dict]:
    """Return the newest saved scans first."""

    if limit < 1:
        raise ValueError("limit must be at least 1")

    initialize_database(db_path)

    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, target, generated_at, scan_status,
                   device_type, vendor, risk_score, risk_level
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def save_report_record(report: dict, db_path=DEFAULT_DB_PATH) -> int:
    """Save metadata for a generated PDF/JSON customer report."""
    initialize_database(db_path)

    summary_json = report.get("summary_json")
    if isinstance(summary_json, (dict, list)):
        summary_json = json.dumps(summary_json, ensure_ascii=False)

    with get_db_connection(db_path) as connection:
        cursor = connection.execute("""
            INSERT INTO reports (
                report_id,
                scan_id,
                target,
                customer_name,
                organization_name,
                assessment_scope,
                assessor_name,
                notes,
                generated_at,
                risk_score,
                risk_level,
                findings_count,
                pdf_path,
                json_path,
                file_size_bytes,
                summary_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.get("report_id"),
            report.get("scan_id"),
            report.get("target", "unknown"),
            report.get("customer_name") or "",
            report.get("organization_name") or "",
            report.get("assessment_scope") or "",
            report.get("assessor_name") or "",
            report.get("notes") or "",
            report.get("generated_at", datetime.now(timezone.utc).isoformat()),
            int(report.get("risk_score", 0)),
            report.get("risk_level", "INFO"),
            int(report.get("findings_count", 0)),
            report.get("pdf_path", ""),
            report.get("json_path") or "",
            int(report.get("file_size_bytes", 0)),
            summary_json or "{}"
        ))
        return cursor.lastrowid


def get_report_by_id(report_id: str, db_path=DEFAULT_DB_PATH) -> dict | None:
    """Retrieve report metadata by its unique report_id string."""
    initialize_database(db_path)

    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM reports WHERE report_id = ?",
            (report_id,)
        ).fetchone()

    if row is None:
        return None

    data = dict(row)
    if data.get("summary_json"):
        try:
            data["summary"] = json.loads(data["summary_json"])
        except Exception:
            data["summary"] = {}
    return data


def list_report_records(limit: int = 100, db_path=DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve all generated customer reports, newest first."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    initialize_database(db_path)

    with get_db_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT id, report_id, scan_id, target, customer_name,
                   organization_name, assessment_scope, assessor_name,
                   generated_at, risk_score, risk_level, findings_count,
                   pdf_path, json_path, file_size_bytes, summary_json
            FROM reports
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    result = []
    for r in rows:
        d = dict(r)
        if d.get("summary_json"):
            try:
                d["summary"] = json.loads(d["summary_json"])
            except Exception:
                d["summary"] = {}
        result.append(d)
    return result


def delete_report_record(report_id: str, db_path=DEFAULT_DB_PATH) -> bool:
    """Delete a report record by report_id."""
    initialize_database(db_path)

    with get_db_connection(db_path) as connection:
        cursor = connection.execute("DELETE FROM reports WHERE report_id = ?", (report_id,))
        return cursor.rowcount > 0

