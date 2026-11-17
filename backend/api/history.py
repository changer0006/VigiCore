import sqlite3
from fastapi import APIRouter, HTTPException, Query
from app.database.db import list_scans, DEFAULT_DB_PATH

router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("")
def get_scan_history(limit: int = 100):
    try:
        limit_val = limit if isinstance(limit, int) else 100
        scans = list_scans(limit=limit_val)
        return {
            "count": len(scans),
            "scans": scans
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.delete("/{scan_id}")
def delete_scan_record(scan_id: int):
    try:
        with sqlite3.connect(DEFAULT_DB_PATH) as connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found")
        return {"success": True, "message": f"Scan #{scan_id} deleted."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
