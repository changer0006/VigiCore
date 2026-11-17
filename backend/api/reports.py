"""
Reports API Router
Exposes endpoints for generating, listing, viewing, and downloading customer VAPT reports.
"""

from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from fastapi.responses import FileResponse
from app.reports.report_service import (
    generate_and_save_report,
    get_report_details,
    list_all_reports,
    delete_report,
)

router = APIRouter(prefix="/api/reports", tags=["Reports"])


class GenerateReportRequest(BaseModel):
    customer_name: Optional[str] = Field(None, example="Acme Corporation")
    organization_name: Optional[str] = Field(None, example="Enterprise Physical Security Division")
    assessment_scope: Optional[str] = Field(None, example="CCTV Camera & Gateway Subnet Audit")
    assessor_name: Optional[str] = Field(None, example="Lead Cybersecurity Consultant")
    notes: Optional[str] = Field(None, example="Standard defensive compliance assessment")


@router.post("/generate/{scan_id}")
def generate_report_endpoint(scan_id: int, request: Optional[GenerateReportRequest] = None):
    """
    Generate a customer-ready multi-page ReportLab PDF & companion JSON
    from persisted scan results.
    """
    metadata = {}
    if request:
        metadata = request.model_dump(exclude_unset=True)

    try:
        report_record = generate_and_save_report(scan_id, metadata)
        return {
            "success": True,
            "message": f"Report {report_record['report_id']} generated successfully.",
            "report": report_record
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


@router.get("")
def list_reports_endpoint(limit: int = 50):
    """Retrieve all generated customer reports from SQLite."""
    try:
        limit_val = limit if isinstance(limit, int) else 50
        reports = list_all_reports(limit=limit_val)
        return {
            "count": len(reports),
            "reports": reports
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{report_id}")
def get_report_details_endpoint(report_id: str):
    """Retrieve metadata and findings summary for a specific report."""
    rep = get_report_details(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return rep


@router.get("/{report_id}/pdf")
def download_report_pdf(report_id: str, download: bool = False):
    """
    Download or stream the generated PDF report.
    If download=true, sends as attachment with Content-Disposition header.
    Otherwise streams inline.
    """
    download_bool = bool(download) if not hasattr(download, "default") else False
    rep = get_report_details(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    pdf_path = Path(rep["pdf_path"])
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF report file does not exist on disk.")

    filename = pdf_path.name
    disposition = "attachment" if download else "inline"

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'}
    )


@router.get("/{report_id}/json")
def download_report_json(report_id: str):
    """Download the structured JSON companion report."""
    rep = get_report_details(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    json_path = rep.get("json_path")
    if not json_path or not Path(json_path).exists():
        raise HTTPException(status_code=404, detail="JSON report file does not exist on disk.")

    return FileResponse(
        path=str(json_path),
        media_type="application/json",
        filename=Path(json_path).name,
        headers={"Content-Disposition": f'attachment; filename="{Path(json_path).name}"'}
    )


@router.delete("/{report_id}")
def delete_report_endpoint(report_id: str):
    """Delete a report record and its files from disk."""
    success = delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return {
        "success": True,
        "message": f"Report '{report_id}' deleted successfully."
    }
