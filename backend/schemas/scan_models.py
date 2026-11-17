from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class DiscoveryRequest(BaseModel):
    network: str = Field(..., example="192.168.1.0/24")


class HostItem(BaseModel):
    ip: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None


class DiscoveryResponse(BaseModel):
    network: str
    count: int
    hosts: List[HostItem]


class ScanRequest(BaseModel):
    target: str = Field(..., example="192.168.1.20")


class TaskStatus(BaseModel):
    task_id: str
    target: str
    status: str  # "pending", "running", "completed", "failed"
    stage: str   # "initializing", "service_scanning", "fingerprinting", "http_checks", "cve_matching", "scoring", "completed", "failed"
    progress: int  # 0 to 100
    message: str
    logs: List[str] = []
    scan_id: Optional[int] = None
    error: Optional[str] = None


class ScanSummary(BaseModel):
    id: int
    target: str
    generated_at: str
    scan_status: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    risk_score: Optional[int] = 0
    risk_level: Optional[str] = "INFO"


class OverviewStats(BaseModel):
    total_discovered_devices: int
    online_devices: int
    vulnerable_devices: int
    critical_vulnerabilities: int
    overall_security_score: int
    severity_breakdown: Dict[str, int]
    vendor_distribution: List[Dict[str, Any]]
    risk_trend: List[Dict[str, Any]]
    recent_scans: List[ScanSummary]
