import {
  OverviewStats,
  DeviceInventoryItem,
  VulnerabilityItem,
  ScanSummary,
  ScanTaskStatus,
  DiscoveryTaskStatus,
  FullScanReport,
  SystemNetworkInfo,
  NetworkInterfaceItem,
  AssetRecord,
  ReportSummaryItem
} from "../types";

const API_BASE = ""; // Proxied by Vite to http://127.0.0.1:8000

export async function fetchNetworkInfo(): Promise<SystemNetworkInfo> {
  const res = await fetch(`${API_BASE}/api/network/info`);
  if (!res.ok) throw new Error(`Failed to fetch network telemetry: ${res.statusText}`);
  return res.json();
}

export async function fetchNetworkInterfaces(): Promise<{ interfaces: NetworkInterfaceItem[] }> {
  const res = await fetch(`${API_BASE}/api/network/interfaces`);
  if (!res.ok) throw new Error(`Failed to fetch network interfaces: ${res.statusText}`);
  return res.json();
}

export async function fetchAssets(category?: string): Promise<{ count: number; assets: AssetRecord[]; devices: AssetRecord[] }> {
  const query = category && category !== "ALL" ? `?category=${encodeURIComponent(category)}` : "";
  const res = await fetch(`${API_BASE}/api/assets${query}`);
  if (!res.ok) throw new Error(`Failed to fetch assets: ${res.statusText}`);
  return res.json();
}

export async function overrideAssetCategory(assetId: number, category: string): Promise<{ success: boolean; message: string; asset: AssetRecord }> {
  const res = await fetch(`${API_BASE}/api/assets/${assetId}/override-type`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ category })
  });
  if (!res.ok) throw new Error(`Failed to override asset category: ${res.statusText}`);
  return res.json();
}

export async function identifySingleAsset(assetId: number): Promise<{ success: boolean; message: string; asset: AssetRecord }> {
  const res = await fetch(`${API_BASE}/api/assets/${assetId}/identify`, {
    method: "POST"
  });
  if (!res.ok) throw new Error(`Identification failed: ${res.statusText}`);
  return res.json();
}

export async function identifyAllAssets(): Promise<{ count: number; message: string; assets: AssetRecord[] }> {
  const res = await fetch(`${API_BASE}/api/assets/identify-all`, {
    method: "POST"
  });
  if (!res.ok) throw new Error(`Identify all failed: ${res.statusText}`);
  return res.json();
}

export async function fetchAssetIdentification(assetId: number): Promise<any> {
  const res = await fetch(`${API_BASE}/api/assets/${assetId}/identification`);
  if (!res.ok) throw new Error(`Failed to fetch identification details: ${res.statusText}`);
  return res.json();
}

export async function deleteAsset(assetId: number): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/assets/${assetId}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error(`Failed to delete asset: ${res.statusText}`);
  return res.json();
}

export async function fetchOverviewStats(): Promise<OverviewStats> {
  const res = await fetch(`${API_BASE}/api/stats/overview`);
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.statusText}`);
  return res.json();
}

export async function fetchDeviceInventory(): Promise<{ count: number; devices: DeviceInventoryItem[] }> {
  const res = await fetch(`${API_BASE}/api/inventory`);
  if (!res.ok) throw new Error(`Failed to fetch inventory: ${res.statusText}`);
  return res.json();
}

export async function fetchVulnerabilities(): Promise<{ count: number; findings: VulnerabilityItem[] }> {
  const res = await fetch(`${API_BASE}/api/vulnerabilities`);
  if (!res.ok) throw new Error(`Failed to fetch vulnerabilities: ${res.statusText}`);
  return res.json();
}

export async function fetchScanHistory(limit = 100): Promise<{ count: number; scans: ScanSummary[] }> {
  const res = await fetch(`${API_BASE}/api/history?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch scan history: ${res.statusText}`);
  return res.json();
}

export async function deleteScanRecord(scanId: number): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/history/${scanId}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error(`Failed to delete scan: ${res.statusText}`);
  return res.json();
}

export async function fetchScanDetails(scanId: number): Promise<FullScanReport> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error(`Failed to fetch scan details: ${res.statusText}`);
  return res.json();
}

export async function fetchDefaultNetwork(): Promise<{ network: string; local_ip: string }> {
  const res = await fetch(`${API_BASE}/api/discovery/default-network`);
  if (!res.ok) return { network: "192.168.0.0/24", local_ip: "127.0.0.1" };
  return res.json();
}

export async function startNetworkDiscovery(network: string): Promise<{ task_id: string; network: string }> {

  const res = await fetch(`${API_BASE}/api/discovery/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ network })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Discovery failed to start");
  }
  return res.json();
}

export async function pollDiscoveryTask(taskId: string): Promise<DiscoveryTaskStatus> {
  const res = await fetch(`${API_BASE}/api/discovery/tasks/${taskId}`);
  if (!res.ok) throw new Error(`Discovery task poll failed: ${res.statusText}`);
  return res.json();
}

export async function startHostScan(target: string): Promise<{ task_id: string; target: string }> {
  const res = await fetch(`${API_BASE}/api/scans/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Scan failed to start");
  }
  return res.json();
}

export async function pollScanTask(taskId: string): Promise<ScanTaskStatus> {
  const res = await fetch(`${API_BASE}/api/scans/tasks/${taskId}`);
  if (!res.ok) throw new Error(`Scan task poll failed: ${res.statusText}`);
  return res.json();
}

export async function generatePdfReport(
  scanId: number,
  metadata?: {
    customer_name?: string;
    organization_name?: string;
    assessment_scope?: string;
    assessor_name?: string;
    notes?: string;
  }
): Promise<{ success: boolean; message: string; report: ReportSummaryItem }> {
  const res = await fetch(`${API_BASE}/api/reports/generate/${scanId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(metadata || {})
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to generate report");
  }
  return res.json();
}

export async function fetchReportsList(limit = 50): Promise<{ count: number; reports: ReportSummaryItem[] }> {
  const res = await fetch(`${API_BASE}/api/reports?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch reports list: ${res.statusText}`);
  return res.json();
}

export async function fetchReportDetails(reportId: string): Promise<ReportSummaryItem> {
  const res = await fetch(`${API_BASE}/api/reports/${reportId}`);
  if (!res.ok) throw new Error(`Failed to fetch report details: ${res.statusText}`);
  return res.json();
}

export async function deleteReport(reportId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/reports/${reportId}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error(`Failed to delete report: ${res.statusText}`);
  return res.json();
}

export function getReportPdfUrl(reportId: string, download = true): string {
  return `${API_BASE}/api/reports/${reportId}/pdf?download=${download ? "true" : "false"}`;
}

export function getReportJsonUrl(reportId: string): string {
  return `${API_BASE}/api/reports/${reportId}/json`;
}

export async function fetchHealthStatus(): Promise<{
  status: string;
  service: string;
  version: string;
  database?: { connected: boolean };
  nmap?: { available: boolean; path?: string };
}> {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}


