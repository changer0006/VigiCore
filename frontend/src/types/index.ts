export interface ScanSummary {
  id: number;
  target: string;
  generated_at: string;
  scan_status?: string;
  device_type?: string;
  vendor?: string;
  risk_score?: number;
  risk_level?: string;
}

export interface OverviewStats {
  total_discovered_devices: number;
  online_devices: number;
  vulnerable_devices: number;
  critical_vulnerabilities: number;
  overall_security_score: number;
  severity_breakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  vendor_distribution: Array<{ name: string; count: number }>;
  risk_trend: Array<{ id: number; target: string; date: string; score: number; level: string }>;
  recent_scans: ScanSummary[];
}

export interface DeviceInventoryItem {
  ip: string;
  mac: string;
  vendor: string;
  device_type: string;
  status: string;
  risk_score: number;
  risk_level: string;
  open_ports: number[];
  last_scan_id: number | null;
  last_scanned: string;
}

export interface VulnerabilityItem {
  scan_id: number;
  target: string;
  date: string;
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  is_candidate: boolean;
  requires_manual_validation?: boolean;
  confirmed_vulnerability: boolean;
  evidence: string;
  description: string;
  remediation: string;
  port: number | null;
  references: string[];
}

export interface ScanTaskStatus {
  task_id: string;
  target: string;
  status: "pending" | "running" | "completed" | "failed";
  stage: string;
  progress: number;
  message: string;
  logs: string[];
  scan_id: number | null;
  error?: string | null;
}

export interface DiscoveryHostItem {
  ip: string;
  mac: string | null;
  vendor: string | null;
  hostname?: string | null;
  discovery_method?: string;
  discovery_type?: string;
}

export interface DiscoveryTaskStatus {
  task_id: string;
  network: string;
  status: "pending" | "running" | "completed" | "failed";
  stage: string;
  progress: number;
  message?: string;
  logs: string[];
  result?: DiscoveryHostItem[];
  error?: string | null;
}

export interface FullScanReport {
  id: number;
  target: string;
  generated_at: string;
  scan_status: string;
  device_type: string;
  vendor: string;
  risk_score: number;
  risk_level: string;
  result: {
    schema_version: number;
    generated_at: string;
    target: string;
    scan_status: string;
    services: Array<{
      port: number;
      protocol: string;
      state: string;
      service: string | null;
      product: string | null;
      version: string | null;
    }>;
    fingerprint: {
      target: string;
      status: string;
      device_type: string;
      vendor: string;
      confidence: number;
      confidence_type: string;
      evidence: string[];
    };
    security_findings: Array<{
      id: string;
      target: string;
      title: string;
      severity: string;
      evidence: string;
      description: string;
      remediation: string;
      confirmed_vulnerability: boolean;
      observed_at: string;
    }>;
    http_checks: Array<{
      url: string;
      final_url?: string;
      status_code?: number;
      reachable: boolean;
      headers?: Record<string, string>;
      error?: string;
    }>;
    http_findings: Array<{
      id: string;
      target: string;
      port: number;
      url: string;
      title: string;
      severity: string;
      evidence: string;
      remediation: string;
      confirmed_vulnerability: boolean;
    }>;
    cve_candidates: Array<{
      cve_id: string;
      target: string;
      port: number;
      product_detected: string;
      version_detected: string;
      description: string;
      severity: string;
      match_type: string;
      confirmed_vulnerability: boolean;
      requires_manual_validation: boolean;
      references: string[];
    }>;
    cve_database_error?: string | null;
    risk: {
      risk_score: number;
      risk_level: string;
      finding_count: number;
      severity_counts: Record<string, number>;
      scoring_method: string;
      findings: any[];
    };
    limitations: string[];
  };
}

export interface SystemNetworkInfo {
  active_interface: string;
  ip: string | null;
  netmask: string | null;
  cidr: string | null;
  gateway: string | null;
  broadcast: string | null;
  mac: string | null;
  ssid: string | null;
  nmap: {
    installed: boolean;
    path: string | null;
    version: string | null;
    privileged_available?: boolean;
    privilege_mode?: string;
    privilege_guidance?: {
      rule: string;
      sudoers_file: string;
      instructions: string;
    } | null;
  };
}

export interface NetworkInterfaceItem {
  interface: string;
  ip: string | null;
  netmask: string | null;
  cidr: string | null;
  broadcast: string | null;
  mac: string | null;
  is_active: boolean;
  is_default?: boolean;
  gateway?: string | null;
}

export interface AssetRecord {
  id: number;
  ip: string;
  mac: string;
  vendor: string;
  model?: string | null;
  hostname: string | null;
  device_category: string;
  effective_category: string;
  device_type: string;
  confidence_level: "High" | "Medium" | "Low" | "Unknown";
  confidence_score: number;
  first_discovered: string;
  last_discovered: string;
  last_scanned: string | null;
  last_scan_id: number | null;
  last_identified?: string | null;
  status: string;
  manual_override_category: string | null;
  open_ports: number[];
  evidence?: string[];
  inconclusive_signals?: string[];
  risk_score: number;
  risk_level: string;
}

export interface ReportSummaryItem {
  id: number;
  report_id: string;
  scan_id: number;
  target: string;
  customer_name: string;
  organization_name: string;
  assessment_scope: string;
  assessor_name: string;
  notes: string;
  generated_at: string;
  risk_score: number;
  risk_level: string;
  findings_count: number;
  pdf_path: string;
  json_path: string;
  file_size_bytes: number;
  summary?: {
    device_type?: string;
    vendor?: string;
    severity_counts?: Record<string, number>;
    controls_passed?: number;
    controls_failed?: number;
    controls_unassessed?: number;
  };
}
