import React, { useState, useEffect } from "react";
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  Server,
  Download,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Info,
  Clock,
  Layers,
  Globe
} from "lucide-react";
import { FullScanReport } from "../types";
import { fetchScanDetails } from "../api/client";

interface ScanDetailPageProps {
  scanId: number;
  onBack: () => void;
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-[rgba(255,59,48,0.08)]", text: "text-[#FF3B30]", border: "border-[rgba(255,59,48,0.2)]" },
  HIGH: { bg: "bg-[rgba(255,149,0,0.1)]", text: "text-[#FF9500]", border: "border-[rgba(255,149,0,0.2)]" },
  MEDIUM: { bg: "bg-[rgba(255,204,0,0.14)]", text: "text-[#B28900]", border: "border-[rgba(255,204,0,0.25)]" },
  LOW: { bg: "bg-[rgba(0,122,255,0.08)]", text: "text-[#007AFF]", border: "border-[rgba(0,122,255,0.2)]" },
  INFO: { bg: "bg-[rgba(52,199,89,0.1)]", text: "text-[#34C759]", border: "border-[rgba(52,199,89,0.2)]" },
};

export const ScanDetailPage: React.FC<ScanDetailPageProps> = ({ scanId, onBack }) => {
  const [report, setReport] = useState<FullScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchScanDetails(scanId)
      .then((data) => setReport(data))
      .catch((err) => setError(err.message || "Failed to load scan report"))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-6 animate-pulse">
        <div className="h-6 w-32 bg-[#E5E5EA] rounded-md" />
        <div className="h-40 bg-white border border-[#E5E5EA] rounded-[18px]" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="h-48 bg-white border border-[#E5E5EA] rounded-[18px]" />
          <div className="h-48 bg-white border border-[#E5E5EA] rounded-[18px]" />
          <div className="h-48 bg-white border border-[#E5E5EA] rounded-[18px]" />
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-4">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-[13px] font-medium text-[#007AFF] hover:underline"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to History</span>
        </button>
        <div className="bg-[rgba(255,59,48,0.08)] border border-[rgba(255,59,48,0.2)] rounded-xl p-6 text-center text-[#FF3B30]">
          <p className="font-semibold">{error || "Scan report not found."}</p>
        </div>
      </div>
    );
  }

  const { result, target, vendor, device_type, risk_score, risk_level, generated_at } = report;
  const fp = result.fingerprint || { confidence: 0, evidence: [] };
  const risk = result.risk || { risk_score: 0, risk_level: "INFO", severity_counts: {}, findings: [] };
  const services = result.services || [];
  const findings = result.security_findings || [];
  const httpChecks = result.http_checks || [];
  const httpFindings = result.http_findings || [];
  const cveCandidates = result.cve_candidates || [];

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cctv_audit_${target}_${scanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Navigation Back Action */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-[13px] font-medium text-[#007AFF] hover:underline"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Records</span>
        </button>

        <button
          onClick={handleDownload}
          className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] rounded-xl hover:bg-[#F5F5F7] transition-colors shadow-xs"
        >
          <Download className="w-3.5 h-3.5 text-[#86868B]" />
          <span>Export JSON</span>
        </button>
      </div>

      {/* Target Profile Hero Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[20px] p-6 shadow-apple-subtle">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-[#E5E5EA]">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                AUDIT ID #{scanId}
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-[rgba(52,199,89,0.1)] text-[#34C759]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#34C759]" />
                Host Up
              </span>
            </div>
            <h1 className="text-[26px] font-bold text-[#1D1D1F] tracking-tight font-mono">
              {target}
            </h1>
            <p className="text-[13px] text-[#86868B]">
              Scanned on {generated_at ? generated_at.replace("T", " ").slice(0, 19) : "N/A"} (UTC)
            </p>
          </div>

          {/* Risk Level Badge & Score */}
          <div className="flex items-center gap-5">
            <div className="text-right">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#86868B] block">
                Calculated Risk Score
              </span>
              <div className="flex items-baseline justify-end gap-1">
                <span className="text-[34px] font-bold tracking-tight text-[#1D1D1F]">
                  {risk_score}
                </span>
                <span className="text-[14px] text-[#86868B]">/100</span>
              </div>
            </div>

            <div
              className={`px-4 py-2 rounded-2xl border text-center font-semibold text-[13px] ${
                SEVERITY_COLORS[risk_level]?.bg || "bg-gray-100"
              } ${SEVERITY_COLORS[risk_level]?.text || "text-gray-800"} ${
                SEVERITY_COLORS[risk_level]?.border || "border-gray-200"
              }`}
            >
              <span className="block text-[10px] uppercase font-bold tracking-wider opacity-70">
                Priority
              </span>
              <span>{risk_level}</span>
            </div>
          </div>
        </div>

        {/* 3 Telemetry Summary Blocks */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-6 text-[13px]">
          <div className="bg-[#F5F5F7] rounded-xl p-4 space-y-1">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#86868B]">
              Classification
            </span>
            <p className="font-semibold text-[#1D1D1F]">{device_type || "Unknown"}</p>
            <p className="text-[11px] text-[#86868B]">
              Confidence: {fp.confidence}% (Heuristic score)
            </p>
          </div>

          <div className="bg-[#F5F5F7] rounded-xl p-4 space-y-1">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#86868B]">
              Hardware Manufacturer
            </span>
            <p className="font-semibold text-[#1D1D1F]">{vendor || "Unknown"}</p>
            <p className="text-[11px] text-[#86868B]">
              OUI & Banner Signature match
            </p>
          </div>

          <div className="bg-[#F5F5F7] rounded-xl p-4 space-y-1">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#86868B]">
              Open Services Analyzed
            </span>
            <p className="font-semibold text-[#1D1D1F]">
              {services.filter((s) => s.state === "open").length} open ports
            </p>
            <p className="text-[11px] text-[#86868B]">
              {findings.length + httpFindings.length} total finding alerts
            </p>
          </div>
        </div>
      </div>

      {/* Services & Open Ports Matrix */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        <h3 className="text-[15px] font-semibold text-[#1D1D1F] mb-1">
          Open Services & Banners Matrix
        </h3>
        <p className="text-[12px] text-[#86868B] mb-4">
          Structured port state, detected protocol, daemon product, and version strings
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[#E5E5EA] text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                <th className="py-2.5 px-3">Port / Protocol</th>
                <th className="py-2.5 px-3">State</th>
                <th className="py-2.5 px-3">Service</th>
                <th className="py-2.5 px-3">Identified Product</th>
                <th className="py-2.5 px-3">Detected Version</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5EA]/70">
              {services.map((p, idx) => (
                <tr key={idx} className="hover:bg-[#F5F5F7]/80">
                  <td className="py-2.5 px-3 font-mono font-medium text-[#1D1D1F]">
                    {p.port}/{p.protocol}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded-full text-[11px] font-medium bg-[rgba(52,199,89,0.1)] text-[#34C759]">
                      {p.state}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[#1D1D1F]">
                    {p.service || "unknown"}
                  </td>
                  <td className="py-2.5 px-3 text-[#1D1D1F]">
                    {p.product || "—"}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[#86868B]">
                    {p.version || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Findings & Remediation */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle space-y-4">
        <div>
          <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
            Security Findings & Remediation Advice
          </h3>
          <p className="text-[12px] text-[#86868B]">
            Automated configuration review recommendations from exposure rules
          </p>
        </div>

        <div className="space-y-3">
          {findings.map((f, idx) => {
            const style = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.INFO;

            return (
              <div
                key={idx}
                className="p-4 rounded-xl border border-[#E5E5EA] bg-[#F5F5F7]/30 space-y-2 text-[13px]"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${style.bg} ${style.text}`}>
                      {f.severity}
                    </span>
                    <h4 className="font-semibold text-[#1D1D1F]">{f.title}</h4>
                  </div>
                  <span className="font-mono text-[11px] text-[#86868B]">{f.id}</span>
                </div>

                <div className="bg-white border border-[#E5E5EA] rounded-lg p-2.5 font-mono text-[11px] text-[#86868B]">
                  <strong>Evidence:</strong> {f.evidence}
                </div>

                <p className="text-[#1D1D1F] text-[12px] leading-relaxed">
                  {f.description}
                </p>

                <div className="bg-[rgba(52,199,89,0.06)] border border-[rgba(52,199,89,0.2)] rounded-lg p-2.5 text-[12px] text-[#1D1D1F]">
                  <strong className="text-[#34C759]">Remediation:</strong> {f.remediation}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Dynamic HTTP Security Header Auditing */}
      {httpChecks.length > 0 && (
        <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle space-y-4">
          <div>
            <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
              HTTP Header Security Inspection
            </h3>
            <p className="text-[12px] text-[#86868B]">
              Active probe of camera web management interfaces for standard defense-in-depth headers
            </p>
          </div>

          <div className="space-y-4">
            {httpChecks.map((check, idx) => (
              <div key={idx} className="border border-[#E5E5EA] rounded-xl p-4 bg-[#F5F5F7]/40 text-[13px] space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-[#007AFF]" />
                    <span className="font-mono font-semibold text-[#1D1D1F]">{check.url}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${check.reachable ? "bg-[rgba(52,199,89,0.1)] text-[#34C759]" : "bg-[rgba(255,59,48,0.08)] text-[#FF3B30]"}`}>
                    {check.reachable ? `HTTP ${check.status_code || 200} Reachable` : "Unreachable"}
                  </span>
                </div>

                {check.headers && (
                  <div className="bg-white border border-[#E5E5EA] rounded-lg p-3 text-[11px] font-mono text-[#1D1D1F] max-h-36 overflow-y-auto space-y-0.5">
                    {Object.entries(check.headers).map(([k, v]) => (
                      <div key={k} className="truncate">
                        <strong className="text-[#86868B]">{k}:</strong> {v}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Local CVE Match Candidates */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle space-y-4">
        <div>
          <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
            Local CVE Intelligence Matches
          </h3>
          <p className="text-[12px] text-[#86868B]">
            Product and firmware version correlation against local CVE database (data/cve_database.json)
          </p>
        </div>

        {cveCandidates.length > 0 ? (
          <div className="space-y-3">
            {cveCandidates.map((cve, idx) => (
              <div key={idx} className="p-4 rounded-xl border border-[rgba(255,149,0,0.3)] bg-[rgba(255,149,0,0.04)] space-y-2 text-[13px]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#FF9500] text-white uppercase">
                      {cve.severity}
                    </span>
                    <span className="font-mono font-bold text-[#1D1D1F]">{cve.cve_id}</span>
                  </div>
                  <span className="text-[11px] font-medium text-[#FF9500] bg-[rgba(255,149,0,0.1)] px-2 py-0.5 rounded-md">
                    Candidate (Requires Validation)
                  </span>
                </div>
                <p className="text-[#1D1D1F] text-[12px] leading-relaxed">
                  {cve.description}
                </p>
                <div className="text-[11px] text-[#86868B]">
                  Matched on detected product: <span className="font-mono text-[#1D1D1F]">{cve.product_detected} {cve.version_detected}</span> (Port {cve.port})
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 bg-[#F5F5F7] rounded-xl text-center text-[#86868B] text-[13px]">
            <CheckCircle2 className="w-8 h-8 text-[#34C759] mx-auto mb-2" />
            <p className="font-medium text-[#1D1D1F]">No Candidate CVEs Triggered</p>
            <p className="text-[12px] mt-0.5">
              Detected services/versions did not match known vulnerable strings in the local CVE database.
            </p>
          </div>
        )}
      </div>

      {/* Limitations & Caveats */}
      <div className="bg-[#FFFFFF] border border-[#E5E5EA] rounded-[18px] p-5 shadow-apple-subtle text-[12px] text-[#86868B] space-y-1.5">
        <p className="font-semibold text-[#1D1D1F] flex items-center gap-1.5">
          <Info className="w-4 h-4 text-[#007AFF]" />
          <span>Security Assessment Scope & Limitations:</span>
        </p>
        <ul className="list-disc list-inside space-y-1 pl-1">
          {result.limitations?.map((lim: string, idx: number) => (
            <li key={idx}>{lim}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};
