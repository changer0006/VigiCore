import React, { useState, useEffect } from "react";
import {
  FileText,
  Download,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Server,
  Layers,
  ChevronRight,
  Plus,
  RefreshCw,
  Trash2,
  Eye,
  ExternalLink,
  Info,
  Calendar,
  Building,
  UserCheck
} from "lucide-react";
import {
  fetchScanHistory,
  fetchScanDetails,
  fetchReportsList,
  generatePdfReport,
  deleteReport,
  getReportPdfUrl,
  getReportJsonUrl
} from "../api/client";
import { ScanSummary, FullScanReport, ReportSummaryItem } from "../types";

interface ReportsPageProps {
  onSelectScan?: (scanId: number) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ onSelectScan }) => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [reports, setReports] = useState<ReportSummaryItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [selectedReport, setSelectedReport] = useState<ReportSummaryItem | null>(null);
  const [fullReport, setFullReport] = useState<FullScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [previewModalOpen, setPreviewModalOpen] = useState(false);

  // Form state for generating a report
  const [customerName, setCustomerName] = useState("");
  const [organizationName, setOrganizationName] = useState("Enterprise Security Division");
  const [assessmentScope, setAssessmentScope] = useState("");
  const [assessorName, setAssessorName] = useState("Lead Cybersecurity Consultant");
  const [notes, setNotes] = useState("");
  const [successToast, setSuccessToast] = useState<string | null>(null);
  const [errorToast, setErrorToast] = useState<string | null>(null);

  const loadInitialData = async () => {
    try {
      const [historyData, reportsData] = await Promise.all([
        fetchScanHistory(50),
        fetchReportsList(50)
      ]);
      setScans(historyData.scans);
      setReports(reportsData.reports);

      if (historyData.scans.length > 0) {
        setSelectedScanId(historyData.scans[0].id);
      }
      if (reportsData.reports.length > 0) {
        setSelectedReport(reportsData.reports[0]);
      }
    } catch (err) {
      console.error("Failed to load initial reports data:", err);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      setLoading(true);
      fetchScanDetails(selectedScanId)
        .then((report) => {
          setFullReport(report);
          setAssessmentScope(`Single Target CCTV Audit (${report.target})`);
        })
        .catch(console.error)
        .finally(() => setLoading(false));
    }
  }, [selectedScanId]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedScanId) return;

    setGenerating(true);
    setErrorToast(null);
    try {
      const res = await generatePdfReport(selectedScanId, {
        customer_name: customerName.trim() || undefined,
        organization_name: organizationName.trim() || undefined,
        assessment_scope: assessmentScope.trim() || undefined,
        assessor_name: assessorName.trim() || undefined,
        notes: notes.trim() || undefined,
      });

      setSuccessToast(`Report ${res.report.report_id} generated successfully!`);
      setTimeout(() => setSuccessToast(null), 5000);
      setModalOpen(false);

      // Refresh reports list
      const refreshed = await fetchReportsList(50);
      setReports(refreshed.reports);
      setSelectedReport(res.report);
    } catch (err: any) {
      setErrorToast(err.message || "Failed to generate report.");
    } finally {
      setGenerating(false);
    }
  };

  const handleDeleteReport = async (reportId: string) => {
    if (!confirm(`Are you sure you want to delete report ${reportId}?`)) return;
    try {
      await deleteReport(reportId);
      setReports((prev) => prev.filter((r) => r.report_id !== reportId));
      if (selectedReport?.report_id === reportId) {
        setSelectedReport(null);
      }
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  };

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case "CRITICAL":
        return "bg-[#FEE2E2] text-[#991B1B] border-[#FECACA]";
      case "HIGH":
        return "bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]";
      case "MEDIUM":
        return "bg-[#FEF3C7] text-[#D97706] border-[#FDE68A]";
      case "LOW":
        return "bg-[#EFF6FF] text-[#2563EB] border-[#BFDBFE]";
      default:
        return "bg-[#F1F5F9] text-[#64748B] border-[#E2E8F0]";
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Toast notifications */}
      {successToast && (
        <div className="p-4 bg-[#DCFCE7] border border-[#86EFAC] text-[#15803D] rounded-2xl flex items-center justify-between text-[13px] font-medium shadow-apple-subtle animate-fade-in">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-[#16A34A] shrink-0" />
            <span>{successToast}</span>
          </div>
          <button onClick={() => setSuccessToast(null)} className="text-[#15803D] hover:underline text-[12px]">
            Dismiss
          </button>
        </div>
      )}
      {errorToast && (
        <div className="p-4 bg-[#FEE2E2] border border-[#FCA5A5] text-[#991B1B] rounded-2xl flex items-center justify-between text-[13px] font-medium shadow-apple-subtle">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-5 h-5 text-[#DC2626] shrink-0" />
            <span>{errorToast}</span>
          </div>
          <button onClick={() => setErrorToast(null)} className="text-[#991B1B] hover:underline text-[12px]">
            Dismiss
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
            Security Audit Reports
          </h1>
          <p className="text-[13px] text-[#86868B] mt-0.5">
            Generate and export multi-page customer VAPT assessment PDF deliverables using the Python ReportLab engine
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setModalOpen(true)}
            className="flex items-center gap-1.5 px-4 py-2 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-apple-button"
          >
            <Plus className="w-4 h-4" />
            <span>Generate PDF Report</span>
          </button>
        </div>
      </div>

      {/* Quick Generator Panel */}
      <div className="bg-white border border-[#E5E5EA] rounded-[20px] p-6 shadow-apple-card space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#E5E5EA]">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#007AFF] block mb-1">
              Active Assessment Target
            </span>
            <div className="flex items-center gap-3">
              <label className="text-[13px] font-semibold text-[#1D1D1F] shrink-0">
                Target Audit Scan:
              </label>
              <select
                value={selectedScanId || ""}
                onChange={(e) => setSelectedScanId(Number(e.target.value))}
                className="bg-[#F5F5F7] text-[13px] font-medium text-[#1D1D1F] px-3.5 py-1.5 rounded-xl border border-[#E5E5EA] focus:outline-none focus:border-[#007AFF] max-w-lg"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    Scan #{s.id} — {s.target} ({s.vendor || "Unknown"}) — Risk: {s.risk_level} ({s.risk_score}/100) — {s.generated_at?.slice(0, 10)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setModalOpen(true)}
              className="flex items-center gap-2 px-3.5 py-1.5 text-[12px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] rounded-xl transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-[#007AFF]" />
              <span>Configure Metadata</span>
            </button>
            <button
              onClick={handleGenerateReport}
              disabled={generating || !selectedScanId}
              className="flex items-center gap-2 px-4 py-1.5 text-[12px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-xs disabled:opacity-50"
            >
              {generating ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Compiling PDF...</span>
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  <span>Compile Customer PDF</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Selected Scan Metric Highlights */}
        {fullReport && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-1">
            <div className="p-3 bg-[#F5F5F7] rounded-xl">
              <span className="text-[11px] text-[#86868B] block">Target Device</span>
              <span className="text-[13px] font-semibold text-[#1D1D1F] font-mono">
                {fullReport.target}
              </span>
              <span className="text-[11px] text-[#007AFF] block">
                {fullReport.vendor} ({fullReport.device_type})
              </span>
            </div>
            <div className="p-3 bg-[#F5F5F7] rounded-xl">
              <span className="text-[11px] text-[#86868B] block">Risk Score</span>
              <span className="text-[13px] font-bold text-[#DC2626]">
                {fullReport.risk_score} / 100
              </span>
              <span className="text-[11px] text-[#86868B] block">
                Level: {fullReport.risk_level}
              </span>
            </div>
            <div className="p-3 bg-[#F5F5F7] rounded-xl">
              <span className="text-[11px] text-[#86868B] block">Total Findings</span>
              <span className="text-[13px] font-semibold text-[#1D1D1F]">
                {fullReport.result?.risk?.finding_count || 0}
              </span>
              <span className="text-[11px] text-[#86868B] block">
                Medium: {fullReport.result?.risk?.severity_counts?.MEDIUM || 0} | Low: {fullReport.result?.risk?.severity_counts?.LOW || 0}
              </span>
            </div>
            <div className="p-3 bg-[#F5F5F7] rounded-xl">
              <span className="text-[11px] text-[#86868B] block">Open Services</span>
              <span className="text-[13px] font-semibold text-[#1D1D1F]">
                {fullReport.result?.services?.length || 0} daemons
              </span>
              <span className="text-[11px] text-[#86868B] block font-mono">
                {fullReport.result?.services?.map((s) => s.port).join(", ")}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Generated Customer PDF Deliverables (Report History) */}
      <div className="bg-white border border-[#E5E5EA] rounded-[20px] p-6 shadow-apple-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#E5E5EA]">
          <div>
            <h2 className="text-[16px] font-semibold text-[#1D1D1F] tracking-tight">
              Customer Deliverables & Report History
            </h2>
            <p className="text-[12px] text-[#86868B]">
              Persistent multi-page PDF documents generated via ReportLab and saved in SQLite
            </p>
          </div>
          <span className="px-2.5 py-1 bg-[#F5F5F7] text-[#86868B] rounded-lg text-[12px] font-medium">
            {reports.length} Deliverables
          </span>
        </div>

        {reports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[#E5E5EA] text-[#86868B] text-[11px] uppercase tracking-wider font-semibold">
                  <th className="py-3 px-3">Report ID</th>
                  <th className="py-3 px-3">Target Scope</th>
                  <th className="py-3 px-3">Organization</th>
                  <th className="py-3 px-3">Date</th>
                  <th className="py-3 px-3">Risk Level</th>
                  <th className="py-3 px-3">Findings</th>
                  <th className="py-3 px-3">Size</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5EA]">
                {reports.map((r) => (
                  <tr key={r.report_id} className="hover:bg-[#F5F5F7] transition-colors">
                    <td className="py-3.5 px-3 font-mono font-medium text-[#1D1D1F]">
                      {r.report_id}
                    </td>
                    <td className="py-3.5 px-3 text-[#1D1D1F]">
                      <span className="font-semibold">{r.target}</span>
                      <span className="block text-[11px] text-[#86868B]">{r.assessment_scope}</span>
                    </td>
                    <td className="py-3.5 px-3 text-[#86868B]">
                      {r.organization_name || r.customer_name || "Enterprise Operations"}
                    </td>
                    <td className="py-3.5 px-3 text-[#86868B] text-[12px]">
                      {r.generated_at?.slice(0, 10)}
                    </td>
                    <td className="py-3.5 px-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold border ${getRiskBadgeColor(
                          r.risk_level
                        )}`}
                      >
                        {r.risk_level} ({r.risk_score}/100)
                      </span>
                    </td>
                    <td className="py-3.5 px-3 text-[#1D1D1F] font-medium">
                      {r.findings_count} findings
                    </td>
                    <td className="py-3.5 px-3 text-[#86868B] text-[12px]">
                      {formatBytes(r.file_size_bytes)}
                    </td>
                    <td className="py-3.5 px-3 text-right space-x-1">
                      <a
                        href={getReportPdfUrl(r.report_id, true)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-lg transition-all shadow-xs"
                        title="Download Customer PDF"
                      >
                        <Download className="w-3 h-3" />
                        <span>PDF</span>
                      </a>
                      <a
                        href={getReportJsonUrl(r.report_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] border border-[#E5E5EA] rounded-lg transition-colors"
                        title="Download Structured JSON"
                      >
                        <span>JSON</span>
                      </a>
                      <button
                        onClick={() => {
                          setSelectedReport(r);
                          setPreviewModalOpen(true);
                        }}
                        className="inline-flex items-center p-1.5 text-[#86868B] hover:text-[#1D1D1F] rounded-lg hover:bg-[#E5E5EA] transition-colors"
                        title="View Report Metadata"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDeleteReport(r.report_id)}
                        className="inline-flex items-center p-1.5 text-[#86868B] hover:text-[#DC2626] rounded-lg hover:bg-[#FEE2E2] transition-colors"
                        title="Delete Report"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 flex flex-col items-center justify-center text-center text-[#86868B]">
            <FileText className="w-10 h-10 text-[#E5E5EA] mb-2" />
            <p className="text-[14px] font-medium text-[#1D1D1F]">No Generated Reports Yet</p>
            <p className="text-[12px] max-w-sm mt-0.5">
              Select an assessment target above and click "Compile Customer PDF" to produce a professional 9-page deliverable.
            </p>
          </div>
        )}
      </div>

      {/* Generate Report Configuration Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-xs p-4">
          <div className="bg-white border border-[#E5E5EA] rounded-[22px] max-w-lg w-full p-6 shadow-apple-card space-y-5 animate-scale-up">
            <div className="flex items-start justify-between border-b border-[#E5E5EA] pb-3">
              <div>
                <h3 className="text-[17px] font-semibold text-[#1D1D1F] tracking-tight">
                  Generate Customer VAPT Report
                </h3>
                <p className="text-[12px] text-[#86868B]">
                  Configure organization branding and scope for the ReportLab PDF document
                </p>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="text-[#86868B] hover:text-[#1D1D1F] text-[18px] leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="space-y-4">
              <div>
                <label className="text-[11px] font-semibold text-[#1D1D1F] uppercase tracking-wider block mb-1">
                  Customer / Client Name
                </label>
                <div className="relative">
                  <UserCheck className="w-4 h-4 text-[#86868B] absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={customerName}
                    onChange={(e) => setCustomerName(e.target.value)}
                    placeholder="e.g. Acme Surveillance Operations"
                    className="w-full pl-9 pr-3 py-2 bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl text-[13px] text-[#1D1D1F] focus:outline-none focus:border-[#007AFF]"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-[#1D1D1F] uppercase tracking-wider block mb-1">
                  Organization / Department
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-[#86868B] absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="e.g. Physical Security & Asset Protection Division"
                    className="w-full pl-9 pr-3 py-2 bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl text-[13px] text-[#1D1D1F] focus:outline-none focus:border-[#007AFF]"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-[#1D1D1F] uppercase tracking-wider block mb-1">
                  Assessment Scope Description
                </label>
                <input
                  type="text"
                  value={assessmentScope}
                  onChange={(e) => setAssessmentScope(e.target.value)}
                  placeholder="e.g. Perimeter IPCam & Management Gateway Evaluation"
                  className="w-full px-3 py-2 bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl text-[13px] text-[#1D1D1F] focus:outline-none focus:border-[#007AFF]"
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold text-[#1D1D1F] uppercase tracking-wider block mb-1">
                  Lead Assessor Name / Title
                </label>
                <input
                  type="text"
                  value={assessorName}
                  onChange={(e) => setAssessorName(e.target.value)}
                  placeholder="e.g. Senior Cybersecurity Consultant"
                  className="w-full px-3 py-2 bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl text-[13px] text-[#1D1D1F] focus:outline-none focus:border-[#007AFF]"
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold text-[#1D1D1F] uppercase tracking-wider block mb-1">
                  Executive Notes (Optional)
                </label>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={2}
                  placeholder="e.g. Routine quarterly compliance audit for authorized surveillance subnet."
                  className="w-full px-3 py-2 bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl text-[13px] text-[#1D1D1F] focus:outline-none focus:border-[#007AFF]"
                />
              </div>

              <div className="pt-3 border-t border-[#E5E5EA] flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 text-[13px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] rounded-xl transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="flex items-center gap-2 px-5 py-2 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-apple-button disabled:opacity-50"
                >
                  {generating ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Generating PDF...</span>
                    </>
                  ) : (
                    <span>Generate Customer PDF</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Report Preview Modal */}
      {previewModalOpen && selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-xs p-4">
          <div className="bg-white border border-[#E5E5EA] rounded-[22px] max-w-xl w-full p-6 shadow-apple-card space-y-4 animate-scale-up">
            <div className="flex items-start justify-between border-b border-[#E5E5EA] pb-3">
              <div>
                <h3 className="text-[17px] font-semibold text-[#1D1D1F] tracking-tight">
                  Report Summary: {selectedReport.report_id}
                </h3>
                <p className="text-[12px] text-[#86868B]">
                  Persisted delivery metadata and findings distribution
                </p>
              </div>
              <button
                onClick={() => setPreviewModalOpen(false)}
                className="text-[#86868B] hover:text-[#1D1D1F] text-[18px] leading-none"
              >
                &times;
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-[13px]">
              <div className="p-3 bg-[#F5F5F7] rounded-xl">
                <span className="text-[11px] text-[#86868B] block">Target Host</span>
                <span className="font-semibold text-[#1D1D1F] font-mono">{selectedReport.target}</span>
              </div>
              <div className="p-3 bg-[#F5F5F7] rounded-xl">
                <span className="text-[11px] text-[#86868B] block">Organization</span>
                <span className="font-semibold text-[#1D1D1F]">{selectedReport.organization_name || "N/A"}</span>
              </div>
              <div className="p-3 bg-[#F5F5F7] rounded-xl">
                <span className="text-[11px] text-[#86868B] block">Heuristic Risk Score</span>
                <span className="font-bold text-[#DC2626]">{selectedReport.risk_score} / 100 ({selectedReport.risk_level})</span>
              </div>
              <div className="p-3 bg-[#F5F5F7] rounded-xl">
                <span className="text-[11px] text-[#86868B] block">Total Findings</span>
                <span className="font-semibold text-[#1D1D1F]">{selectedReport.findings_count} findings</span>
              </div>
            </div>

            {selectedReport.summary && (
              <div className="p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl text-[12px] space-y-1.5">
                <span className="font-semibold text-[#1D1D1F] block">Controls Audit Verification:</span>
                <div className="flex items-center gap-4 text-[12px]">
                  <span className="text-[#16A34A] font-medium">
                    ✓ {selectedReport.summary.controls_passed ?? 0} Passed
                  </span>
                  <span className="text-[#DC2626] font-medium">
                    ✗ {selectedReport.summary.controls_failed ?? 0} Failed
                  </span>
                  <span className="text-[#64748B] font-medium">
                    ○ {selectedReport.summary.controls_unassessed ?? 0} Not Assessed
                  </span>
                </div>
              </div>
            )}

            <div className="pt-3 border-t border-[#E5E5EA] flex justify-end gap-3">
              <a
                href={getReportJsonUrl(selectedReport.report_id)}
                className="px-4 py-2 text-[13px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] rounded-xl transition-colors"
              >
                Download JSON
              </a>
              <a
                href={getReportPdfUrl(selectedReport.report_id, true)}
                className="flex items-center gap-2 px-5 py-2 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-apple-button"
              >
                <Download className="w-4 h-4" />
                <span>Download Customer PDF</span>
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
