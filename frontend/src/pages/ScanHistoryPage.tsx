import React, { useState, useEffect } from "react";
import {
  History,
  Search,
  Trash2,
  Eye,
  RefreshCw,
  ScanLine,
  Filter,
  Calendar
} from "lucide-react";
import { ScanSummary } from "../types";
import { fetchScanHistory, deleteScanRecord } from "../api/client";

interface ScanHistoryPageProps {
  onSelectScan: (scanId: number) => void;
  onScanTarget: (ip: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#FF3B30",
  HIGH: "#FF9500",
  MEDIUM: "#FFCC00",
  LOW: "#007AFF",
  INFO: "#34C759",
};

export const ScanHistoryPage: React.FC<ScanHistoryPageProps> = ({
  onSelectScan,
  onScanTarget,
}) => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await fetchScanHistory(100);
      setScans(data.scans);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleDelete = async (id: number) => {
    if (!window.confirm(`Are you sure you want to delete scan record #${id}?`)) {
      return;
    }
    setDeletingId(id);
    try {
      await deleteScanRecord(id);
      setScans(scans.filter((s) => s.id !== id));
    } catch (err) {
      alert("Failed to delete record");
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = scans.filter((s) => {
    return (
      s.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.device_type && s.device_type.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (s.vendor && s.vendor.toLowerCase().includes(searchTerm.toLowerCase()))
    );
  });

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
            Scan Audit History
          </h1>
          <p className="text-[13px] text-[#86868B] mt-0.5">
            Immutable log of all previous assessments stored locally in SQLite (scan_history.db)
          </p>
        </div>

        <button
          onClick={loadHistory}
          className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] rounded-xl hover:bg-[#F5F5F7] transition-colors shadow-xs w-fit"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#86868B] ${loading ? "animate-spin" : ""}`} />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* Search Bar */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-4 shadow-apple-subtle">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-[#86868B] absolute left-3 top-1/2 -translate-y-1/2 stroke-[2]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by target IP, vendor, or device..."
            className="w-full bg-[#F5F5F7] text-[13px] text-[#1D1D1F] placeholder-[#86868B] pl-9 pr-3 py-2 rounded-xl border border-transparent focus:border-[#007AFF] focus:bg-white focus:outline-none transition-all"
          />
        </div>
      </div>

      {/* History Table Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E5E5EA] text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                  <th className="py-3 px-4">Audit ID</th>
                  <th className="py-3 px-4">Target IP</th>
                  <th className="py-3 px-4">Device Classification</th>
                  <th className="py-3 px-4">Vendor</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Scan Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5EA]/70 text-[13px]">
                {filtered.map((scan) => {
                  const level = scan.risk_level || "INFO";
                  const score = scan.risk_score || 0;
                  const color = SEVERITY_COLORS[level] || "#34C759";

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-[#F5F5F7]/80 transition-colors cursor-pointer"
                      onClick={() => onSelectScan(scan.id)}
                    >
                      <td className="py-3.5 px-4 font-mono text-[12px] text-[#86868B]">
                        #{scan.id}
                      </td>
                      <td className="py-3.5 px-4 font-mono font-medium text-[#1D1D1F]">
                        {scan.target}
                      </td>
                      <td className="py-3.5 px-4 text-[#1D1D1F]">
                        {scan.device_type || "Unknown"}
                      </td>
                      <td className="py-3.5 px-4 text-[#86868B]">
                        {scan.vendor || "Unknown"}
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold"
                          style={{
                            backgroundColor: `${color}15`,
                            color: color,
                          }}
                        >
                          {level}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-[#1D1D1F]">
                        {score}
                        <span className="text-[11px] font-normal text-[#86868B]">/100</span>
                      </td>
                      <td className="py-3.5 px-4 text-[#86868B] text-[12px]">
                        {scan.generated_at ? scan.generated_at.replace("T", " ").slice(0, 16) : "N/A"}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onSelectScan(scan.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] hover:bg-[rgba(0,122,255,0.15)] rounded-lg transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>View</span>
                          </button>
                          <button
                            onClick={() => onScanTarget(scan.target)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] border border-[#E5E5EA] rounded-lg transition-colors"
                          >
                            <ScanLine className="w-3.5 h-3.5 text-[#86868B]" />
                            <span>Re-scan</span>
                          </button>
                          <button
                            disabled={deletingId === scan.id}
                            onClick={() => handleDelete(scan.id)}
                            title="Delete Record"
                            className="p-1 text-[#86868B] hover:text-[#FF3B30] hover:bg-[rgba(255,59,48,0.08)] rounded-lg transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 flex flex-col items-center justify-center text-center text-[#86868B]">
            <History className="w-10 h-10 text-[#E5E5EA] mb-3" />
            <p className="text-[14px] font-medium text-[#1D1D1F]">No History Records</p>
            <p className="text-[12px] max-w-sm mt-1">
              Audit reports will appear here as soon as you scan devices in your environment.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
