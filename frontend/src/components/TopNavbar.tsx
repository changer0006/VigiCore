import React from "react";
import { ChevronRight, Radar, ScanLine, RefreshCw } from "lucide-react";
import { NavPage } from "./Sidebar";

interface TopNavbarProps {
  currentPage: NavPage;
  selectedScanTarget?: string;
  systemHealthy?: boolean;
  onNavigate?: (page: NavPage) => void;
  onRefresh?: () => void;
  refreshing?: boolean;
}

const pageTitles: Record<NavPage, { title: string; breadcrumb: string }> = {
  overview: { title: "Overview", breadcrumb: "Security Posture" },
  discovery: { title: "Network Discovery", breadcrumb: "Asset Discovery" },
  inventory: { title: "Asset Inventory", breadcrumb: "Discovered Devices" },
  vulnerabilities: { title: "Vulnerability Assessment", breadcrumb: "Threat Intelligence" },
  scan_center: { title: "Scan Center", breadcrumb: "Active Audit Console" },
  history: { title: "Scan History", breadcrumb: "Audit Log & Records" },
  reports: { title: "Security Reports", breadcrumb: "Compliance & Summaries" },
  settings: { title: "Settings", breadcrumb: "Configuration" },
  scan_detail: { title: "Scan Assessment Report", breadcrumb: "Detailed Device Audit" },
};

export const TopNavbar: React.FC<TopNavbarProps> = ({
  currentPage,
  selectedScanTarget,
  systemHealthy = true,
  onNavigate,
  onRefresh,
  refreshing = false,
}) => {
  const currentMeta = pageTitles[currentPage];

  return (
    <header className="h-16 bg-[#FFFFFF] border-b border-[#E5E5EA] px-8 flex items-center justify-between sticky top-0 z-20 select-none">
      {/* Breadcrumbs & Title */}
      <div>
        <div className="flex items-center gap-1.5 text-[11px] font-medium text-[#86868B]">
          <span className="font-semibold text-[#1D1D1F] hover:text-[#007AFF] transition-colors cursor-pointer" onClick={() => onNavigate?.("overview")}>
            VigiCore
          </span>
          <ChevronRight className="w-3 h-3 stroke-[2] text-[#86868B]/60" />
          <span className="text-[#86868B]">
            {selectedScanTarget && currentPage === "scan_detail"
              ? "Audit Report"
              : currentMeta.title}
          </span>
          <ChevronRight className="w-3 h-3 stroke-[2] text-[#86868B]/60" />
          <span className="text-[#1D1D1F] font-semibold">
            {selectedScanTarget && currentPage === "scan_detail"
              ? selectedScanTarget
              : currentMeta.breadcrumb}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <h2 className="text-[17px] font-semibold text-[#1D1D1F] tracking-tight">
            {selectedScanTarget && currentPage === "scan_detail"
              ? `Audit Report: ${selectedScanTarget}`
              : currentMeta.title}
          </h2>
        </div>
      </div>

      {/* Right Controls: Real-time Engine Status Pill & Functional Shortcuts */}
      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={refreshing}
            title="Refresh active view"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] rounded-full transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#86868B] ${refreshing ? "animate-spin text-[#007AFF]" : ""}`} />
            <span>Refresh</span>
          </button>
        )}

        {onNavigate && currentPage !== "discovery" && (
          <button
            onClick={() => onNavigate("discovery")}
            title="Discover local subnet devices"
            className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] rounded-full transition-colors"
          >
            <Radar className="w-3.5 h-3.5 text-[#007AFF]" />
            <span>Discover Subnet</span>
          </button>
        )}

        {onNavigate && currentPage !== "scan_center" && (
          <button
            onClick={() => onNavigate("scan_center")}
            title="Launch security scan"
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] hover:bg-[rgba(0,122,255,0.15)] rounded-full transition-colors"
          >
            <ScanLine className="w-3.5 h-3.5" />
            <span>Scan Device</span>
          </button>
        )}

        {/* Real-Time Engine Status Pill */}
        <div
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-[12px] font-medium transition-all ${
            systemHealthy
              ? "bg-[#34C759]/10 border-[#34C759]/30 text-[#15803D]"
              : "bg-[#FF3B30]/10 border-[#FF3B30]/30 text-[#DC2626]"
          }`}
          title={systemHealthy ? "FastAPI scanning engine running normally" : "Backend service offline"}
        >
          <span className="relative flex h-2 w-2">
            {systemHealthy && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#34C759] opacity-75" />
            )}
            <span
              className={`relative inline-flex rounded-full h-2 w-2 ${
                systemHealthy ? "bg-[#34C759]" : "bg-[#FF3B30]"
              }`}
            />
          </span>
          <span className="text-[12px] font-semibold">
            {systemHealthy ? "Engine Active" : "Engine Offline"}
          </span>
          <span className="text-[10px] font-medium text-[#86868B] tracking-wider uppercase pl-0.5 border-l border-[#86868B]/30">
            v1.0
          </span>
        </div>
      </div>
    </header>
  );
};
