import React from "react";
import {
  LayoutDashboard,
  Radar,
  Server,
  ShieldAlert,
  ScanLine,
  History,
  FileText,
  Settings,
  ShieldCheck,
  ShieldX
} from "lucide-react";
import { VigiCoreLogo } from "./VigiCoreLogo";

export type NavPage =
  | "overview"
  | "discovery"
  | "inventory"
  | "vulnerabilities"
  | "scan_center"
  | "history"
  | "reports"
  | "settings"
  | "scan_detail";

interface SidebarProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  systemHealthy?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  systemHealthy = true,
}) => {
  const navItems = [
    { id: "overview" as NavPage, label: "Overview", icon: LayoutDashboard },
    { id: "discovery" as NavPage, label: "Network Discovery", icon: Radar },
    { id: "inventory" as NavPage, label: "Asset Inventory", icon: Server },
    { id: "vulnerabilities" as NavPage, label: "Vulnerability Assessment", icon: ShieldAlert },
    { id: "scan_center" as NavPage, label: "Scan Center", icon: ScanLine },
    { id: "history" as NavPage, label: "Scan History", icon: History },
    { id: "reports" as NavPage, label: "Reports", icon: FileText },
    { id: "settings" as NavPage, label: "Settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#FFFFFF] border-r border-[#E5E5EA] flex flex-col justify-between h-screen select-none shrink-0 sticky top-0">
      {/* Brand Header */}
      <div>
        <div className="h-16 flex items-center px-5 border-b border-[#E5E5EA]/60">
          <VigiCoreLogo variant="full" size={32} />
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          <div className="px-3 pt-2 pb-1 text-[11px] font-semibold tracking-wider text-[#86868B] uppercase">
            Platform
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id || (item.id === "history" && currentPage === "scan_detail");

            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-[13px] font-medium transition-all duration-150 ${
                  isActive
                    ? "bg-[#007AFF] text-white shadow-sm"
                    : "text-[#1D1D1F] hover:bg-[#F5F5F7] text-left"
                }`}
              >
                <Icon
                  className={`w-4 h-4 stroke-[2] ${
                    isActive ? "text-white" : "text-[#86868B]"
                  }`}
                />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-[#E5E5EA]/60 m-2">
        <div className="bg-[#F5F5F7] rounded-xl p-3 flex items-center gap-3">
          <div
            className={`w-7 h-7 rounded-lg bg-white flex items-center justify-center shadow-xs ${
              systemHealthy ? "text-[#34C759]" : "text-[#FF3B30]"
            }`}
          >
            {systemHealthy ? (
              <ShieldCheck className="w-4 h-4 stroke-[2.5]" />
            ) : (
              <ShieldX className="w-4 h-4 stroke-[2.5]" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  systemHealthy ? "bg-[#34C759]" : "bg-[#FF3B30]"
                }`}
              />
              <p className="text-[12px] font-medium text-[#1D1D1F] truncate">
                {systemHealthy ? "Engine Active" : "Engine Offline"}
              </p>
            </div>
            <p className="text-[11px] text-[#86868B] truncate">
              VigiCore Scanner v1.0
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
};
