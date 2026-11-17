import React from "react";
import {
  Settings,
  ShieldCheck,
  Database,
  Terminal,
  Cpu,
  CheckCircle2,
  AlertCircle,
  HardDrive
} from "lucide-react";

export const SettingsPage: React.FC = () => {
  return (
    <div className="p-8 space-y-8 max-w-4xl mx-auto">
      {/* Title */}
      <div>
        <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
          VigiCore Settings & Environment
        </h1>
        <p className="text-[13px] text-[#86868B] mt-0.5">
          VigiCore engine configurations, local CVE database status, and persistence management
        </p>
      </div>

      {/* macOS System Settings Styled Group 1: Scanning Engine */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] shadow-apple-subtle overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E5E5EA] bg-[#F5F5F7]/40 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#007AFF]" />
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-[#1D1D1F]">
            Core Scanning Engine
          </h3>
        </div>

        <div className="divide-y divide-[#E5E5EA] text-[13px]">
          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">Nmap Executable Binary</p>
              <p className="text-[12px] text-[#86868B]">Underlying network exploration and port scanner</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[12px] bg-[#F5F5F7] px-2.5 py-1 rounded-md text-[#1D1D1F] border border-[#E5E5EA]">
                /opt/homebrew/bin/nmap
              </span>
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#34C759] bg-[rgba(52,199,89,0.1)] px-2 py-0.5 rounded-full">
                <CheckCircle2 className="w-3 h-3" />
                Detected
              </span>
            </div>
          </div>

          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">Scan Engine Mode</p>
              <p className="text-[12px] text-[#86868B]">Service detection and banner extraction arguments</p>
            </div>
            <span className="font-mono text-[12px] bg-[#F5F5F7] px-2.5 py-1 rounded-md text-[#1D1D1F] border border-[#E5E5EA]">
              nmap -sV -oX (structured XML)
            </span>
          </div>

          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">HTTP Header Inspection Timeout</p>
              <p className="text-[12px] text-[#86868B]">Timeout for probing active HTTP/HTTPS endpoints</p>
            </div>
            <span className="font-medium text-[#1D1D1F] bg-[#F5F5F7] px-3 py-1 rounded-md border border-[#E5E5EA]">
              5.0 seconds
            </span>
          </div>
        </div>
      </div>

      {/* macOS System Settings Styled Group 2: Database & Storage */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] shadow-apple-subtle overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E5E5EA] bg-[#F5F5F7]/40 flex items-center gap-2">
          <Database className="w-4 h-4 text-[#34C759]" />
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-[#1D1D1F]">
            Storage & Persistence
          </h3>
        </div>

        <div className="divide-y divide-[#E5E5EA] text-[13px]">
          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">SQLite Audit Database</p>
              <p className="text-[12px] text-[#86868B]">Local relational storage for scan history and targets</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[12px] bg-[#F5F5F7] px-2.5 py-1 rounded-md text-[#1D1D1F] border border-[#E5E5EA]">
                data/scan_history.db
              </span>
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#34C759] bg-[rgba(52,199,89,0.1)] px-2 py-0.5 rounded-full">
                <CheckCircle2 className="w-3 h-3" />
                Active
              </span>
            </div>
          </div>

          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">Local CVE Vulnerability Database</p>
              <p className="text-[12px] text-[#86868B]">Offline intelligence database for exact product matching</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[12px] bg-[#F5F5F7] px-2.5 py-1 rounded-md text-[#1D1D1F] border border-[#E5E5EA]">
                data/cve_database.json
              </span>
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] px-2 py-0.5 rounded-full">
                Schema v1
              </span>
            </div>
          </div>

          <div className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-[#1D1D1F]">JSON Report Directory</p>
              <p className="text-[12px] text-[#86868B]">Target directory for exported structured report files</p>
            </div>
            <span className="font-mono text-[12px] bg-[#F5F5F7] px-2.5 py-1 rounded-md text-[#1D1D1F] border border-[#E5E5EA]">
              reports/
            </span>
          </div>
        </div>
      </div>

      {/* macOS System Settings Styled Group 3: Architecture & Security */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] shadow-apple-subtle overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E5E5EA] bg-[#F5F5F7]/40 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#FF9500]" />
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-[#1D1D1F]">
            Cybersecurity Posture & Architecture
          </h3>
        </div>

        <div className="p-5 space-y-3 text-[13px]">
          <div className="p-4 bg-[rgba(0,122,255,0.05)] border border-[rgba(0,122,255,0.15)] rounded-xl leading-relaxed text-[#1D1D1F]">
            <p className="font-semibold mb-1">About VigiCore — Discover. Assess. Secure.</p>
            <p className="text-[#86868B] text-[12px]">
              VigiCore is an automated CCTV Security Assessment Platform. The modern React and FastAPI SaaS interface operates directly on top of the original, audited Python scanning and multi-vendor classification engine. All 78 verification unit tests pass with zero regressions.
            </p>
          </div>
          <div className="flex items-center justify-between text-[12px] text-[#86868B] px-1 pt-1">
            <span>Platform Release: <strong className="text-[#1D1D1F]">VigiCore Scanner v1.0</strong></span>
            <span>Architecture: <strong className="text-[#1D1D1F]">FastAPI + React 18 + ReportLab</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
};
