import React, { useState, useEffect } from "react";
import {
  ScanLine,
  Play,
  CheckCircle2,
  AlertCircle,
  Clock,
  Terminal,
  ShieldCheck,
  ShieldAlert,
  Server,
  Layers,
  FileText,
  ExternalLink,
  ChevronRight
} from "lucide-react";
import { startHostScan, pollScanTask } from "../api/client";
import { ScanTaskStatus } from "../types";

interface ScanCenterPageProps {
  initialTarget?: string;
  onSelectScan: (scanId: number) => void;
}

const STAGES = [
  { key: "service_scanning", label: "Nmap Port & Service Scan (-sV)" },
  { key: "fingerprinting", label: "CCTV/DVR Device Fingerprinting" },
  { key: "vulnerability_assessment", label: "HTTP Header Audit & Local CVE Correlation" },
  { key: "saving", label: "Risk Scoring & Database Persistence" },
  { key: "completed", label: "Audit Completed" },
];

export const ScanCenterPage: React.FC<ScanCenterPageProps> = ({
  initialTarget = "",
  onSelectScan,
}) => {
  const [target, setTarget] = useState(initialTarget || "192.168.1.20");
  const [currentTask, setCurrentTask] = useState<ScanTaskStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialTarget) {
      setTarget(initialTarget);
    }
  }, [initialTarget]);

  // Polling active scan task
  useEffect(() => {
    if (!currentTask || currentTask.status === "completed" || currentTask.status === "failed") {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const update = await pollScanTask(currentTask.task_id);
        setCurrentTask(update);

        if (update.status === "completed") {
          setLoading(false);
        } else if (update.status === "failed") {
          setError(update.error || "Scan execution failed");
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.message);
        setLoading(false);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [currentTask]);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setError(null);
    setLoading(true);

    try {
      const resp = await startHostScan(target.trim());
      setCurrentTask({
        task_id: resp.task_id,
        target: resp.target,
        status: "pending",
        stage: "service_scanning",
        progress: 10,
        message: "Initiating Nmap service detection...",
        logs: [`[${new Date().toLocaleTimeString()}] Scan launched for target ${resp.target}`],
        scan_id: null,
      });
    } catch (err: any) {
      setError(err.message || "Failed to launch scan");
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div>
        <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
          Scan & Audit Center
        </h1>
        <p className="text-[13px] text-[#86868B] mt-0.5">
          Execute structured security scans, service detection, device classification, and CVE candidate matching
        </p>
      </div>

      {/* Target Input Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        <form onSubmit={handleLaunchScan} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div className="md:col-span-3">
              <label className="block text-[12px] font-medium text-[#1D1D1F] mb-1.5 uppercase tracking-wider">
                Target Device IPv4 Address
              </label>
              <div className="relative">
                <Server className="w-4 h-4 text-[#86868B] absolute left-3.5 top-1/2 -translate-y-1/2 stroke-[2]" />
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.20"
                  disabled={loading}
                  className="w-full bg-[#F5F5F7] text-[13px] text-[#1D1D1F] placeholder-[#86868B] pl-10 pr-4 py-2.5 rounded-xl border border-transparent focus:border-[#007AFF] focus:bg-white focus:outline-none transition-all disabled:opacity-60"
                />
              </div>
              <p className="text-[11px] text-[#86868B] mt-2">
                Only scan CCTV cameras, NVRs, and devices you own or have explicit written permission to assess.
              </p>
            </div>

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full h-[42px] flex items-center justify-center gap-2 px-4 py-2.5 bg-[#007AFF] hover:bg-[#0062CC] text-white text-[13px] font-medium rounded-xl transition-all shadow-xs disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <Clock className="w-4 h-4 animate-spin stroke-[2]" />
                    <span>Auditing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white stroke-[0]" />
                    <span>Launch Audit</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        {error && (
          <div className="mt-4 bg-[rgba(255,59,48,0.08)] border border-[rgba(255,59,48,0.2)] rounded-xl p-3.5 text-[13px] text-[#FF3B30] flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Real-time Stepper & Progress */}
      {currentTask && (
        <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-[rgba(0,122,255,0.08)] flex items-center justify-center text-[#007AFF]">
                <ScanLine className="w-4 h-4 stroke-[2]" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
                  Auditing Target: {currentTask.target}
                </h3>
                <p className="text-[12px] text-[#86868B]">
                  Task ID: <span className="font-mono">{currentTask.task_id}</span>
                </p>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[20px] font-bold text-[#007AFF]">
                {currentTask.progress}%
              </span>
              <p className="text-[11px] font-medium uppercase tracking-wider text-[#86868B]">
                {currentTask.status}
              </p>
            </div>
          </div>

          {/* Apple Progress Bar */}
          <div className="w-full bg-[#E5E5EA] h-2.5 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                currentTask.status === "completed"
                  ? "bg-[#34C759]"
                  : currentTask.status === "failed"
                  ? "bg-[#FF3B30]"
                  : "bg-[#007AFF]"
              }`}
              style={{ width: `${currentTask.progress}%` }}
            />
          </div>

          {/* Stepper Stages */}
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 pt-2">
            {STAGES.map((s, idx) => {
              const isPast =
                currentTask.status === "completed" ||
                (s.key === "service_scanning" && currentTask.progress > 20) ||
                (s.key === "fingerprinting" && currentTask.progress > 50) ||
                (s.key === "vulnerability_assessment" && currentTask.progress > 75) ||
                (s.key === "saving" && currentTask.progress >= 90);

              const isCurrent = currentTask.stage === s.key;

              return (
                <div
                  key={s.key}
                  className={`p-3 rounded-xl border transition-all text-center ${
                    isPast
                      ? "bg-[rgba(52,199,89,0.06)] border-[rgba(52,199,89,0.25)] text-[#1D1D1F]"
                      : isCurrent
                      ? "bg-[rgba(0,122,255,0.08)] border-[#007AFF] text-[#007AFF]"
                      : "bg-[#F5F5F7] border-[#E5E5EA] text-[#86868B]"
                  }`}
                >
                  <div className="text-[10px] font-semibold uppercase tracking-wider mb-1">
                    Stage {idx + 1}
                  </div>
                  <p className="text-[11px] font-medium leading-tight">
                    {s.label}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Completion Summary Card */}
          {currentTask.status === "completed" && (
            <div className="bg-[rgba(52,199,89,0.08)] border border-[rgba(52,199,89,0.25)] rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-7 h-7 text-[#34C759] shrink-0" />
                <div>
                  <h4 className="text-[15px] font-semibold text-[#1D1D1F]">
                    Security Assessment Complete
                  </h4>
                  <p className="text-[12px] text-[#86868B]">
                    {currentTask.message || "All checks executed and stored in SQLite database."}
                  </p>
                </div>
              </div>

              {currentTask.scan_id && (
                <button
                  onClick={() => onSelectScan(currentTask.scan_id!)}
                  className="px-4 py-2 bg-[#007AFF] hover:bg-[#0062CC] text-white text-[13px] font-semibold rounded-xl transition-all shadow-xs flex items-center justify-center gap-1.5 shrink-0"
                >
                  <span>View Full Report</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              )}
            </div>
          )}

          {/* Live Activity Logs */}
          <div className="bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl p-4 font-mono text-[12px] text-[#1D1D1F] space-y-1.5">
            <div className="flex items-center justify-between text-[#86868B] pb-2 border-b border-[#E5E5EA] font-sans font-medium text-[11px]">
              <div className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                <span>Engine Execution Stream</span>
              </div>
              <span>Real-time</span>
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1 pt-1">
              {currentTask.logs.map((log, i) => (
                <div key={i} className="leading-relaxed">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
