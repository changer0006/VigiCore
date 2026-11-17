import React, { useEffect, useState } from "react";
import {
  Server,
  Wifi,
  ShieldAlert,
  AlertOctagon,
  ShieldCheck,
  ChevronRight,
  RefreshCw,
  ScanLine,
  Radar
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area
} from "recharts";
import { MetricCard } from "../components/MetricCard";
import { OverviewStats } from "../types";
import { fetchOverviewStats } from "../api/client";
import { NavPage } from "../components/Sidebar";

interface OverviewDashboardProps {
  onNavigate: (page: NavPage) => void;
  onSelectScan: (scanId: number) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#FF3B30",
  HIGH: "#FF9500",
  MEDIUM: "#FFCC00",
  LOW: "#007AFF",
  INFO: "#34C759",
};

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  onNavigate,
  onSelectScan,
}) => {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchOverviewStats();
      setStats(data);
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard metrics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div className="h-6 w-48 bg-[#E5E5EA] animate-pulse rounded-md" />
          <div className="h-8 w-24 bg-[#E5E5EA] animate-pulse rounded-lg" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-32 bg-white border border-[#E5E5EA] rounded-[18px] animate-pulse p-5" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-72 bg-white border border-[#E5E5EA] rounded-[18px] animate-pulse" />
          <div className="h-72 bg-white border border-[#E5E5EA] rounded-[18px] animate-pulse" />
        </div>
      </div>
    );
  }

  // Fallback defaults if no scans yet
  const overview = stats || {
    total_discovered_devices: 0,
    online_devices: 0,
    vulnerable_devices: 0,
    critical_vulnerabilities: 0,
    overall_security_score: 100,
    severity_breakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    vendor_distribution: [],
    risk_trend: [],
    recent_scans: []
  };

  const donutData = Object.entries(overview.severity_breakdown).map(([name, value]) => ({
    name,
    value,
  })).filter(d => d.value > 0);

  // If donut has no findings, show a healthy "Clean" placeholder segment
  const finalDonutData = donutData.length > 0 ? donutData : [{ name: "No Vulnerabilities", value: 1 }];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner & Quick Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
            Security Operations Overview
          </h1>
          <p className="text-[13px] text-[#86868B] mt-0.5">
            Real-time security posture, asset health, and CCTV telemetry
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            title="Refresh metrics"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] rounded-xl hover:bg-[#F5F5F7] transition-colors shadow-xs"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#86868B]" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => onNavigate("discovery")}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-xs"
          >
            <Radar className="w-3.5 h-3.5" />
            <span>Discover Subnet</span>
          </button>
          <button
            onClick={() => onNavigate("scan_center")}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-[13px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] hover:bg-[rgba(0,122,255,0.14)] rounded-xl transition-all"
          >
            <ScanLine className="w-3.5 h-3.5" />
            <span>Scan Device</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-[rgba(255,59,48,0.08)] border border-[rgba(255,59,48,0.2)] rounded-xl p-4 text-[13px] text-[#FF3B30] flex items-center justify-between">
          <span>{error}</span>
          <button onClick={loadData} className="underline font-medium ml-4">Retry</button>
        </div>
      )}

      {/* 5 Elegant Apple Health Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Discovered Devices"
          value={overview.total_discovered_devices}
          subtitle="Identified across network"
          icon={Server}
          variant="blue"
        />
        <MetricCard
          title="Online Devices"
          value={overview.online_devices}
          subtitle="Responding to ping & probes"
          icon={Wifi}
          variant="green"
        />
        <MetricCard
          title="Vulnerable Devices"
          value={overview.vulnerable_devices}
          subtitle="Assets with flagged exposure"
          icon={ShieldAlert}
          variant="orange"
          badgeText={overview.vulnerable_devices > 0 ? "Review Required" : "Clean"}
        />
        <MetricCard
          title="Critical Findings"
          value={overview.critical_vulnerabilities}
          subtitle="Urgent remediation needs"
          icon={AlertOctagon}
          variant="red"
          badgeText={overview.critical_vulnerabilities > 0 ? "High Risk" : "0 Alert"}
        />
        <MetricCard
          title="Security Score"
          value={`${overview.overall_security_score}/100`}
          subtitle="Risk-adjusted health index"
          icon={ShieldCheck}
          variant={
            overview.overall_security_score >= 80
              ? "green"
              : overview.overall_security_score >= 50
              ? "orange"
              : "red"
          }
        />
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Donut Chart */}
        <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
                Vulnerability Breakdown
              </h3>
              <p className="text-[12px] text-[#86868B]">
                Distribution by severity level
              </p>
            </div>
            <button
              onClick={() => onNavigate("vulnerabilities")}
              className="text-[12px] font-medium text-[#007AFF] hover:underline"
            >
              View All
            </button>
          </div>

          <div className="h-56 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={finalDonutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={donutData.length > 1 ? 4 : 0}
                  dataKey="value"
                  stroke="#FFFFFF"
                  strokeWidth={2}
                >
                  {finalDonutData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={SEVERITY_COLORS[entry.name] || "#34C759"}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#FFFFFF",
                    borderRadius: "12px",
                    border: "1px solid #E5E5EA",
                    boxShadow: "0 4px 12px rgba(0,0,0,0.06)",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[20px] font-bold text-[#1D1D1F]">
                {donutData.reduce((acc, curr) => acc + curr.value, 0)}
              </span>
              <span className="text-[10px] text-[#86868B] uppercase tracking-wider">
                Findings
              </span>
            </div>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-3 gap-2 mt-2 pt-4 border-t border-[#E5E5EA]">
            {Object.entries(overview.severity_breakdown).map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: SEVERITY_COLORS[sev] }}
                />
                <span className="text-[11px] text-[#86868B] truncate">
                  {sev}: <strong className="text-[#1D1D1F]">{count}</strong>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Vendor Distribution Chart */}
        <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
                Manufacturer Distribution
              </h3>
              <p className="text-[12px] text-[#86868B]">
                Identified CCTV & DVR hardware
              </p>
            </div>
            <button
              onClick={() => onNavigate("inventory")}
              className="text-[12px] font-medium text-[#007AFF] hover:underline"
            >
              Inventory
            </button>
          </div>

          <div className="h-64">
            {overview.vendor_distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={overview.vendor_distribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#86868B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#86868B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#FFFFFF",
                      borderRadius: "12px",
                      border: "1px solid #E5E5EA",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.06)",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" fill="#007AFF" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center text-[#86868B]">
                <Server className="w-8 h-8 text-[#E5E5EA] mb-2" />
                <p className="text-[13px] font-medium">No Manufacturer Data</p>
                <p className="text-[11px]">Run discovery or scanning to map hardware vendors.</p>
              </div>
            )}
          </div>
        </div>

        {/* Historical Risk Trend Chart */}
        <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
                Risk Score Trajectory
              </h3>
              <p className="text-[12px] text-[#86868B]">
                Sequential audit scores (0-100)
              </p>
            </div>
            <button
              onClick={() => onNavigate("history")}
              className="text-[12px] font-medium text-[#007AFF] hover:underline"
            >
              History
            </button>
          </div>

          <div className="h-64">
            {overview.risk_trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={overview.risk_trend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="appleBlueGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#007AFF" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#007AFF" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="target" stroke="#86868B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis domain={[0, 100]} stroke="#86868B" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#FFFFFF",
                      borderRadius: "12px",
                      border: "1px solid #E5E5EA",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.06)",
                      fontSize: "12px",
                    }}
                  />
                  <Area type="monotone" dataKey="score" stroke="#007AFF" strokeWidth={2.5} fillOpacity={1} fill="url(#appleBlueGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center text-[#86868B]">
                <ShieldCheck className="w-8 h-8 text-[#E5E5EA] mb-2" />
                <p className="text-[13px] font-medium">No Historical Scans</p>
                <p className="text-[11px]">Audit records will generate your risk trajectory.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
              Recent Audit Activity
            </h3>
            <p className="text-[12px] text-[#86868B]">
              Latest security scans recorded in SQLite database
            </p>
          </div>
          <button
            onClick={() => onNavigate("history")}
            className="flex items-center gap-1 text-[13px] font-medium text-[#007AFF] hover:underline"
          >
            <span>View All Records</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {overview.recent_scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E5E5EA] text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                  <th className="py-3 px-4">Target IP</th>
                  <th className="py-3 px-4">Device Classification</th>
                  <th className="py-3 px-4">Vendor</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5EA]/70 text-[13px]">
                {overview.recent_scans.map((scan) => {
                  const level = scan.risk_level || "INFO";
                  const score = scan.risk_score || 0;

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-[#F5F5F7]/80 transition-colors cursor-pointer group"
                      onClick={() => onSelectScan(scan.id)}
                    >
                      <td className="py-3 px-4 font-medium text-[#1D1D1F]">
                        {scan.target}
                      </td>
                      <td className="py-3 px-4 text-[#1D1D1F]">
                        {scan.device_type || "Unknown"}
                      </td>
                      <td className="py-3 px-4 text-[#86868B]">
                        {scan.vendor || "Unknown"}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold"
                          style={{
                            backgroundColor: `${SEVERITY_COLORS[level]}15`,
                            color: SEVERITY_COLORS[level],
                          }}
                        >
                          {level}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-semibold text-[#1D1D1F]">
                        {score}
                        <span className="text-[11px] font-normal text-[#86868B]">
                          /100
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[#86868B] text-[12px]">
                        {scan.generated_at ? scan.generated_at.replace("T", " ").slice(0, 16) : "N/A"}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectScan(scan.id);
                          }}
                          className="px-2.5 py-1 text-[12px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] hover:bg-[rgba(0,122,255,0.15)] rounded-lg transition-colors"
                        >
                          View Report
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 flex flex-col items-center justify-center text-center text-[#86868B]">
            <Server className="w-10 h-10 text-[#E5E5EA] mb-3" />
            <p className="text-[14px] font-medium text-[#1D1D1F]">No Scan Records Found</p>
            <p className="text-[12px] max-w-sm mt-1">
              Start by discovering hosts on your network or running a targeted scan on an authorized CCTV IP address.
            </p>
            <button
              onClick={() => onNavigate("scan_center")}
              className="mt-4 px-4 py-2 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-xs"
            >
              Start First Scan
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
