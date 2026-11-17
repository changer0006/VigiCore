import React, { useState, useEffect } from "react";
import {
  Radar,
  Play,
  CheckCircle2,
  AlertCircle,
  Server,
  ScanLine,
  RefreshCw,
  Terminal,
  Clock,
  Wifi,
  Laptop
} from "lucide-react";
import {
  startNetworkDiscovery,
  pollDiscoveryTask,
  fetchDeviceInventory,
  fetchNetworkInfo
} from "../api/client";
import { DiscoveryTaskStatus, SystemNetworkInfo, DiscoveryHostItem } from "../types";

interface NetworkDiscoveryPageProps {
  onScanTarget: (ip: string) => void;
}

export const NetworkDiscoveryPage: React.FC<NetworkDiscoveryPageProps> = ({
  onScanTarget,
}) => {
  const [network, setNetwork] = useState("192.168.0.0/24");
  const [networkInfo, setNetworkInfo] = useState<SystemNetworkInfo | null>(null);
  const [networkInfoLoading, setNetworkInfoLoading] = useState(true);
  const [currentTask, setCurrentTask] = useState<DiscoveryTaskStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [discoveredList, setDiscoveredList] = useState<DiscoveryHostItem[]>([]);

  const loadNetworkTelemetry = () => {
    setNetworkInfoLoading(true);
    fetchNetworkInfo()
      .then((data) => {
        setNetworkInfo(data);
        if (data.cidr) {
          setNetwork(data.cidr);
        }
      })
      .catch((err) => {
        console.error("Failed to load network telemetry:", err);
      })
      .finally(() => {
        setNetworkInfoLoading(false);
      });
  };

  // Load telemetry and existing inventory on mount
  useEffect(() => {
    loadNetworkTelemetry();

    fetchDeviceInventory()
      .then((data) => {
        if (data.devices.length > 0) {
          setDiscoveredList(
            data.devices.map((d) => ({
              ip: d.ip,
              mac: d.mac !== "Unknown" ? d.mac : null,
              vendor: d.vendor !== "Unknown" ? d.vendor : null,
            }))
          );
        }
      })
      .catch(() => {});
  }, []);


  // Polling active discovery task
  useEffect(() => {
    if (!currentTask || currentTask.status === "completed" || currentTask.status === "failed") {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const update = await pollDiscoveryTask(currentTask.task_id);
        setCurrentTask(update);

        if (update.status === "completed" && update.result) {
          setDiscoveredList(update.result);
          setLoading(false);
        } else if (update.status === "failed") {
          setError(update.error || "Discovery failed");
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.message);
        setLoading(false);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [currentTask]);

  const handleStartDiscovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!network.trim()) return;

    setError(null);
    setLoading(true);

    try {
      const resp = await startNetworkDiscovery(network.trim());
      setCurrentTask({
        task_id: resp.task_id,
        network: resp.network,
        status: "pending",
        stage: "queued",
        progress: 10,
        logs: [`[${new Date().toLocaleTimeString()}] Subnet sweep queued for ${resp.network}`],
      });
    } catch (err: any) {
      setError(err.message || "Failed to start network discovery");
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
            Network Host Discovery
          </h1>
          <p className="text-[13px] text-[#86868B] mt-0.5">
            Dynamic macOS network telemetry and automated Nmap ping sweeps (-sn)
          </p>
        </div>

        <button
          onClick={loadNetworkTelemetry}
          className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] rounded-xl hover:bg-[#F5F5F7] transition-colors shadow-xs w-fit"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#86868B] ${networkInfoLoading ? "animate-spin" : ""}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Dynamic macOS Network Telemetry Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-5 shadow-apple-subtle">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#E5E5EA]">
          <div className="flex items-center gap-2">
            <Laptop className="w-4 h-4 text-[#007AFF]" />
            <h2 className="text-[14px] font-semibold text-[#1D1D1F]">Active Network Environment</h2>
          </div>
          {networkInfo?.ssid && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-[rgba(0,122,255,0.08)] text-[#007AFF]">
              <Wifi className="w-3 h-3" />
              <span>Wi-Fi: {networkInfo.ssid}</span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-[13px]">
          <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/60">
            <span className="text-[11px] font-medium text-[#86868B] block">Active Interface</span>
            <span className="font-semibold text-[#1D1D1F] mt-0.5 block font-mono">
              {networkInfo?.active_interface || "Detecting..."}
            </span>
            <span className="text-[11px] text-[#34C759] mt-0.5 block font-medium">● Connected</span>
          </div>

          <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/60">
            <span className="text-[11px] font-medium text-[#86868B] block">MacBook IP (Local)</span>
            <span className="font-semibold text-[#1D1D1F] mt-0.5 block font-mono">
              {networkInfo?.ip || "Detecting..."}
            </span>
            <span className="text-[11px] text-[#86868B] mt-0.5 block font-mono truncate">
              {networkInfo?.mac || "Hardware MAC"}
            </span>
          </div>

          <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/60">
            <span className="text-[11px] font-medium text-[#86868B] block">Router Gateway</span>
            <span className="font-semibold text-[#1D1D1F] mt-0.5 block font-mono">
              {networkInfo?.gateway || "Detecting..."}
            </span>
            <span className="text-[11px] text-[#86868B] mt-0.5 block">Default Route</span>
          </div>

          <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/60">
            <span className="text-[11px] font-medium text-[#86868B] block">Calculated Subnet</span>
            <div className="flex items-center justify-between mt-0.5">
              <span className="font-semibold text-[#007AFF] font-mono">
                {networkInfo?.cidr || "192.168.0.0/24"}
              </span>
              {networkInfo?.cidr && network !== networkInfo.cidr && (
                <button
                  type="button"
                  onClick={() => setNetwork(networkInfo.cidr!)}
                  className="text-[10px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.1)] px-1.5 py-0.5 rounded hover:bg-[rgba(0,122,255,0.2)]"
                >
                  Use
                </button>
              )}
            </div>
            <span className="text-[11px] text-[#86868B] mt-0.5 block truncate">
              Netmask: {networkInfo?.netmask || "255.255.255.0"}
            </span>
          </div>
        </div>

        {/* Nmap Engine Status Banner */}
        <div className="mt-4 pt-3 border-t border-[#E5E5EA] flex items-center justify-between text-[12px]">
          <div className="flex items-center gap-2">
            <span className="text-[#86868B]">Discovery Engine:</span>
            {networkInfo?.nmap?.installed ? (
              <span className="inline-flex items-center gap-1.5 text-[#34C759] font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Nmap v{networkInfo.nmap.version || "7.x"}</span>
                <span className="text-[#86868B] font-normal">•</span>
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-[rgba(0,122,255,0.08)] text-[#007AFF]">
                  {networkInfo.nmap.privileged_available ? "Privileged ARP Active" : "Unprivileged Kernel-ARP Active"}
                </span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[#FF9500] font-medium">
                <AlertCircle className="w-3.5 h-3.5" />
                <span>Checking or unavailable</span>
              </span>
            )}
          </div>
          {networkInfo?.nmap?.path && (
            <span className="text-[#86868B] font-mono text-[11px] hidden sm:inline">
              {networkInfo.nmap.path}
            </span>
          )}
        </div>
      </div>

      {/* Discovery Input Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        <form onSubmit={handleStartDiscovery} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div className="md:col-span-3">
              <label className="block text-[12px] font-medium text-[#1D1D1F] mb-1.5 uppercase tracking-wider">
                Authorized Network CIDR
              </label>
              <div className="relative">
                <Radar className="w-4 h-4 text-[#86868B] absolute left-3.5 top-1/2 -translate-y-1/2 stroke-[2]" />
                <input
                  type="text"
                  value={network}
                  onChange={(e) => setNetwork(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/24"
                  disabled={loading}
                  className="w-full bg-[#F5F5F7] text-[13px] text-[#1D1D1F] placeholder-[#86868B] pl-10 pr-4 py-2.5 rounded-xl border border-transparent focus:border-[#007AFF] focus:bg-white focus:outline-none transition-all disabled:opacity-60"
                />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className="text-[11px] text-[#86868B]">Common Subnets:</span>
                {["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"].map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => setNetwork(preset)}
                    className="text-[11px] text-[#007AFF] hover:underline bg-[rgba(0,122,255,0.06)] px-2 py-0.5 rounded-md"
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full h-[42px] flex items-center justify-center gap-2 px-4 py-2.5 bg-[#007AFF] hover:bg-[#0062CC] text-white text-[13px] font-medium rounded-xl transition-all shadow-xs disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin stroke-[2]" />
                    <span>Discovering...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white stroke-[0]" />
                    <span>Start Discovery</span>
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

        {/* Progress & Live Stepper */}
        {currentTask && (
          <div className="mt-6 pt-6 border-t border-[#E5E5EA] space-y-3">
            <div className="flex items-center justify-between text-[13px]">
              <div className="flex items-center gap-2">
                {currentTask.status === "completed" ? (
                  <CheckCircle2 className="w-4 h-4 text-[#34C759]" />
                ) : currentTask.status === "failed" ? (
                  <AlertCircle className="w-4 h-4 text-[#FF3B30]" />
                ) : (
                  <Clock className="w-4 h-4 text-[#007AFF] animate-pulse" />
                )}
                <span
                  className={`font-semibold capitalize ${
                    currentTask.status === "failed"
                      ? "text-[#FF3B30]"
                      : "text-[#1D1D1F]"
                  }`}
                >
                  {currentTask.status === "failed"
                    ? "Discovery Failed"
                    : currentTask.stage.replace("_", " ")}
                </span>
                <span className="text-[#86868B]">({currentTask.network})</span>
              </div>
              <span
                className={`font-semibold ${
                  currentTask.status === "failed"
                    ? "text-[#FF3B30]"
                    : "text-[#007AFF]"
                }`}
              >
                {currentTask.status === "failed" ? "Failed" : `${currentTask.progress}%`}
              </span>
            </div>

            {/* Apple-style smooth progress bar */}
            <div className="w-full bg-[#E5E5EA] h-2 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  currentTask.status === "failed"
                    ? "bg-[#FF3B30]"
                    : currentTask.status === "completed"
                    ? "bg-[#34C759]"
                    : "bg-[#007AFF]"
                }`}
                style={{ width: `${currentTask.progress}%` }}
              />
            </div>

            {/* Live Terminal Logs */}
            {currentTask.logs.length > 0 && (
              <div className="bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl p-3 font-mono text-[11px] text-[#1D1D1F] max-h-32 overflow-y-auto space-y-1">
                <div className="flex items-center gap-1.5 text-[#86868B] pb-1 border-b border-[#E5E5EA] font-sans font-medium">
                  <Terminal className="w-3 h-3" />
                  <span>Nmap Engine Log Stream</span>
                </div>
                {currentTask.logs.map((log, idx) => (
                  <div key={idx} className="leading-relaxed truncate">
                    {log}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Discovered Hosts Table */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-[15px] font-semibold text-[#1D1D1F]">
              Discovered Network Hosts
            </h3>
            <p className="text-[12px] text-[#86868B]">
              {discoveredList.length} active IP address(es) identified
            </p>
          </div>
        </div>

        {discoveredList.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E5E5EA] text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                  <th className="py-3 px-4">IPv4 Address</th>
                  <th className="py-3 px-4">Hardware MAC</th>
                  <th className="py-3 px-4">Hardware OUI / Vendor</th>
                  <th className="py-3 px-4">Discovery Technique</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Audit Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5EA]/70 text-[13px]">
                {discoveredList.map((host, idx) => (
                  <tr key={idx} className="hover:bg-[#F5F5F7]/80 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-[#1D1D1F]">
                      {host.ip}
                    </td>
                    <td className="py-3 px-4 font-mono text-[#86868B] text-[12px]">
                      {host.mac || "Not Broadcast / Local"}
                    </td>
                    <td className="py-3 px-4 text-[#1D1D1F]">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-[#F5F5F7] text-[#1D1D1F] border border-[#E5E5EA]">
                        {host.vendor || "Generic Hardware"}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-medium ${
                          host.discovery_method === "privileged_arp"
                            ? "bg-[rgba(52,199,89,0.1)] text-[#15803D]"
                            : host.discovery_method === "local_telemetry"
                            ? "bg-[rgba(175,82,222,0.1)] text-[#7E22CE]"
                            : "bg-[rgba(0,122,255,0.08)] text-[#007AFF]"
                        }`}
                      >
                        {host.discovery_type || (host.discovery_method === "privileged_arp" ? "Full ARP (Layer 2)" : "Kernel-ARP (Layer 2/3)")}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-[rgba(52,199,89,0.1)] text-[#34C759]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#34C759]" />
                        Active
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onScanTarget(host.ip)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-xs"
                      >
                        <ScanLine className="w-3.5 h-3.5" />
                        <span>Run Full Scan</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 flex flex-col items-center justify-center text-center text-[#86868B]">
            <Server className="w-10 h-10 text-[#E5E5EA] mb-3" />
            <p className="text-[14px] font-medium text-[#1D1D1F]">No Hosts Discovered Yet</p>
            <p className="text-[12px] max-w-sm mt-1">
              Enter your subnet range above and click "Start Discovery" to run an automated sweep.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
