import React, { useState, useEffect } from "react";
import {
  Server,
  Search,
  ScanLine,
  RefreshCw,
  Eye,
  Tag,
  Check,
  Cpu,
  Info,
  X,
  ShieldCheck,
  AlertCircle,
  HelpCircle
} from "lucide-react";
import { AssetRecord } from "../types";
import {
  fetchAssets,
  overrideAssetCategory,
  identifySingleAsset,
  identifyAllAssets
} from "../api/client";

interface AssetInventoryPageProps {
  onScanTarget: (ip: string) => void;
  onSelectScan: (scanId: number) => void;
}

const SEVERITY_BADGES: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "bg-[rgba(255,59,48,0.08)]", text: "text-[#FF3B30]" },
  HIGH: { bg: "bg-[rgba(255,149,0,0.1)]", text: "text-[#FF9500]" },
  MEDIUM: { bg: "bg-[rgba(255,204,0,0.14)]", text: "text-[#B28900]" },
  LOW: { bg: "bg-[rgba(0,122,255,0.08)]", text: "text-[#007AFF]" },
  INFO: { bg: "bg-[rgba(52,199,89,0.1)]", text: "text-[#34C759]" },
};

const CONFIDENCE_BADGES: Record<string, { bg: string; text: string }> = {
  High: { bg: "bg-[rgba(52,199,89,0.1)]", text: "text-[#34C759]" },
  Medium: { bg: "bg-[rgba(255,149,0,0.1)]", text: "text-[#FF9500]" },
  Low: { bg: "bg-[rgba(0,122,255,0.08)]", text: "text-[#007AFF]" },
  Unknown: { bg: "bg-[#F5F5F7]", text: "text-[#86868B]" },
};

const CATEGORY_OPTIONS = [
  "IP CCTV Camera",
  "DVR",
  "NVR",
  "Router",
  "Computer",
  "Mobile",
  "Printer",
  "Other",
  "Unknown"
];

export const AssetInventoryPage: React.FC<AssetInventoryPageProps> = ({
  onScanTarget,
  onSelectScan,
}) => {
  const [devices, setDevices] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [identifyingAll, setIdentifyingAll] = useState(false);
  const [identifyingId, setIdentifyingId] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [vendorFilter, setVendorFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [editingAssetId, setEditingAssetId] = useState<number | null>(null);
  const [editCategoryVal, setEditCategoryVal] = useState("");
  const [selectedAssetForEvidence, setSelectedAssetForEvidence] = useState<AssetRecord | null>(null);

  const loadInventory = async () => {
    setLoading(true);
    try {
      const data = await fetchAssets();
      setDevices(data.assets || (data.devices as any) || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInventory();
  }, []);

  const handleIdentifyAll = async () => {
    setIdentifyingAll(true);
    try {
      await identifyAllAssets();
      await loadInventory();
    } catch (err) {
      console.error("Failed to run batch identification:", err);
    } finally {
      setIdentifyingAll(false);
    }
  };

  const handleIdentifySingle = async (assetId: number) => {
    setIdentifyingId(assetId);
    try {
      const res = await identifySingleAsset(assetId);
      if (selectedAssetForEvidence && selectedAssetForEvidence.id === assetId) {
        setSelectedAssetForEvidence(res.asset);
      }
      await loadInventory();
    } catch (err) {
      console.error("Failed to identify asset:", err);
    } finally {
      setIdentifyingId(null);
    }
  };

  const handleOverride = async (assetId: number, category: string) => {
    if (!category.trim()) return;
    try {
      const res = await overrideAssetCategory(assetId, category.trim());
      setEditingAssetId(null);
      if (selectedAssetForEvidence && selectedAssetForEvidence.id === assetId) {
        setSelectedAssetForEvidence(res.asset);
      }
      await loadInventory();
    } catch (err) {
      console.error("Failed to override category:", err);
    }
  };

  const vendors = Array.from(new Set(devices.map((d) => d.vendor || "Unknown"))).filter(Boolean);

  const filtered = devices.filter((d) => {
    const matchesSearch =
      d.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (d.effective_category || d.device_type || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (d.model || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (d.mac || "").toLowerCase().includes(searchTerm.toLowerCase());
    const matchesVendor = vendorFilter === "ALL" || d.vendor === vendorFilter;
    const matchesCategory =
      categoryFilter === "ALL" ||
      (d.effective_category || d.device_type) === categoryFilter;

    return matchesSearch && matchesVendor && matchesCategory;
  });

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title & Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[#1D1D1F]">
            Asset Inventory
          </h1>
          <p className="text-[13px] text-[#86868B] mt-0.5">
            Multi-vendor CCTV, NVR, DVR, and endpoint classification registry
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleIdentifyAll}
            disabled={identifyingAll || loading || devices.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-all shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Cpu className={`w-3.5 h-3.5 ${identifyingAll ? "animate-spin" : ""}`} />
            <span>{identifyingAll ? "Identifying Network..." : "Identify All Devices"}</span>
          </button>

          <button
            onClick={loadInventory}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] rounded-xl hover:bg-[#F5F5F7] transition-colors shadow-xs w-fit"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#86868B] ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-4 shadow-apple-subtle flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-[#86868B] absolute left-3 top-1/2 -translate-y-1/2 stroke-[2]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by IP, vendor, model, or category..."
            className="w-full bg-[#F5F5F7] text-[13px] text-[#1D1D1F] placeholder-[#86868B] pl-9 pr-3 py-2 rounded-xl border border-transparent focus:border-[#007AFF] focus:bg-white focus:outline-none transition-all"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          <div className="flex items-center gap-1.5 text-[12px] text-[#86868B]">
            <span>Category:</span>
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-[#F5F5F7] text-[12px] font-medium text-[#1D1D1F] px-3 py-1.5 rounded-lg border border-[#E5E5EA] focus:outline-none focus:border-[#007AFF]"
          >
            <option value="ALL">All Categories</option>
            {CATEGORY_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <div className="flex items-center gap-1.5 text-[12px] text-[#86868B]">
            <span>Vendor:</span>
          </div>
          <select
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
            className="bg-[#F5F5F7] text-[12px] font-medium text-[#1D1D1F] px-3 py-1.5 rounded-lg border border-[#E5E5EA] focus:outline-none focus:border-[#007AFF]"
          >
            <option value="ALL">All Manufacturers</option>
            {vendors.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Inventory Table Card */}
      <div className="bg-white border border-[#E5E5EA] rounded-[18px] p-6 shadow-apple-subtle">
        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E5E5EA] text-[11px] font-semibold text-[#86868B] uppercase tracking-wider">
                  <th className="py-3 px-4">Device / IP</th>
                  <th className="py-3 px-4">Hardware MAC</th>
                  <th className="py-3 px-4">Manufacturer</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Model</th>
                  <th className="py-3 px-4">Open Ports</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E5EA]/70 text-[13px]">
                {filtered.map((item) => {
                  const confBadge = CONFIDENCE_BADGES[item.confidence_level] || CONFIDENCE_BADGES.Unknown;
                  const isEditing = editingAssetId === item.id;
                  const isIdentifying = identifyingId === item.id;

                  return (
                    <tr key={item.ip} className="hover:bg-[#F5F5F7]/80 transition-colors group">
                      <td className="py-3.5 px-4">
                        <span className="font-mono font-medium text-[#1D1D1F] block">
                          {item.ip}
                        </span>
                        {item.hostname && (
                          <span className="text-[11px] text-[#86868B] block truncate max-w-[140px]">
                            {item.hostname}
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#86868B] text-[12px]">
                        {item.mac || "Unknown"}
                      </td>
                      <td className="py-3.5 px-4 text-[#1D1D1F] font-medium">
                        {item.vendor || "Unknown"}
                      </td>
                      <td className="py-3.5 px-4">
                        {isEditing ? (
                          <div className="flex items-center gap-1.5">
                            <select
                              value={editCategoryVal}
                              onChange={(e) => setEditCategoryVal(e.target.value)}
                              className="bg-white text-[11px] font-medium text-[#1D1D1F] px-2 py-1 rounded border border-[#007AFF] focus:outline-none"
                            >
                              {CATEGORY_OPTIONS.map((opt) => (
                                <option key={opt} value={opt}>
                                  {opt}
                                </option>
                              ))}
                            </select>
                            <button
                              onClick={() => handleOverride(item.id, editCategoryVal)}
                              className="p-1 text-[#34C759] hover:bg-[rgba(52,199,89,0.1)] rounded"
                              title="Save classification"
                            >
                              <Check className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setEditingAssetId(null)}
                              className="p-1 text-[#86868B] hover:bg-[#F5F5F7] rounded text-[11px]"
                            >
                              ✕
                            </button>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-[11px] font-medium bg-[#F5F5F7] text-[#1D1D1F] border border-[#E5E5EA]">
                              {item.effective_category || item.device_type || "Unknown"}
                            </span>
                            {item.manual_override_category && (
                              <span className="text-[10px] text-[#007AFF] font-medium bg-[rgba(0,122,255,0.08)] px-1 py-0.2 rounded">
                                custom
                              </span>
                            )}
                            <button
                              onClick={() => {
                                setEditingAssetId(item.id);
                                setEditCategoryVal(item.effective_category || item.device_type || "IP CCTV Camera");
                              }}
                              className="opacity-0 group-hover:opacity-100 hover:text-[#007AFF] text-[#86868B] p-0.5 transition-opacity"
                              title="Change classification"
                            >
                              <Tag className="w-3 h-3" />
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold ${confBadge.bg} ${confBadge.text}`}>
                          <span>{item.confidence_level || "Unknown"}</span>
                          <span className="text-[10px] opacity-75">({item.confidence_score || 0})</span>
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[12px] text-[#1D1D1F]">
                        {item.model || <span className="text-[#86868B] font-sans text-[11px]">-</span>}
                      </td>
                      <td className="py-3.5 px-4">
                        {item.open_ports && item.open_ports.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {item.open_ports.slice(0, 3).map((p) => (
                              <span
                                key={p}
                                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#F5F5F7] text-[#1D1D1F] border border-[#E5E5EA]"
                              >
                                {p}
                              </span>
                            ))}
                            {item.open_ports.length > 3 && (
                              <span className="text-[10px] text-[#86868B] self-center">
                                +{item.open_ports.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-[11px] text-[#86868B]">None reported</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedAssetForEvidence(item)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium text-[#1D1D1F] bg-white border border-[#E5E5EA] hover:bg-[#F5F5F7] rounded-lg transition-colors"
                            title="View identification evidence"
                          >
                            <Info className="w-3.5 h-3.5 text-[#007AFF]" />
                            <span>Evidence</span>
                          </button>

                          <button
                            onClick={() => handleIdentifySingle(item.id)}
                            disabled={isIdentifying}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium text-[#007AFF] bg-[rgba(0,122,255,0.08)] hover:bg-[rgba(0,122,255,0.15)] rounded-lg transition-colors disabled:opacity-50"
                            title="Re-run multi-vendor identification engine"
                          >
                            <Cpu className={`w-3.5 h-3.5 ${isIdentifying ? "animate-spin" : ""}`} />
                            <span>Identify</span>
                          </button>

                          <button
                            onClick={() => onScanTarget(item.ip)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium text-[#1D1D1F] bg-[#F5F5F7] hover:bg-[#E5E5EA] border border-[#E5E5EA] rounded-lg transition-colors"
                          >
                            <ScanLine className="w-3.5 h-3.5 text-[#86868B]" />
                            <span>Scan</span>
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
            <Server className="w-10 h-10 text-[#E5E5EA] mb-3" />
            <p className="text-[14px] font-medium text-[#1D1D1F]">No Matching Devices</p>
            <p className="text-[12px] max-w-sm mt-1">
              {devices.length === 0
                ? "No devices discovered yet. Go to Network Discovery to populate your asset inventory."
                : "Try adjusting your search terms or filters to locate assets."}
            </p>
          </div>
        )}
      </div>

      {/* Identification Evidence Modal */}
      {selectedAssetForEvidence && (
        <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-[#E5E5EA] rounded-[22px] max-w-2xl w-full p-6 shadow-2xl space-y-5 animate-in fade-in duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-3 border-b border-[#E5E5EA]">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-[#007AFF]" />
                <div>
                  <h3 className="text-[16px] font-semibold text-[#1D1D1F]">
                    Identification Evidence Breakdown
                  </h3>
                  <span className="font-mono text-[12px] text-[#86868B]">
                    {selectedAssetForEvidence.ip} • {selectedAssetForEvidence.mac || "Unknown MAC"}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedAssetForEvidence(null)}
                className="p-1 rounded-lg text-[#86868B] hover:text-[#1D1D1F] hover:bg-[#F5F5F7] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Classification & Confidence Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[13px]">
              <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/70">
                <span className="text-[11px] font-medium text-[#86868B] block">Effective Category</span>
                <span className="font-semibold text-[#1D1D1F] mt-0.5 block truncate">
                  {selectedAssetForEvidence.effective_category || selectedAssetForEvidence.device_type}
                </span>
                {selectedAssetForEvidence.manual_override_category && (
                  <span className="text-[10px] text-[#007AFF] font-medium">User Override</span>
                )}
              </div>

              <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/70">
                <span className="text-[11px] font-medium text-[#86868B] block">Manufacturer</span>
                <span className="font-semibold text-[#1D1D1F] mt-0.5 block truncate">
                  {selectedAssetForEvidence.vendor || "Unknown"}
                </span>
              </div>

              <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/70">
                <span className="text-[11px] font-medium text-[#86868B] block">Model Detected</span>
                <span className="font-semibold text-[#1D1D1F] mt-0.5 block truncate font-mono text-[12px]">
                  {selectedAssetForEvidence.model || "None"}
                </span>
              </div>

              <div className="p-3 bg-[#F5F5F7] rounded-xl border border-[#E5E5EA]/70">
                <span className="text-[11px] font-medium text-[#86868B] block">Confidence Level</span>
                <span className="font-semibold text-[#007AFF] mt-0.5 block">
                  {selectedAssetForEvidence.confidence_level} ({selectedAssetForEvidence.confidence_score}/100)
                </span>
              </div>
            </div>

            {/* Supporting Evidence List */}
            <div className="space-y-2">
              <h4 className="text-[12px] font-semibold text-[#1D1D1F] uppercase tracking-wider flex items-center gap-1.5">
                <Check className="w-3.5 h-3.5 text-[#34C759]" />
                <span>Supporting Evidence Signals</span>
              </h4>
              {selectedAssetForEvidence.evidence && selectedAssetForEvidence.evidence.length > 0 ? (
                <div className="bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl p-3 space-y-1.5 max-h-40 overflow-y-auto">
                  {selectedAssetForEvidence.evidence.map((item, idx) => (
                    <div key={idx} className="text-[12px] text-[#1D1D1F] flex items-start gap-2">
                      <span className="text-[#34C759] font-bold">✓</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 bg-[#F5F5F7] rounded-xl text-[12px] text-[#86868B]">
                  No authoritative fingerprints confirmed yet. Click "Identify" to execute active fingerprinting.
                </div>
              )}
            </div>

            {/* Inconclusive Signals */}
            <div className="space-y-2">
              <h4 className="text-[12px] font-semibold text-[#86868B] uppercase tracking-wider flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-[#86868B]" />
                <span>Inconclusive or Absent Signals</span>
              </h4>
              {selectedAssetForEvidence.inconclusive_signals && selectedAssetForEvidence.inconclusive_signals.length > 0 ? (
                <div className="bg-[#F5F5F7] border border-[#E5E5EA] rounded-xl p-3 space-y-1.5 max-h-32 overflow-y-auto">
                  {selectedAssetForEvidence.inconclusive_signals.map((item, idx) => (
                    <div key={idx} className="text-[11px] text-[#86868B] flex items-start gap-2">
                      <span className="text-[#86868B]">○</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-2.5 text-[11px] text-[#86868B]">
                  No absent or conflicting signals recorded.
                </div>
              )}
            </div>

            {/* Manual Override Quick Action */}
            <div className="pt-3 border-t border-[#E5E5EA] flex items-center justify-between">
              <div className="flex items-center gap-2 text-[12px]">
                <Tag className="w-3.5 h-3.5 text-[#86868B]" />
                <span className="text-[#86868B]">Manual Override:</span>
                <select
                  value={selectedAssetForEvidence.manual_override_category || selectedAssetForEvidence.effective_category}
                  onChange={(e) => handleOverride(selectedAssetForEvidence.id, e.target.value)}
                  className="bg-[#F5F5F7] text-[12px] font-medium text-[#1D1D1F] px-2.5 py-1 rounded-lg border border-[#E5E5EA] focus:outline-none focus:border-[#007AFF]"
                >
                  {CATEGORY_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>
                      {opt}
                    </option>
                  ))}
                </select>
              </div>

              <button
                onClick={() => handleIdentifySingle(selectedAssetForEvidence.id)}
                className="px-3 py-1.5 text-[12px] font-medium text-white bg-[#007AFF] hover:bg-[#0062CC] rounded-xl transition-colors shadow-xs"
              >
                Re-identify Device
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
