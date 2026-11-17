import React, { useState, useEffect, useCallback } from "react";
import { Sidebar, NavPage } from "./components/Sidebar";
import { TopNavbar } from "./components/TopNavbar";
import { OverviewDashboard } from "./pages/OverviewDashboard";
import { NetworkDiscoveryPage } from "./pages/NetworkDiscoveryPage";
import { AssetInventoryPage } from "./pages/AssetInventoryPage";
import { VulnerabilityCenterPage } from "./pages/VulnerabilityCenterPage";
import { ScanCenterPage } from "./pages/ScanCenterPage";
import { ScanHistoryPage } from "./pages/ScanHistoryPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { fetchHealthStatus } from "./api/client";

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<NavPage>("overview");
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [scanTarget, setScanTarget] = useState<string>("192.168.1.20");
  const [systemHealthy, setSystemHealthy] = useState<boolean>(true);

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetchHealthStatus();
      setSystemHealthy(res.status === "healthy" || res.status === "ok");
    } catch {
      setSystemHealthy(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  const handleNavigate = (page: NavPage) => {
    setCurrentPage(page);
  };

  const handleSelectScan = (scanId: number) => {
    setSelectedScanId(scanId);
    setCurrentPage("scan_detail");
  };

  const handleScanTarget = (ip: string) => {
    setScanTarget(ip);
    setCurrentPage("scan_center");
  };

  return (
    <div className="flex h-screen bg-[#F5F5F7] text-[#1D1D1F] overflow-hidden font-sans">
      {/* 1. Left Sidebar */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={handleNavigate}
        systemHealthy={systemHealthy}
      />

      {/* 2. Main Content Container */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Navigation */}
        <TopNavbar
          currentPage={currentPage}
          selectedScanTarget={selectedScanId ? `Scan #${selectedScanId}` : undefined}
          systemHealthy={systemHealthy}
          onNavigate={handleNavigate}
          onRefresh={checkHealth}
        />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto">
          {currentPage === "overview" && (
            <OverviewDashboard
              onNavigate={handleNavigate}
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === "discovery" && (
            <NetworkDiscoveryPage
              onScanTarget={handleScanTarget}
            />
          )}

          {currentPage === "inventory" && (
            <AssetInventoryPage
              onScanTarget={handleScanTarget}
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === "vulnerabilities" && (
            <VulnerabilityCenterPage
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === "scan_center" && (
            <ScanCenterPage
              initialTarget={scanTarget}
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === "history" && (
            <ScanHistoryPage
              onSelectScan={handleSelectScan}
              onScanTarget={handleScanTarget}
            />
          )}

          {currentPage === "reports" && (
            <ReportsPage
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === "settings" && (
            <SettingsPage />
          )}

          {currentPage === "scan_detail" && selectedScanId && (
            <ScanDetailPage
              scanId={selectedScanId}
              onBack={() => setCurrentPage("history")}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
