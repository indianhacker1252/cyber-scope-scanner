/**
 * VAPT Security Scanner - Main Dashboard
 * Copyright (c) 2024 Harsh Malik - All Rights Reserved
 */

import { useState } from "react";
import Header from "@/components/dashboard/Header";
import Sidebar from "@/components/dashboard/Sidebar";
import { Copyright } from "@/components/dashboard/Copyright";
import DashboardOverview from "@/components/dashboard/DashboardOverview";
import TargetInput from "@/components/dashboard/TargetInput";
import EnhancedScanResults from "@/components/dashboard/EnhancedScanResults";
import MobileSecurity from "@/components/dashboard/MobileSecurity";
import IoTSecurity from "@/components/dashboard/IoTSecurity";
import AssetExclusion from "@/components/dashboard/AssetExclusion";
import GitRepository from "@/components/dashboard/GitRepository";
import Reports from "@/components/dashboard/Reports";
import ToolManagement from "@/components/dashboard/ToolManagement";
import AgentManagement from "@/components/dashboard/AgentManagement";
import VAPTReports from "@/components/dashboard/VAPTReports";
import { AutomatedVAPT } from "@/components/dashboard/AutomatedVAPT";
import { ThreatIntelligence } from "@/components/security/ThreatIntelligence";
import { SecurityAdvisor } from "@/components/security/SecurityAdvisor";
import AttackVisualization from "@/components/dashboard/AttackVisualization";
import { WebHackersWeapons } from "@/components/dashboard/WebHackersWeapons";
import AIHub from "@/components/dashboard/AIHub";
import ScanningHub from "@/components/dashboard/ScanningHub";
import SecurityTestingHub from "@/components/dashboard/SecurityTestingHub";

const Index = () => {
  const [activeSection, setActiveSection] = useState("dashboard");

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard":
        return <DashboardOverview />;
      case "target":
        return <TargetInput onNavigateToResults={() => setActiveSection("scan-results")} />;
      case "ai-hub":
        return <AIHub />;
      case "threat-intel":
        return <ThreatIntelligence />;
      case "security-advisor":
        return <SecurityAdvisor />;
      case "attack-visualization":
        return <AttackVisualization />;
      case "scanning-hub":
        return <ScanningHub />;
      case "vapt-auto":
        return <AutomatedVAPT />;
      case "security-testing-hub":
        return <SecurityTestingHub />;
      case "webhackers-weapons":
        return <WebHackersWeapons />;
      case "scan-results":
        return <EnhancedScanResults />;
      case "mobile":
        return <MobileSecurity />;
      case "iot-security":
        return <IoTSecurity />;
      case "asset-exclusion":
        return <AssetExclusion />;
      case "git-repository":
        return <GitRepository />;
      case "agent-management":
        return <AgentManagement />;
      case "vapt-reports":
        return <VAPTReports />;
      case "reports":
        return <Reports />;
      case "tools":
        return <ToolManagement />;
      default:
        return <DashboardOverview />;
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      <div className="flex">
        <Sidebar activeSection={activeSection} onSectionChange={setActiveSection} />
        <main className="flex-1 p-6">
          {renderContent()}
        </main>
      </div>
      <Copyright />
    </div>
  );
};

export default Index;
