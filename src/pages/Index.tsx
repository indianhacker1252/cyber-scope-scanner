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
import AdvancedScanning from "@/components/dashboard/AdvancedScanning";
import AdvancedTools from "@/components/dashboard/AdvancedTools";
import EnhancedScanResults from "@/components/dashboard/EnhancedScanResults";
import WebVulnerabilities from "@/components/dashboard/WebVulnerabilities";
import Reconnaissance from "@/components/dashboard/Reconnaissance";
import NetworkScanning from "@/components/dashboard/NetworkScanning";
import MobileSecurity from "@/components/dashboard/MobileSecurity";
import IoTSecurity from "@/components/dashboard/IoTSecurity";
import CodeAnalysis from "@/components/dashboard/CodeAnalysis";
import DatabaseTesting from "@/components/dashboard/DatabaseTesting";
import ExploitTesting from "@/components/dashboard/ExploitTesting";
import AssetExclusion from "@/components/dashboard/AssetExclusion";
import GitRepository from "@/components/dashboard/GitRepository";
import Reports from "@/components/dashboard/Reports";
import ToolManagement from "@/components/dashboard/ToolManagement";
import AgentManagement from "@/components/dashboard/AgentManagement";
import VAPTReports from "@/components/dashboard/VAPTReports";
import PentestGPT from "@/components/dashboard/PentestGPT";
import { AutomatedVAPT } from "@/components/dashboard/AutomatedVAPT";
import AutonomousHacking from "@/components/dashboard/AutonomousHacking";
import { ExaInsights } from "@/components/dashboard/ExaInsights";
import { ThreatIntelligence } from "@/components/security/ThreatIntelligence";
import { SecurityAdvisor } from "@/components/security/SecurityAdvisor";
import AttackVisualization from "@/components/dashboard/AttackVisualization";

const Index = () => {
  const [activeSection, setActiveSection] = useState("dashboard");

  const navigateToResults = () => setActiveSection("scan-results");

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard":
        return <DashboardOverview />;
      case "target":
        return <TargetInput onNavigateToResults={() => setActiveSection("scan-results")} />;
      case "threat-intel":
        return <ThreatIntelligence />;
      case "security-advisor":
        return <SecurityAdvisor />;
      case "attack-visualization":
        return <AttackVisualization />;
      case "advanced-scanning":
        return <AdvancedScanning />;
      case "advanced-tools":
        return <AdvancedTools />;
      case "scan-results":
        return <EnhancedScanResults />;
      case "web-vulns":
        return <WebVulnerabilities onNavigateToResults={navigateToResults} />;
      case "reconnaissance":
        return <Reconnaissance onNavigateToResults={navigateToResults} />;
      case "network":
        return <NetworkScanning onNavigateToResults={navigateToResults} />;
      case "mobile":
        return <MobileSecurity />;
      case "iot-security":
        return <IoTSecurity />;
      case "pentestgpt":
        return <PentestGPT />;
      case "automated-vapt":
        return <AutomatedVAPT />;
      case "autonomous":
        return <AutonomousHacking />;
      case "exa-insights":
        return <ExaInsights />;
      case "code-analysis":
        return <CodeAnalysis />;
      case "database":
        return <DatabaseTesting onNavigateToResults={navigateToResults} />;
      case "exploits":
        return <ExploitTesting />;
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