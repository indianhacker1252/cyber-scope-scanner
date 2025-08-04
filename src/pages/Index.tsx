import { useState } from "react";
import Header from "@/components/dashboard/Header";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardOverview from "@/components/dashboard/DashboardOverview";
import TargetInput from "@/components/dashboard/TargetInput";
import AdvancedScanning from "@/components/dashboard/AdvancedScanning";
import ScanResults from "@/components/dashboard/ScanResults";
import WebVulnerabilities from "@/components/dashboard/WebVulnerabilities";
import Reconnaissance from "@/components/dashboard/Reconnaissance";
import NetworkScanning from "@/components/dashboard/NetworkScanning";
import MobileSecurity from "@/components/dashboard/MobileSecurity";
import CodeAnalysis from "@/components/dashboard/CodeAnalysis";
import DatabaseTesting from "@/components/dashboard/DatabaseTesting";
import ExploitTesting from "@/components/dashboard/ExploitTesting";
import Reports from "@/components/dashboard/Reports";
import ToolManagement from "@/components/dashboard/ToolManagement";
import PentestGPT from "@/components/dashboard/PentestGPT";

const Index = () => {
  const [activeSection, setActiveSection] = useState("dashboard");

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard":
        return <DashboardOverview />;
      case "target":
        return <TargetInput />;
      case "advanced-scanning":
        return <AdvancedScanning />;
      case "scan-results":
        return <ScanResults />;
      case "web-vulns":
        return <WebVulnerabilities />;
      case "reconnaissance":
        return <Reconnaissance />;
      case "network":
        return <NetworkScanning />;
      case "mobile":
        return <MobileSecurity />;
      case "pentestgpt":
        return <PentestGPT />;
      case "code-analysis":
        return <CodeAnalysis />;
      case "database":
        return <DatabaseTesting />;
      case "exploits":
        return <ExploitTesting />;
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
    </div>
  );
};

export default Index;