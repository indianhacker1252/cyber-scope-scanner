import { useState } from "react";
import Header from "@/components/dashboard/Header";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardOverview from "@/components/dashboard/DashboardOverview";
import TargetInput from "@/components/dashboard/TargetInput";
import WebVulnerabilities from "@/components/dashboard/WebVulnerabilities";

const Index = () => {
  const [activeSection, setActiveSection] = useState("dashboard");

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard":
        return <DashboardOverview />;
      case "target":
        return <TargetInput />;
      case "web-vulns":
        return <WebVulnerabilities />;
      case "reconnaissance":
        return <div className="p-8 text-center text-muted-foreground">Reconnaissance module coming soon...</div>;
      case "network":
        return <div className="p-8 text-center text-muted-foreground">Network scanning module coming soon...</div>;
      case "mobile":
        return <div className="p-8 text-center text-muted-foreground">Mobile security module coming soon...</div>;
      case "code-analysis":
        return <div className="p-8 text-center text-muted-foreground">Code analysis module coming soon...</div>;
      case "database":
        return <div className="p-8 text-center text-muted-foreground">Database testing module coming soon...</div>;
      case "exploits":
        return <div className="p-8 text-center text-muted-foreground">Exploit testing module coming soon...</div>;
      case "reports":
        return <div className="p-8 text-center text-muted-foreground">Reports module coming soon...</div>;
      case "tools":
        return <div className="p-8 text-center text-muted-foreground">Tool management module coming soon...</div>;
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