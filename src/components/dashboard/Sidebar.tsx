import { 
  Globe, 
  Smartphone, 
  Network, 
  FileText, 
  Target, 
  Search,
  Shield,
  Database,
  Code,
  Bug,
  AlertTriangle,
  Activity,
  Settings,
  Terminal,
  Brain,
  Wifi,
  EyeOff,
  Download,
  GitBranch,
  Lightbulb
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const Sidebar = ({ activeSection, onSectionChange }: SidebarProps) => {
const sections = [
    { id: "dashboard", label: "Dashboard", icon: Activity },
    { id: "target", label: "Target Input", icon: Target },
    { id: "attack-visualization", label: "🎯 Live Visualization", icon: Activity },
    { id: "threat-intel", label: "Threat Intelligence", icon: Brain },
    { id: "security-advisor", label: "Security Advisor", icon: Shield },
    { id: "advanced-scanning", label: "Advanced Scanning", icon: Terminal },
    { id: "advanced-tools", label: "Advanced Tools", icon: Shield },
    { id: "scan-results", label: "Scan Results", icon: FileText },
    { id: "reconnaissance", label: "Reconnaissance", icon: Search },
    { id: "web-vulns", label: "Web Vulnerabilities", icon: Globe },
    { id: "network", label: "Network Scanning", icon: Network },
    { id: "mobile", label: "Mobile Security", icon: Smartphone },
    { id: "iot-security", label: "IoT Security", icon: Wifi },
      { id: "pentestgpt", label: "PentestGPT", icon: Brain },
      { id: "automated-vapt", label: "AI Auto-VAPT", icon: Shield },
      { id: "autonomous", label: "🔥 AI Autonomous", icon: Brain },
      { id: "exa-insights", label: "Exa.ai Insights", icon: Lightbulb },
      { id: "code-analysis", label: "Code Analysis", icon: Code },
    { id: "database", label: "Database Testing", icon: Database },
    { id: "exploits", label: "Exploit Testing", icon: Bug },
    { id: "asset-exclusion", label: "Asset Exclusion", icon: EyeOff },
    { id: "git-repository", label: "Git Repository", icon: GitBranch },
    { id: "agent-management", label: "Agent Management", icon: Shield },
    { id: "vapt-reports", label: "VAPT Reports", icon: FileText },
    { id: "reports", label: "AI Reports", icon: AlertTriangle },
    { id: "tools", label: "Tool Management", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-card border-r border-border p-4">
      <nav className="space-y-2">
        {sections.map((section) => {
          const Icon = section.icon;
          return (
            <Button
              key={section.id}
              variant={activeSection === section.id ? "default" : "ghost"}
              className={cn(
                "w-full justify-start",
                activeSection === section.id && "bg-primary text-primary-foreground"
              )}
              onClick={() => onSectionChange(section.id)}
            >
              <Icon className="h-4 w-4 mr-2" />
              {section.label}
            </Button>
          );
        })}
      </nav>
    </aside>
  );
};

export default Sidebar;