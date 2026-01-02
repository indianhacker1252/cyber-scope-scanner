import { useState } from "react";
import { 
  Activity, 
  Target, 
  Brain, 
  Search,
  Shield,
  FileText,
  Settings,
  ChevronDown,
  ChevronRight,
  Smartphone,
  Wifi,
  GitBranch,
  EyeOff
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

interface SectionGroup {
  id: string;
  label: string;
  icon: any;
  items?: { id: string; label: string }[];
}

const Sidebar = ({ activeSection, onSectionChange }: SidebarProps) => {
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    "ai-hub": true,
    "scanning-hub": true,
    "security-testing": true
  });

  const toggleGroup = (groupId: string) => {
    setOpenGroups(prev => ({ ...prev, [groupId]: !prev[groupId] }));
  };

  const mainSections = [
    { id: "dashboard", label: "Dashboard", icon: Activity },
    { id: "target", label: "Target Input", icon: Target },
  ];

  const sectionGroups: SectionGroup[] = [
    {
      id: "ai-hub",
      label: "🧠 AI Hub",
      icon: Brain,
      items: [
        { id: "ai-hub", label: "AI Overview" },
        { id: "ai-learning", label: "AI Learning Dashboard" },
        { id: "apex-sentinel", label: "Apex Sentinel" },
        { id: "attack-visualization", label: "Live Visualization" },
        { id: "threat-intel", label: "Threat Intelligence" },
        { id: "security-advisor", label: "Security Advisor" },
      ]
    },
    {
      id: "scanning-hub",
      label: "🔍 Scanning Hub",
      icon: Search,
      items: [
        { id: "scanning-hub", label: "Scanning Overview" },
        { id: "vapt-auto", label: "Automated VAPT" },
      ]
    },
    {
      id: "security-testing",
      label: "🛡️ Security Testing",
      icon: Shield,
      items: [
        { id: "security-testing-hub", label: "Testing Overview" },
        { id: "webhackers-weapons", label: "WebHackers Arsenal" },
      ]
    },
  ];

  const otherSections = [
    { id: "mobile", label: "Mobile Security", icon: Smartphone },
    { id: "iot-security", label: "IoT Security", icon: Wifi },
    { id: "scan-results", label: "Scan Results", icon: FileText },
    { id: "vapt-reports", label: "VAPT Reports", icon: FileText },
    { id: "reports", label: "AI Reports", icon: FileText },
  ];

  const managementSections = [
    { id: "asset-exclusion", label: "Asset Exclusion", icon: EyeOff },
    { id: "git-repository", label: "Git Repository", icon: GitBranch },
    { id: "agent-management", label: "Agent Management", icon: Shield },
    { id: "tools", label: "Tool Management", icon: Settings },
  ];

  const isActive = (id: string) => activeSection === id;
  const isGroupActive = (group: SectionGroup) => 
    group.items?.some(item => activeSection === item.id) || activeSection === group.id;

  return (
    <aside className="w-64 bg-card border-r border-border p-4 overflow-y-auto max-h-[calc(100vh-80px)]">
      <nav className="space-y-1">
        {/* Main Sections */}
        {mainSections.map((section) => {
          const Icon = section.icon;
          return (
            <Button
              key={section.id}
              variant={isActive(section.id) ? "default" : "ghost"}
              className={cn(
                "w-full justify-start",
                isActive(section.id) && "bg-primary text-primary-foreground"
              )}
              onClick={() => onSectionChange(section.id)}
            >
              <Icon className="h-4 w-4 mr-2" />
              {section.label}
            </Button>
          );
        })}

        <div className="py-2">
          <div className="border-t border-border" />
        </div>

        {/* Grouped Sections with Collapsible */}
        {sectionGroups.map((group) => {
          const Icon = group.icon;
          const isOpen = openGroups[group.id];
          const hasActiveChild = isGroupActive(group);
          
          return (
            <Collapsible 
              key={group.id} 
              open={isOpen} 
              onOpenChange={() => toggleGroup(group.id)}
            >
              <CollapsibleTrigger asChild>
                <Button
                  variant={hasActiveChild ? "secondary" : "ghost"}
                  className={cn(
                    "w-full justify-between",
                    hasActiveChild && "bg-primary/10"
                  )}
                >
                  <div className="flex items-center">
                    <Icon className="h-4 w-4 mr-2" />
                    {group.label}
                  </div>
                  {isOpen ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent className="pl-4 space-y-1 mt-1">
                {group.items?.map((item) => (
                  <Button
                    key={item.id}
                    variant={isActive(item.id) ? "default" : "ghost"}
                    className={cn(
                      "w-full justify-start text-sm h-9",
                      isActive(item.id) && "bg-primary text-primary-foreground"
                    )}
                    onClick={() => onSectionChange(item.id)}
                  >
                    {item.label}
                  </Button>
                ))}
              </CollapsibleContent>
            </Collapsible>
          );
        })}

        <div className="py-2">
          <div className="border-t border-border" />
        </div>

        {/* Other Sections */}
        {otherSections.map((section) => {
          const Icon = section.icon;
          return (
            <Button
              key={section.id}
              variant={isActive(section.id) ? "default" : "ghost"}
              className={cn(
                "w-full justify-start text-sm",
                isActive(section.id) && "bg-primary text-primary-foreground"
              )}
              onClick={() => onSectionChange(section.id)}
            >
              <Icon className="h-4 w-4 mr-2" />
              {section.label}
            </Button>
          );
        })}

        <div className="py-2">
          <div className="border-t border-border" />
        </div>

        {/* Management Sections */}
        <p className="text-xs text-muted-foreground px-2 py-1 uppercase tracking-wider">
          Management
        </p>
        {managementSections.map((section) => {
          const Icon = section.icon;
          return (
            <Button
              key={section.id}
              variant={isActive(section.id) ? "default" : "ghost"}
              className={cn(
                "w-full justify-start text-sm",
                isActive(section.id) && "bg-primary text-primary-foreground"
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
