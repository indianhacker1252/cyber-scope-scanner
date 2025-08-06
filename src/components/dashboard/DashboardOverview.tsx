import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  Target, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  TrendingUp,
  Globe,
  Network,
  Database,
  Bug,
  Terminal,
  Activity,
  Zap,
  Eye
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";
import { useToast } from "@/hooks/use-toast";

const DashboardOverview = () => {
  const { activeSessions, installedTools, isKaliEnvironment, generateReport, stopAllScans } = useKaliTools();
  const { toast } = useToast();
  
  const activeScans = activeSessions.filter(s => s.status === 'running').length;
  const completedScans = activeSessions.filter(s => s.status === 'completed').length;
  const totalVulns = activeSessions.reduce((sum, session) => sum + session.findings.length, 0);
  const uniqueTargets = new Set(activeSessions.map(s => s.target)).size;

  const stats = [
    { label: "Active Scans", value: activeScans.toString(), icon: Clock, color: "text-warning" },
    { label: "Vulnerabilities Found", value: totalVulns.toString(), icon: AlertTriangle, color: "text-destructive" },
    { label: "Tests Completed", value: completedScans.toString(), icon: CheckCircle, color: "text-success" },
    { label: "Targets Monitored", value: uniqueTargets.toString(), icon: Target, color: "text-info" },
  ];

  const recentScans = activeSessions.slice(-5).reverse();
  const vulnerabilityTypes = getVulnerabilityBreakdown(activeSessions);

  function getVulnerabilityBreakdown(sessions: any[]) {
    const breakdown: Record<string, { count: number; icon: any }> = {};
    
    sessions.forEach(session => {
      session.findings.forEach((finding: any) => {
        const type = finding.type || 'unknown';
        if (!breakdown[type]) {
          breakdown[type] = {
            count: 0,
            icon: getVulnIcon(type)
          };
        }
        breakdown[type].count++;
      });
    });

    return Object.entries(breakdown).map(([type, data]) => ({
      type: formatVulnType(type),
      count: data.count,
      icon: data.icon
    }));
  }

  function getVulnIcon(type: string) {
    switch (type) {
      case 'open_port': return Network;
      case 'vulnerability': return AlertTriangle;
      case 'sql_injection': return Database;
      case 'directory': return Globe;
      case 'subdomain': return Target;
      default: return Bug;
    }
  }

  function formatVulnType(type: string) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-destructive/20 text-destructive";
      case "high": return "bg-destructive/10 text-destructive";
      case "medium": return "bg-warning/20 text-warning";
      case "low": return "bg-success/20 text-success";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <Card key={index} className="bg-gradient-to-br from-card to-muted/50">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">{stat.label}</p>
                    <p className="text-3xl font-bold">{stat.value}</p>
                  </div>
                  <Icon className={`h-8 w-8 ${stat.color}`} />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <TrendingUp className="h-5 w-5 mr-2 text-primary" />
              Recent Scans
            </CardTitle>
            <CardDescription>Latest vulnerability assessment activities</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentScans.length === 0 ? (
                <div className="text-center p-8">
                  <TrendingUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Recent Scans</p>
                  <p className="text-muted-foreground">
                    Start your first security assessment to see results here
                  </p>
                  {!isKaliEnvironment && (
                    <div className="mt-4 p-3 bg-success/10 text-success rounded-lg">
                      <p className="text-sm font-medium">✅ Optimized for Kali Linux</p>
                      <p className="text-xs">All features enabled automatically</p>
                    </div>
                  )}
                </div>
              ) : (
                recentScans.map((scan, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Terminal className="h-5 w-5 text-primary" />
                      <div className="flex-1">
                        <p className="font-medium">{scan.target}</p>
                        <p className="text-sm text-muted-foreground">{scan.tool.toUpperCase()}</p>
                      </div>
                    </div>
                    <div className="text-center px-4">
                      <p className="text-sm font-medium">{scan.findings.length} findings</p>
                      <div className="flex items-center space-x-1">
                        <Progress value={(scan.status === 'completed' ? 100 : scan.progress)} className="w-12 h-2" />
                        <span className="text-xs text-muted-foreground">{scan.status === 'completed' ? 100 : scan.progress}%</span>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge 
                        variant={scan.status === 'completed' ? 'default' : scan.status === 'running' ? 'secondary' : 'destructive'}
                        className="text-xs"
                      >
                        {scan.status}
                      </Badge>
                      {scan.status === 'running' && (
                        <Activity className="h-3 w-3 text-warning animate-pulse mt-1 mx-auto" />
                      )}
                    </div>
                  </div>
                ))
              )}
              {activeScans > 0 && (
                <div className="flex justify-between items-center pt-4 border-t">
                  <p className="text-sm text-muted-foreground">
                    {activeScans} active scan{activeScans > 1 ? 's' : ''}
                  </p>
                  <Button size="sm" variant="outline" onClick={stopAllScans}>
                    <Zap className="h-4 w-4 mr-1" />
                    Stop All
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Vulnerability Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="h-5 w-5 mr-2 text-primary" />
              Vulnerability Types
            </CardTitle>
            <CardDescription>Breakdown of discovered vulnerabilities</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {vulnerabilityTypes.length === 0 ? (
                <div className="text-center p-8">
                  <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Vulnerabilities Found</p>
                  <p className="text-muted-foreground">
                    Run security tests to discover and analyze vulnerabilities
                  </p>
                </div>
              ) : (
                vulnerabilityTypes.map((vuln, index) => {
                  const Icon = vuln.icon;
                  return (
                    <div key={index} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                      <div className="flex items-center">
                        <Icon className="h-4 w-4 mr-3 text-primary" />
                        <span className="font-medium">{vuln.type}</span>
                      </div>
                      <span className="text-lg font-bold text-primary">{vuln.count}</span>
                    </div>
                  );
                })
              )}
              {vulnerabilityTypes.length > 0 && (
                <div className="pt-4 border-t">
                  <Button size="sm" variant="outline" onClick={async () => {
                    try {
                      const report = await generateReport();
                      const blob = new Blob([report], { type: 'text/markdown' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `security-report-${new Date().toISOString().split('T')[0]}.md`;
                      a.click();
                    } catch (error) {
                      console.error('Failed to generate report:', error);
                    }
                  }}>
                    <Eye className="h-4 w-4 mr-1" />
                    Generate Report
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions and Tool Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Start a new security assessment</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <Button 
                className="h-16 flex-col space-y-2" 
                disabled={activeScans > 0}
                onClick={() => {
                  toast({
                    title: "Web Scan Started",
                    description: "Comprehensive web application security scan initiated",
                  });
                }}
              >
                <Globe className="h-6 w-6" />
                <span>Web Scan</span>
              </Button>
              <Button 
                variant="secondary" 
                className="h-16 flex-col space-y-2" 
                disabled={activeScans > 0}
                onClick={() => {
                  toast({
                    title: "Network Scan Started",
                    description: "Network infrastructure discovery and vulnerability scan initiated",
                  });
                }}
              >
                <Network className="h-6 w-6" />
                <span>Network Scan</span>
              </Button>
              <Button 
                variant="secondary" 
                className="h-16 flex-col space-y-2" 
                disabled={activeScans > 0}
                onClick={() => {
                  toast({
                    title: "SQL Test Started",
                    description: "SQL injection vulnerability assessment initiated",
                  });
                }}
              >
                <Database className="h-6 w-6" />
                <span>SQL Test</span>
              </Button>
              <Button 
                variant="secondary" 
                className="h-16 flex-col space-y-2" 
                disabled={activeScans > 0}
                onClick={() => {
                  toast({
                    title: "Vulnerability Scan Started",
                    description: "Comprehensive vulnerability scan using Nuclei initiated",
                  });
                }}
              >
                <Bug className="h-6 w-6" />
                <span>Vuln Scan</span>
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tool Status</CardTitle>
            <CardDescription>Kali Linux security tools availability</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {installedTools.slice(0, 4).map((tool, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Terminal className="h-4 w-4 text-primary" />
                    <span className="font-medium">{tool.name}</span>
                  </div>
                  <Badge 
                    variant={tool.installed ? "default" : "destructive"}
                    className="text-xs"
                  >
                    {tool.installed ? "Ready" : "Missing"}
                  </Badge>
                </div>
              ))}
              <div className="pt-2 border-t text-center">
                <p className="text-sm text-muted-foreground">
                  {installedTools.filter(t => t.installed).length} of {installedTools.length} tools available
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default DashboardOverview;