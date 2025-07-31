import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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
  Bug
} from "lucide-react";

const DashboardOverview = () => {
  const stats = [
    { label: "Active Scans", value: "0", icon: Clock, color: "text-warning" },
    { label: "Vulnerabilities Found", value: "0", icon: AlertTriangle, color: "text-destructive" },
    { label: "Tests Completed", value: "0", icon: CheckCircle, color: "text-success" },
    { label: "Targets Monitored", value: "0", icon: Target, color: "text-info" },
  ];

  const recentScans: any[] = [];

  const vulnerabilityTypes: any[] = [];

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
                </div>
              ) : (
                recentScans.map((scan, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex-1">
                      <p className="font-medium">{scan.target}</p>
                      <p className="text-sm text-muted-foreground">{scan.type}</p>
                    </div>
                    <div className="text-center px-4">
                      <p className="text-sm font-medium">{scan.vulns} vulns</p>
                      <p className={`text-xs ${
                        scan.severity === 'High' ? 'text-destructive' : 
                        scan.severity === 'Medium' ? 'text-warning' : 'text-muted-foreground'
                      }`}>
                        {scan.severity}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        scan.status === 'Completed' ? 'bg-success/20 text-success' :
                        scan.status === 'Running' ? 'bg-warning/20 text-warning' :
                        'bg-muted text-muted-foreground'
                      }`}>
                        {scan.status}
                      </span>
                    </div>
                  </div>
                ))
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
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>Start a new security assessment</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Button className="h-16 flex-col space-y-2">
              <Globe className="h-6 w-6" />
              <span>Web Scan</span>
            </Button>
            <Button variant="secondary" className="h-16 flex-col space-y-2">
              <Network className="h-6 w-6" />
              <span>Network Scan</span>
            </Button>
            <Button variant="secondary" className="h-16 flex-col space-y-2">
              <Database className="h-6 w-6" />
              <span>API Test</span>
            </Button>
            <Button variant="secondary" className="h-16 flex-col space-y-2">
              <Bug className="h-6 w-6" />
              <span>Full Audit</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default DashboardOverview;