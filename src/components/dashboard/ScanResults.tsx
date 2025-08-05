import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar,
  Target,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  Shield,
  Database,
  Globe,
  Network,
  Bug
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";

const ScanResults = () => {
  const { activeSessions, generateReport, clearSessions } = useKaliTools();

  const completedScans = activeSessions.filter(s => s.status === 'completed');
  const runningScans = activeSessions.filter(s => s.status === 'running');
  const failedScans = activeSessions.filter(s => s.status === 'failed');
  
  const allFindings = completedScans.flatMap(scan => scan.findings);
  const findingsByType = allFindings.reduce((acc, finding) => {
    const type = finding.type || 'unknown';
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-destructive/20 text-destructive";
      case "high": return "bg-destructive/10 text-destructive";
      case "medium": return "bg-warning/20 text-warning";
      case "low": return "bg-success/20 text-success";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getToolIcon = (tool: string) => {
    switch (tool) {
      case 'nmap': return Network;
      case 'nikto': return Globe;
      case 'sqlmap': return Database;
      case 'gobuster': return Globe;
      case 'nuclei': return Bug;
      case 'amass': return Target;
      default: return Shield;
    }
  };

  const exportResults = async () => {
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
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center">
              <FileText className="h-5 w-5 mr-2 text-primary" />
              Scan Results & Reports
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="secondary">{runningScans.length} Running</Badge>
              <Badge variant="default">{completedScans.length} Completed</Badge>
              {failedScans.length > 0 && <Badge variant="destructive">{failedScans.length} Failed</Badge>}
            </div>
          </CardTitle>
          <CardDescription>
            View detailed results from your security scans and generate reports
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="completed">Completed Scans</TabsTrigger>
              <TabsTrigger value="findings">Detailed Findings</TabsTrigger>
              <TabsTrigger value="export">Export & Reports</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Total Scans</p>
                        <p className="text-2xl font-bold">{activeSessions.length}</p>
                      </div>
                      <Activity className="h-8 w-8 text-primary" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Completed</p>
                        <p className="text-2xl font-bold">{completedScans.length}</p>
                      </div>
                      <CheckCircle className="h-8 w-8 text-success" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Running</p>
                        <p className="text-2xl font-bold">{runningScans.length}</p>
                      </div>
                      <Clock className="h-8 w-8 text-warning" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Total Findings</p>
                        <p className="text-2xl font-bold">{allFindings.length}</p>
                      </div>
                      <AlertTriangle className="h-8 w-8 text-destructive" />
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Findings by Type</CardTitle>
                </CardHeader>
                <CardContent>
                  {Object.keys(findingsByType).length === 0 ? (
                    <div className="text-center p-8">
                      <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                      <p className="text-lg font-medium mb-2">No Findings Yet</p>
                      <p className="text-muted-foreground">Complete some scans to see results here</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {Object.entries(findingsByType).map(([type, count]) => (
                        <div key={type} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                          <div className="flex items-center space-x-3">
                            <div className="w-3 h-3 bg-primary rounded-full"></div>
                            <span className="font-medium capitalize">{type.replace('_', ' ')}</span>
                          </div>
                          <Badge>{String(count)}</Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="completed" className="space-y-4">
              {completedScans.length === 0 ? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <CheckCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Completed Scans</p>
                    <p className="text-muted-foreground">Start a scan to see results here</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-4">
                  {completedScans.map((scan) => {
                    const Icon = getToolIcon(scan.tool);
                    const duration = scan.endTime ? 
                      Math.round((scan.endTime.getTime() - scan.startTime.getTime()) / 1000) : 0;
                    
                    return (
                      <Card key={scan.id}>
                        <CardHeader>
                          <div className="flex items-center justify-between">
                            <CardTitle className="flex items-center">
                              <Icon className="h-5 w-5 mr-2 text-primary" />
                              {scan.tool.toUpperCase()} - {scan.target}
                            </CardTitle>
                            <div className="flex items-center space-x-2">
                              <Badge variant="default">
                                {scan.findings.length} findings
                              </Badge>
                              <Badge variant="outline">
                                {duration}s
                              </Badge>
                            </div>
                          </div>
                          <CardDescription>
                            Started: {scan.startTime.toLocaleString()}
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <p className="text-sm font-medium mb-2">Findings Summary</p>
                                <div className="space-y-1">
                                  {scan.findings.slice(0, 3).map((finding, i) => (
                                    <div key={i} className="text-sm p-2 bg-muted/50 rounded">
                                      <span className="font-medium">{finding.type}:</span> {String(finding.description || finding.port || finding.domain || finding.path || 'No details')}
                                    </div>
                                  ))}
                                  {scan.findings.length > 3 && (
                                    <p className="text-sm text-muted-foreground">
                                      ... and {scan.findings.length - 3} more findings
                                    </p>
                                  )}
                                </div>
                              </div>
                              <div>
                                <p className="text-sm font-medium mb-2">Raw Output (Preview)</p>
                                <Textarea
                                  value={scan.output.substring(0, 200) + (scan.output.length > 200 ? '...' : '')}
                                  readOnly
                                  className="min-h-20 text-xs font-mono"
                                />
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </TabsContent>

            <TabsContent value="findings" className="space-y-4">
              {allFindings.length === 0 ? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <Bug className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Findings Yet</p>
                    <p className="text-muted-foreground">Complete scans to see detailed findings here</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-4">
                  {completedScans.map((scan) => (
                    <Card key={scan.id}>
                      <CardHeader>
                        <CardTitle className="text-lg">{scan.tool.toUpperCase()} Findings</CardTitle>
                        <CardDescription>{scan.target}</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {scan.findings.map((finding, i) => (
                            <div key={i} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                              <div className="flex-1">
                                <p className="font-medium">{finding.type}</p>
                                <p className="text-sm text-muted-foreground">
                                  {String(finding.description || finding.port || finding.domain || finding.path || 'No details')}
                                </p>
                              </div>
                              {finding.severity && (
                                <Badge className={getSeverityColor(finding.severity)}>
                                  {finding.severity}
                                </Badge>
                              )}
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="export" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Export Results</CardTitle>
                  <CardDescription>Export your scan results in various formats</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button 
                      onClick={exportResults}
                      disabled={completedScans.length === 0}
                      className="w-full"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Export Markdown Report
                    </Button>
                    
                    <Button 
                      variant="outline"
                      disabled={completedScans.length === 0}
                      className="w-full"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Export JSON Data
                    </Button>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button 
                      variant="outline"
                      onClick={clearSessions}
                      disabled={activeSessions.length === 0}
                      className="w-full"
                    >
                      Clear All Results
                    </Button>
                    
                    <Button 
                      variant="outline"
                      disabled={completedScans.length === 0}
                      className="w-full"
                    >
                      <Eye className="h-4 w-4 mr-2" />
                      View Full Report
                    </Button>
                  </div>
                  
                  {completedScans.length > 0 && (
                    <div className="mt-6">
                      <p className="text-sm font-medium mb-2">Report Preview</p>
                      <Textarea
                        value="Report preview will be generated when you click generate..."
                        readOnly
                        className="min-h-32 font-mono text-xs"
                      />
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ScanResults;