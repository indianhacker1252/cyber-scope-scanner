import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
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
  Bug,
  Trash2,
  RefreshCw
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";
import { useToast } from "@/components/ui/use-toast";

const ScanResults = () => {
  const { activeSessions, generateReport, clearSessions } = useKaliTools();
  const { toast } = useToast();
  const [selectedScan, setSelectedScan] = useState<any>(null);

  const completedScans = activeSessions.filter(s => s.status === 'completed');
  const runningScans = activeSessions.filter(s => s.status === 'running');
  const failedScans = activeSessions.filter(s => s.status === 'failed');
  
  const allFindings = completedScans.flatMap(scan => scan.findings || []);
  const findingsByType = allFindings.reduce((acc, finding) => {
    const type = finding.type || 'unknown';
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "bg-destructive/20 text-destructive border-destructive";
      case "high": return "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/20 dark:text-orange-400 dark:border-orange-800";
      case "medium": return "bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-400 dark:border-yellow-800";
      case "low": return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800";
      default: return "bg-muted text-muted-foreground border-muted";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "bg-green-100 text-green-800 border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-800";
      case "running": return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800";
      case "failed": return "bg-destructive/20 text-destructive border-destructive";
      default: return "bg-muted text-muted-foreground border-muted";
    }
  };

  const getToolIcon = (tool: string) => {
    switch (tool?.toLowerCase()) {
      case 'nmap': return Network;
      case 'nikto': return Globe;
      case 'sqlmap': return Database;
      case 'gobuster': return Globe;
      case 'nuclei': return Bug;
      case 'amass': return Target;
      case 'whatweb': return Eye;
      case 'sublist3r': return Target;
      default: return Shield;
    }
  };

  const exportResults = async () => {
    try {
      if (completedScans.length === 0) {
        toast({
          title: "No Results to Export",
          description: "Complete some scans first to generate a report.",
          variant: "destructive"
        });
        return;
      }

      const report = await generateReport();
      const blob = new Blob([report], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${new Date().toISOString().split('T')[0]}.md`;
      a.click();
      URL.revokeObjectURL(url);

      toast({
        title: "Report Exported",
        description: "Security report has been downloaded successfully."
      });
    } catch (error) {
      console.error('Failed to generate report:', error);
      toast({
        title: "Export Failed",
        description: "Failed to generate report. Please try again.",
        variant: "destructive"
      });
    }
  };

  const handleClearResults = () => {
    clearSessions();
    toast({
      title: "Results Cleared",
      description: "All scan results have been cleared successfully."
    });
  };

  const formatDuration = (start: Date, end?: Date) => {
    if (!start) return 'Unknown';
    const duration = end ? end.getTime() - start.getTime() : Date.now() - start.getTime();
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  // Show empty state if no scans exist
  if (activeSessions.length === 0) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="h-5 w-5 mr-2 text-primary" />
              Scan Results & Reports
            </CardTitle>
            <CardDescription>
              View detailed results from your security scans and generate reports
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-center p-12">
              <Shield className="h-16 w-16 mx-auto mb-6 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">No Scan Results</h3>
              <p className="text-muted-foreground mb-6">
                Start a security scan to see results here. You can initiate scans from the Target Input or Advanced Scanning sections.
              </p>
              <div className="flex justify-center space-x-4">
                <Button variant="outline" onClick={() => window.location.reload()}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

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
              {runningScans.length > 0 && (
                <Badge variant="secondary" className="animate-pulse">
                  {runningScans.length} Running
                </Badge>
              )}
              <Badge variant="default">{completedScans.length} Completed</Badge>
              {failedScans.length > 0 && (
                <Badge variant="destructive">{failedScans.length} Failed</Badge>
              )}
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
                        <p className="text-2xl font-bold text-green-600">{completedScans.length}</p>
                      </div>
                      <CheckCircle className="h-8 w-8 text-green-600" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Running</p>
                        <p className="text-2xl font-bold text-blue-600">{runningScans.length}</p>
                      </div>
                      <Clock className="h-8 w-8 text-blue-600" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Total Findings</p>
                        <p className="text-2xl font-bold text-orange-600">{allFindings.length}</p>
                      </div>
                      <AlertTriangle className="h-8 w-8 text-orange-600" />
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Recent Scans</CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-64">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Tool</TableHead>
                          <TableHead>Target</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Duration</TableHead>
                          <TableHead>Findings</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {activeSessions.slice(-10).reverse().map((scan) => {
                          const Icon = getToolIcon(scan.tool);
                          return (
                            <TableRow key={scan.id}>
                              <TableCell>
                                <div className="flex items-center">
                                  <Icon className="h-4 w-4 mr-2 text-primary" />
                                  {scan.tool.toUpperCase()}
                                </div>
                              </TableCell>
                              <TableCell className="font-medium">{scan.target}</TableCell>
                              <TableCell>
                                <Badge className={getStatusColor(scan.status)} variant="outline">
                                  {scan.status}
                                </Badge>
                              </TableCell>
                              <TableCell>{formatDuration(scan.startTime, scan.endTime)}</TableCell>
                              <TableCell>{scan.findings?.length || 0}</TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </ScrollArea>
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
                                {scan.findings?.length || 0} findings
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
                                  {(scan.findings || []).slice(0, 3).map((finding, i) => (
                                    <div key={i} className="text-sm p-2 bg-muted/50 rounded">
                                      <span className="font-medium">{finding.type}:</span> {String(finding.description || finding.port || finding.domain || finding.path || 'No details')}
                                    </div>
                                  ))}
                                  {(scan.findings?.length || 0) > 3 && (
                                    <p className="text-sm text-muted-foreground">
                                      ... and {(scan.findings?.length || 0) - 3} more findings
                                    </p>
                                  )}
                                </div>
                              </div>
                              <div>
                                <p className="text-sm font-medium mb-2">Raw Output (Preview)</p>
                                <Textarea
                                  value={(scan.output || '').substring(0, 200) + ((scan.output || '').length > 200 ? '...' : '')}
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
                          {(scan.findings || []).map((finding, i) => (
                            <div key={i} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                              <div className="flex-1">
                                <p className="font-medium">{finding.type}</p>
                                <p className="text-sm text-muted-foreground">
                                  {String(finding.description || finding.port || finding.domain || finding.path || 'No details')}
                                </p>
                              </div>
                              {finding.severity && (
                                <Badge className={getSeverityColor(finding.severity)} variant="outline">
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
                      onClick={handleClearResults}
                      disabled={activeSessions.length === 0}
                      className="w-full"
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Clear All Results
                    </Button>
                  </div>
                  
                  {completedScans.length > 0 && (
                    <div className="mt-6">
                      <p className="text-sm font-medium mb-2">Report Summary</p>
                      <div className="p-4 bg-muted/50 rounded-lg">
                        <p className="text-sm">
                          Ready to export: {completedScans.length} completed scans with {allFindings.length} total findings
                        </p>
                      </div>
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