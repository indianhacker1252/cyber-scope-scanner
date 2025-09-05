import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { 
  Search, 
  Download, 
  Eye, 
  Trash2, 
  Filter, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Terminal,
  Globe,
  Shield,
  Database,
  Network,
  Bug,
  FileText,
  BarChart3,
  PieChart,
  TrendingUp,
  Calendar,
  Target,
  Zap
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";
import { useToast } from "@/components/ui/use-toast";

interface FilterState {
  target: string;
  tool: string;
  status: string;
  severity: string;
  dateRange: string;
}

const EnhancedScanResults = () => {
  const { activeSessions, generateReport, clearSessions } = useKaliTools();
  const { toast } = useToast();
  
  const [filters, setFilters] = useState<FilterState>({
    target: '',
    tool: 'all-tools',
    status: 'all-status',
    severity: 'all-severities',
    dateRange: ''
  });
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScan, setSelectedScan] = useState<any>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [liveOutput, setLiveOutput] = useState<Record<string, string[]>>({});

  // Real-time output streaming
  useEffect(() => {
    const intervals: NodeJS.Timeout[] = [];
    
    activeSessions.forEach(session => {
      if (session.status === 'running') {
        const interval = setInterval(() => {
          // Simulate real-time output updates
          setLiveOutput(prev => ({
            ...prev,
            [session.id]: [
              ...(prev[session.id] || []),
              `[${new Date().toLocaleTimeString()}] ${session.tool}: Scanning ${session.target}...`
            ].slice(-20) // Keep last 20 lines
          }));
        }, 2000);
        intervals.push(interval);
      }
    });

    return () => intervals.forEach(clearInterval);
  }, [activeSessions]);

  // Filter and search logic
  const filteredSessions = useMemo(() => {
    return activeSessions.filter(session => {
      const matchesSearch = !searchQuery || 
        session.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        session.tool.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesTarget = !filters.target || session.target.includes(filters.target);
      const matchesTool = !filters.tool || filters.tool === 'all-tools' || session.tool === filters.tool;
      const matchesStatus = !filters.status || filters.status === 'all-status' || session.status === filters.status;
      
      const matchesSeverity = !filters.severity || filters.severity === 'all-severities' || 
        session.findings.some((finding: any) => finding.severity === filters.severity);
      
      return matchesSearch && matchesTarget && matchesTool && matchesStatus && matchesSeverity;
    });
  }, [activeSessions, searchQuery, filters]);

  // Statistics
  const stats = useMemo(() => {
    const completed = activeSessions.filter(s => s.status === 'completed').length;
    const running = activeSessions.filter(s => s.status === 'running').length;
    const failed = activeSessions.filter(s => s.status === 'failed').length;
    const totalFindings = activeSessions.reduce((sum, s) => sum + s.findings.length, 0);
    
    const severityBreakdown = activeSessions.reduce((acc, session) => {
      session.findings.forEach((finding: any) => {
        const severity = finding.severity || 'info';
        acc[severity] = (acc[severity] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    return {
      total: activeSessions.length,
      completed,
      running,
      failed,
      totalFindings,
      critical: severityBreakdown.critical || 0,
      high: severityBreakdown.high || 0,
      medium: severityBreakdown.medium || 0,
      low: severityBreakdown.low || 0,
      info: severityBreakdown.info || 0
    };
  }, [activeSessions]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400";
      case "high": return "bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400";
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400";
      case "running": return "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400";
      case "failed": return "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400";
    }
  };

  const getToolIcon = (tool: string) => {
    switch (tool.toLowerCase()) {
      case 'nmap': return Network;
      case 'nikto': return Globe;
      case 'sqlmap': return Database;
      case 'nuclei': return Bug;
      case 'whatweb': return Eye;
      case 'gobuster': return Search;
      case 'amass': return Target;
      case 'sublist3r': return Target;
      default: return Terminal;
    }
  };

  const formatDuration = (start: Date, end?: Date) => {
    const duration = end ? end.getTime() - start.getTime() : Date.now() - start.getTime();
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const exportReport = async (format: 'html' | 'pdf' | 'json' | 'csv') => {
    setIsGeneratingReport(true);
    try {
      const report = await generateReport();
      let content = report;
      let mimeType = 'text/plain';
      let extension = 'txt';

      switch (format) {
        case 'html':
          content = convertToHTML(report);
          mimeType = 'text/html';
          extension = 'html';
          break;
        case 'json':
          content = JSON.stringify(activeSessions, null, 2);
          mimeType = 'application/json';
          extension = 'json';
          break;
        case 'csv':
          content = convertToCSV(activeSessions);
          mimeType = 'text/csv';
          extension = 'csv';
          break;
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${new Date().toISOString().split('T')[0]}.${extension}`;
      a.click();
      URL.revokeObjectURL(url);

      toast({
        title: "Report Generated",
        description: `${format.toUpperCase()} report has been downloaded successfully.`
      });
    } catch (error) {
      toast({
        title: "Export Failed",
        description: "Failed to generate the report. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const convertToHTML = (markdown: string) => {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Security Assessment Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
          .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
          .stat-card { padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
          .findings { margin: 20px 0; }
          .severity-critical { color: #dc2626; }
          .severity-high { color: #ea580c; }
          .severity-medium { color: #ca8a04; }
          .severity-low { color: #2563eb; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>Security Assessment Report</h1>
          <p>Generated on: ${new Date().toLocaleString()}</p>
        </div>
        <pre>${markdown}</pre>
      </body>
      </html>
    `;
  };

  const convertToCSV = (sessions: any[]) => {
    const headers = ['Timestamp', 'Target', 'Tool', 'Status', 'Findings', 'Duration'];
    const rows = sessions.map(session => [
      session.startTime?.toISOString() || '',
      session.target,
      session.tool,
      session.status,
      session.findings.length,
      session.endTime ? formatDuration(session.startTime, session.endTime) : 'Running'
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
  };

  const handleClearResults = () => {
    clearSessions();
    setLiveOutput({});
    toast({
      title: "Results Cleared",
      description: "All scan results have been cleared successfully."
    });
  };

  return (
    <div className="space-y-6">
      {/* Statistics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-primary">{stats.total}</p>
              <p className="text-sm text-muted-foreground">Total Scans</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-green-600">{stats.completed}</p>
              <p className="text-sm text-muted-foreground">Completed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-600">{stats.running}</p>
              <p className="text-sm text-muted-foreground">Running</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-red-600">{stats.failed}</p>
              <p className="text-sm text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-orange-600">{stats.totalFindings}</p>
              <p className="text-sm text-muted-foreground">Findings</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Severity Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            Vulnerability Severity Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4">
            {[
              { label: 'Critical', count: stats.critical, color: 'text-red-600' },
              { label: 'High', count: stats.high, color: 'text-orange-600' },
              { label: 'Medium', count: stats.medium, color: 'text-yellow-600' },
              { label: 'Low', count: stats.low, color: 'text-blue-600' },
              { label: 'Info', count: stats.info, color: 'text-gray-600' }
            ].map((severity) => (
              <div key={severity.label} className="text-center p-3 bg-muted/50 rounded-lg">
                <p className={`text-2xl font-bold ${severity.color}`}>{severity.count}</p>
                <p className="text-sm text-muted-foreground">{severity.label}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="scans" className="space-y-4">
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="scans">Scan Results</TabsTrigger>
            <TabsTrigger value="findings">Detailed Findings</TabsTrigger>
            <TabsTrigger value="reports">Reports & Export</TabsTrigger>
            <TabsTrigger value="live">Live Output</TabsTrigger>
          </TabsList>
          
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" onClick={handleClearResults}>
              <Trash2 className="h-4 w-4 mr-1" />
              Clear All
            </Button>
          </div>
        </div>

        {/* Scan Results Tab */}
        <TabsContent value="scans" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Filter className="h-5 w-5 mr-2" />
                Filters & Search
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
                <div className="md:col-span-2">
                  <Input
                    placeholder="Search targets, tools..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full"
                  />
                </div>
                <Select value={filters.tool} onValueChange={(value) => setFilters(prev => ({ ...prev, tool: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Tool" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all-tools">All Tools</SelectItem>
                    <SelectItem value="nmap">Nmap</SelectItem>
                    <SelectItem value="nikto">Nikto</SelectItem>
                    <SelectItem value="sqlmap">SQLMap</SelectItem>
                    <SelectItem value="nuclei">Nuclei</SelectItem>
                    <SelectItem value="gobuster">Gobuster</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={filters.status} onValueChange={(value) => setFilters(prev => ({ ...prev, status: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all-status">All Status</SelectItem>
                    <SelectItem value="running">Running</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={filters.severity} onValueChange={(value) => setFilters(prev => ({ ...prev, severity: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all-severities">All Severities</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Button 
                  variant="outline" 
                  onClick={() => setFilters({ target: '', tool: 'all-tools', status: 'all-status', severity: 'all-severities', dateRange: '' })}
                >
                  Clear Filters
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Scan Results Table */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Results ({filteredSessions.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Target</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredSessions.map((session) => {
                    const Icon = getToolIcon(session.tool);
                    return (
                      <TableRow key={session.id}>
                        <TableCell className="font-medium">{session.target}</TableCell>
                        <TableCell>
                          <div className="flex items-center">
                            <Icon className="h-4 w-4 mr-2 text-primary" />
                            {session.tool.toUpperCase()}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(session.status)}>
                            {session.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <span className="font-medium">{session.findings.length}</span>
                            {session.findings.filter((f: any) => f.severity === 'critical').length > 0 && (
                              <Badge variant="destructive" className="text-xs">
                                {session.findings.filter((f: any) => f.severity === 'critical').length} Critical
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          {formatDuration(session.startTime, session.endTime)}
                        </TableCell>
                        <TableCell>
                          {session.startTime?.toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Dialog>
                              <DialogTrigger asChild>
                                <Button variant="outline" size="sm" onClick={() => setSelectedScan(session)}>
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="max-w-4xl max-h-[80vh]">
                                <DialogHeader>
                                  <DialogTitle>Scan Details: {session.target}</DialogTitle>
                                  <DialogDescription>
                                    {session.tool.toUpperCase()} scan results
                                  </DialogDescription>
                                </DialogHeader>
                                <ScrollArea className="h-96">
                                  <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                      <div>
                                        <h4 className="font-medium mb-2">Scan Information</h4>
                                        <div className="space-y-1 text-sm">
                                          <p><strong>Target:</strong> {session.target}</p>
                                          <p><strong>Tool:</strong> {session.tool}</p>
                                          <p><strong>Status:</strong> {session.status}</p>
                                          <p><strong>Findings:</strong> {session.findings.length}</p>
                                        </div>
                                      </div>
                                      <div>
                                        <h4 className="font-medium mb-2">Timing</h4>
                                        <div className="space-y-1 text-sm">
                                          <p><strong>Started:</strong> {session.startTime?.toLocaleString()}</p>
                                          <p><strong>Duration:</strong> {formatDuration(session.startTime, session.endTime)}</p>
                                          {session.status === 'running' && (
                                            <Progress value={session.progress || 0} className="w-full" />
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                    
                                    {session.findings.length > 0 && (
                                      <div>
                                        <h4 className="font-medium mb-2">Findings</h4>
                                        <div className="space-y-2">
                                          {session.findings.map((finding: any, index: number) => (
                                            <div key={index} className="p-3 bg-muted rounded-lg">
                                              <div className="flex items-center justify-between">
                                                <span className="font-medium">{finding.type || 'Unknown'}</span>
                                                <Badge className={getSeverityColor(finding.severity || 'info')}>
                                                  {finding.severity || 'info'}
                                                </Badge>
                                              </div>
                                              <p className="text-sm text-muted-foreground mt-1">
                                                {finding.description || finding.name || 'No description'}
                                              </p>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                    
                                    <div>
                                      <h4 className="font-medium mb-2">Raw Output</h4>
                                      <Textarea
                                        value={session.output || 'No output available'}
                                        readOnly
                                        className="min-h-40 font-mono text-xs"
                                      />
                                    </div>
                                  </div>
                                </ScrollArea>
                              </DialogContent>
                            </Dialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              
              {filteredSessions.length === 0 && (
                <div className="text-center py-8">
                  <TrendingUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Scan Results</p>
                  <p className="text-muted-foreground">
                    Start a security scan to see results here
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Detailed Findings Tab */}
        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>All Findings</CardTitle>
              <CardDescription>Comprehensive list of all discovered vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {activeSessions.flatMap(session => 
                  session.findings.map((finding: any, index: number) => (
                    <div key={`${session.id}-${index}`} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">{session.tool.toUpperCase()}</Badge>
                          <span className="text-sm text-muted-foreground">{session.target}</span>
                        </div>
                        <Badge className={getSeverityColor(finding.severity || 'info')}>
                          {finding.severity || 'info'}
                        </Badge>
                      </div>
                      <h4 className="font-medium">{finding.type || finding.name || 'Unknown Finding'}</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        {finding.description || 'No description available'}
                      </p>
                      {finding.templateId && (
                        <p className="text-xs text-muted-foreground mt-1">
                          Template: {finding.templateId}
                        </p>
                      )}
                    </div>
                  ))
                )}
                
                {activeSessions.every(s => s.findings.length === 0) && (
                  <div className="text-center py-8">
                    <Bug className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Findings</p>
                    <p className="text-muted-foreground">
                      Run security scans to discover vulnerabilities
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Reports & Export Tab */}
        <TabsContent value="reports" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Export Reports</CardTitle>
              <CardDescription>Generate and download security assessment reports</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button 
                  onClick={() => exportReport('html')} 
                  disabled={isGeneratingReport}
                  className="h-20 flex-col space-y-2"
                >
                  <FileText className="h-6 w-6" />
                  <span>HTML Report</span>
                </Button>
                <Button 
                  onClick={() => exportReport('json')} 
                  disabled={isGeneratingReport}
                  variant="secondary"
                  className="h-20 flex-col space-y-2"
                >
                  <FileText className="h-6 w-6" />
                  <span>JSON Export</span>
                </Button>
                <Button 
                  onClick={() => exportReport('csv')} 
                  disabled={isGeneratingReport}
                  variant="secondary"
                  className="h-20 flex-col space-y-2"
                >
                  <BarChart3 className="h-6 w-6" />
                  <span>CSV Export</span>
                </Button>
                <Button 
                  onClick={() => exportReport('pdf')} 
                  disabled={isGeneratingReport}
                  variant="secondary"
                  className="h-20 flex-col space-y-2"
                >
                  <FileText className="h-6 w-6" />
                  <span>PDF Report</span>
                </Button>
              </div>
              
              {isGeneratingReport && (
                <div className="mt-4 p-4 bg-muted rounded-lg">
                  <div className="flex items-center space-x-2">
                    <div className="animate-spin">
                      <Zap className="h-4 w-4" />
                    </div>
                    <span>Generating report...</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Live Output Tab */}
        <TabsContent value="live" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Live Scan Output</CardTitle>
              <CardDescription>Real-time output from running scans</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(liveOutput).map(([sessionId, outputs]) => {
                  const session = activeSessions.find(s => s.id === sessionId);
                  if (!session) return null;
                  
                  return (
                    <div key={sessionId} className="border rounded-lg">
                      <div className="p-3 bg-muted/50 border-b flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Terminal className="h-4 w-4" />
                          <span className="font-medium">{session.tool.toUpperCase()}</span>
                          <span className="text-sm text-muted-foreground">{session.target}</span>
                        </div>
                        <Badge className={getStatusColor(session.status)}>
                          {session.status}
                        </Badge>
                      </div>
                      <div className="p-3">
                        <ScrollArea className="h-40">
                          <div className="font-mono text-xs space-y-1">
                            {outputs.map((line, index) => (
                              <div key={index} className="text-green-600 dark:text-green-400">
                                {line}
                              </div>
                            ))}
                            {outputs.length === 0 && session.status === 'running' && (
                              <div className="text-muted-foreground">Waiting for output...</div>
                            )}
                          </div>
                        </ScrollArea>
                      </div>
                    </div>
                  );
                })}
                
                {Object.keys(liveOutput).length === 0 && (
                  <div className="text-center py-8">
                    <Terminal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Active Scans</p>
                    <p className="text-muted-foreground">
                      Start a scan to see live output here
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EnhancedScanResults;