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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
  Zap,
  HelpCircle
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";
import { useToast } from "@/components/ui/use-toast";
import { ExaInsights } from "./ExaInsights";
import { ScanModeSelector, ScanMode } from "./ScanModeSelector";
import agentGenerator from "@/utils/agentGenerator";
import TroubleshootingHelper from "./TroubleshootingHelper";

interface FilterState {
  target: string;
  tool: string;
  status: string;
  severity: string;
  dateRange: string;
}

const EnhancedScanResults = () => {
  const { activeSessions, generateReport, clearSessions, isKaliEnvironment } = useKaliTools();
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
  const [showTroubleshooting, setShowTroubleshooting] = useState(false);
  const [troubleshootingType, setTroubleshootingType] = useState<'connection' | 'timeout' | 'privilege' | 'tool-missing' | 'scan-failed'>('connection');
  const [scanMode, setScanMode] = useState<ScanMode>('passive');

  // Real-time output streaming from active sessions
  useEffect(() => {
    const newLiveOutput: Record<string, string[]> = {};
    
    activeSessions.forEach(session => {
      if (session.output) {
        // Split output into lines and keep recent ones
        const lines = session.output.split('\n').filter(line => line.trim());
        newLiveOutput[session.id] = lines.slice(-50); // Keep last 50 lines
      }
    });
    
    setLiveOutput(newLiveOutput);
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
      // Generate comprehensive report with all scan data
      const report = await generateReport();
      let content: string;
      let mimeType: string;
      let extension: string;

      switch (format) {
        case 'html':
          content = convertToHTML(report);
          mimeType = 'text/html';
          extension = 'html';
          break;
        case 'json':
          // Include full scan data with findings
          const exportData = activeSessions.map(session => ({
            ...session,
            startTime: session.startTime?.toISOString(),
            endTime: session.endTime?.toISOString(),
            duration: session.endTime ? formatDuration(session.startTime, session.endTime) : 'In Progress'
          }));
          content = JSON.stringify(exportData, null, 2);
          mimeType = 'application/json';
          extension = 'json';
          break;
        case 'csv':
          content = convertToCSV(activeSessions);
          mimeType = 'text/csv';
          extension = 'csv';
          break;
        case 'pdf':
          // For now, export as HTML (PDF generation would require additional library)
          content = convertToHTML(report);
          mimeType = 'text/html';
          extension = 'html';
          toast({
            title: "PDF Export",
            description: "Exporting as HTML. Use browser 'Print to PDF' for PDF format.",
          });
          break;
        default:
          content = report;
          mimeType = 'text/plain';
          extension = 'txt';
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${new Date().toISOString().split('T')[0]}.${extension}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "Report Exported",
        description: `${format.toUpperCase()} report has been downloaded successfully.`
      });
    } catch (error: any) {
      console.error('Export error:', error);
      toast({
        title: "Export Failed",
        description: error.message || "Failed to generate the report. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const convertToHTML = (markdown: string) => {
    // Create comprehensive HTML report with all scan details
    const scansHTML = activeSessions.map(session => `
      <div class="scan-entry">
        <h3>${session.tool.toUpperCase()} - ${session.target}</h3>
        <p><strong>Status:</strong> <span class="status-${session.status}">${session.status}</span></p>
        <p><strong>Started:</strong> ${session.startTime?.toLocaleString() || 'N/A'}</p>
        <p><strong>Duration:</strong> ${session.endTime ? formatDuration(session.startTime, session.endTime) : 'In Progress'}</p>
        <p><strong>Findings:</strong> ${session.findings.length}</p>
        ${session.findings.length > 0 ? `
          <div class="findings">
            <h4>Findings:</h4>
            <ul>
              ${session.findings.map((f: any) => `
                <li class="severity-${f.severity}">
                  <strong>[${f.severity?.toUpperCase() || 'INFO'}]</strong> ${f.title || f.description || 'Finding'}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : ''}
        <details>
          <summary>View Full Output</summary>
          <pre class="output">${session.output || 'No output available'}</pre>
        </details>
      </div>
    `).join('');

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Security Assessment Report - ${new Date().toLocaleDateString()}</title>
        <meta charset="UTF-8">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
          .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { border-bottom: 3px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
          .header h1 { margin: 0; color: #333; }
          .header p { color: #666; margin: 10px 0 0 0; }
          .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
          .stat-card { padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }
          .stat-card h3 { margin: 0; font-size: 14px; color: #666; text-transform: uppercase; }
          .stat-card .value { font-size: 32px; font-weight: bold; margin: 10px 0; }
          .scan-entry { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }
          .scan-entry h3 { margin: 0 0 15px 0; color: #333; }
          .findings { margin: 15px 0; }
          .findings ul { margin: 10px 0; padding-left: 20px; }
          .findings li { margin: 8px 0; line-height: 1.6; }
          .status-completed { color: #16a34a; font-weight: bold; }
          .status-running { color: #2563eb; font-weight: bold; }
          .status-failed { color: #dc2626; font-weight: bold; }
          .severity-critical { color: #dc2626; font-weight: bold; }
          .severity-high { color: #ea580c; font-weight: bold; }
          .severity-medium { color: #ca8a04; font-weight: bold; }
          .severity-low { color: #2563eb; }
          .severity-info { color: #6b7280; }
          .output { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
          details { margin-top: 15px; }
          summary { cursor: pointer; font-weight: bold; color: #2563eb; }
          summary:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <p>Generated on: ${new Date().toLocaleString()}</p>
            <p>Total Scans: ${stats.total} | Completed: ${stats.completed} | Running: ${stats.running} | Failed: ${stats.failed}</p>
          </div>
          
          <div class="stats">
            <div class="stat-card">
              <h3>Total Findings</h3>
              <div class="value">${stats.totalFindings}</div>
            </div>
            <div class="stat-card">
              <h3>Critical</h3>
              <div class="value" style="color: #dc2626;">${stats.critical}</div>
            </div>
            <div class="stat-card">
              <h3>High</h3>
              <div class="value" style="color: #ea580c;">${stats.high}</div>
            </div>
            <div class="stat-card">
              <h3>Medium</h3>
              <div class="value" style="color: #ca8a04;">${stats.medium}</div>
            </div>
            <div class="stat-card">
              <h3>Low</h3>
              <div class="value" style="color: #2563eb;">${stats.low}</div>
            </div>
          </div>
          
          <h2>Scan Results</h2>
          ${scansHTML || '<p>No scan results available.</p>'}
          
          <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ddd; color: #666; font-size: 12px;">
            <p>This report was generated by the VAPT Security Assessment Tool</p>
            <p>For questions or concerns, please contact your security team.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  };

  const convertToCSV = (sessions: any[]) => {
    // Enhanced CSV with more details
    const headers = [
      'Timestamp', 
      'Target', 
      'Tool', 
      'Status', 
      'Total Findings', 
      'Critical', 
      'High', 
      'Medium', 
      'Low',
      'Duration',
      'Output Length'
    ];
    
    const rows = sessions.map(session => {
      const severityCounts = session.findings.reduce((acc: any, f: any) => {
        const sev = f.severity || 'info';
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
      }, {});
      
      return [
        session.startTime?.toISOString() || 'N/A',
        `"${session.target}"`,
        session.tool,
        session.status,
        session.findings.length,
        severityCounts.critical || 0,
        severityCounts.high || 0,
        severityCounts.medium || 0,
        severityCounts.low || 0,
        session.endTime ? formatDuration(session.startTime, session.endTime) : 'In Progress',
        session.output?.length || 0
      ];
    });
    
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
      {/* Troubleshooting Helper */}
      {showTroubleshooting && (
        <TroubleshootingHelper 
          errorType={troubleshootingType}
          toolName="nmap"
        />
      )}

      {/* Setup Guide Alert for Non-Connected Users */}
      {!isKaliEnvironment && (
        <Alert className="border-warning bg-warning/10">
          <HelpCircle className="h-4 w-4" />
          <AlertTitle>Need Help Getting Started?</AlertTitle>
          <AlertDescription className="flex items-center justify-between">
            <span>Backend not connected. Click here for step-by-step setup instructions.</span>
            <Button 
              size="sm" 
              variant="outline"
              onClick={() => {
                setTroubleshootingType('connection');
                setShowTroubleshooting(true);
              }}
            >
              Show Setup Guide
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Statistics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Connection Status */}
        <Card>
          <CardContent className="p-4">
            <div className="text-center">
              <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                isKaliEnvironment 
                  ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400' 
                  : 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
              }`}>
                {isKaliEnvironment ? '● Connected' : '● Disconnected'}
              </div>
              <p className="text-sm text-muted-foreground mt-2">Backend Status</p>
            </div>
          </CardContent>
        </Card>
        
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
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => {
                setTroubleshootingType('scan-failed');
                setShowTroubleshooting(!showTroubleshooting);
              }}
            >
              <HelpCircle className="h-4 w-4 mr-2" />
              {showTroubleshooting ? 'Hide' : 'Help'}
            </Button>
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
                  {filteredSessions.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8">
                        <div className="space-y-3">
                          <Shield className="h-12 w-12 mx-auto text-muted-foreground" />
                          <p className="text-muted-foreground">No scans yet. Start a scan from Target Input.</p>
                          {!isKaliEnvironment && (
                            <div className="text-sm text-orange-600 dark:text-orange-400">
                              ⚠ Backend not connected. Start the server: <code className="px-2 py-1 bg-muted rounded">cd server && node index.js</code>
                            </div>
                          )}
                          <div>
                            <p className="text-lg font-medium mb-2">No Scan Results</p>
                            <p className="text-muted-foreground mb-4">
                              Start running security scans to see results here
                            </p>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredSessions.map((session, index) => {
                      const ToolIcon = getToolIcon(session.tool);
                      
                      return (
                        <TableRow key={session.id || index}>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <Target className="h-4 w-4 text-muted-foreground" />
                              <span className="font-medium">{session.target || 'Unknown'}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <ToolIcon className="h-4 w-4" />
                              <Badge variant="outline">{session.tool.toUpperCase()}</Badge>
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
                              {session.findings.length > 0 && (
                                <div className="flex space-x-1">
                                  {['critical', 'high', 'medium', 'low'].map(severity => {
                                    const count = session.findings.filter((f: any) => f.severity === severity).length;
                                    if (count > 0) {
                                      return (
                                        <Badge key={severity} className={getSeverityColor(severity)} variant="secondary">
                                          {count}
                                        </Badge>
                                      );
                                    }
                                    return null;
                                  })}
                                </div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            {session.startTime ? formatDuration(session.startTime, session.endTime) : 'N/A'}
                          </TableCell>
                          <TableCell>
                            {session.startTime ? session.startTime.toLocaleString() : 'N/A'}
                          </TableCell>
                          <TableCell>
                            <Dialog>
                              <DialogTrigger asChild>
                                <Button variant="ghost" size="sm">
                                  <Eye className="h-4 w-4 mr-1" />
                                  View
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="max-w-4xl max-h-[80vh]">
                                <DialogHeader>
                                  <DialogTitle className="flex items-center space-x-2">
                                    <ToolIcon className="h-5 w-5" />
                                    <span>{session.tool.toUpperCase()} Results - {session.target}</span>
                                  </DialogTitle>
                                  <DialogDescription>
                                    Scan completed on {session.endTime?.toLocaleString() || 'In Progress'}
                                  </DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4">
                                  <Tabs defaultValue="output" className="w-full">
                                    <TabsList>
                                      <TabsTrigger value="output">Raw Output</TabsTrigger>
                                      <TabsTrigger value="findings">Findings ({session.findings.length})</TabsTrigger>
                                    </TabsList>
                                    <TabsContent value="output">
                                      <ScrollArea className="h-60 w-full border rounded-md p-4">
                                        <pre className="text-xs font-mono">
                                          {session.output || 'No output available'}
                                        </pre>
                                      </ScrollArea>
                                    </TabsContent>
                                    <TabsContent value="findings">
                                      <ScrollArea className="h-60 w-full border rounded-md p-4">
                                        <div className="space-y-3">
                                          {session.findings.length > 0 ? (
                                            session.findings.map((finding: any, index: number) => (
                                              <div key={index} className="p-3 border rounded-lg">
                                                <div className="flex items-center justify-between mb-2">
                                                  <h4 className="font-medium">{finding.title || `Finding ${index + 1}`}</h4>
                                                  {finding.severity && (
                                                    <Badge className={getSeverityColor(finding.severity)}>
                                                      {finding.severity}
                                                    </Badge>
                                                  )}
                                                </div>
                                                <p className="text-sm text-muted-foreground">
                                                  {finding.description || finding.details || 'No description available'}
                                                </p>
                                              </div>
                                            ))
                                          ) : (
                                            <p className="text-center text-muted-foreground">No findings detected</p>
                                          )}
                                        </div>
                                      </ScrollArea>
                                    </TabsContent>
                                  </Tabs>
                                </div>
                              </DialogContent>
                            </Dialog>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
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
              <CardDescription>Real-time streaming output from running security scans</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(liveOutput).map(([sessionId, outputs]) => {
                  const session = activeSessions.find(s => s.id === sessionId);
                  if (!session) return null;
                  
                  const ToolIcon = getToolIcon(session.tool);
                  
                  return (
                    <div key={sessionId} className="border rounded-lg overflow-hidden">
                      <div className="p-3 bg-muted/50 border-b">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <ToolIcon className="h-4 w-4" />
                            <span className="font-medium">{session.tool.toUpperCase()}</span>
                            <span className="text-sm text-muted-foreground">{session.target}</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            {session.status === 'running' && (
                              <div className="flex items-center space-x-1">
                                <div className="animate-pulse h-2 w-2 bg-blue-500 rounded-full"></div>
                                <span className="text-xs text-muted-foreground">Live</span>
                              </div>
                            )}
                            <Badge className={getStatusColor(session.status)}>
                              {session.status}
                            </Badge>
                          </div>
                        </div>
                        {session.progress > 0 && session.progress < 100 && (
                          <div className="space-y-1">
                            <Progress value={session.progress} className="h-1" />
                            <span className="text-xs text-muted-foreground">{session.progress}% complete</span>
                          </div>
                        )}
                      </div>
                      <div className="bg-slate-950 p-4">
                        <ScrollArea className="h-60">
                          <div className="font-mono text-xs space-y-0.5">
                            {outputs.length > 0 ? (
                              outputs.map((line, index) => (
                                <div key={index} className="text-green-400 whitespace-pre-wrap break-all">
                                  {line}
                                </div>
                              ))
                            ) : session.status === 'running' ? (
                              <div className="text-cyan-400 animate-pulse">
                                ● Initializing scan...
                              </div>
                            ) : (
                              <div className="text-yellow-400">
                                ⚠ No output captured
                              </div>
                            )}
                            {session.status === 'running' && outputs.length > 0 && (
                              <div className="text-cyan-400 animate-pulse mt-2">▌</div>
                            )}
                          </div>
                        </ScrollArea>
                      </div>
                      <div className="p-2 bg-muted/30 border-t flex items-center justify-between text-xs text-muted-foreground">
                        <span>Output lines: {outputs.length}</span>
                        <span>Started: {session.startTime?.toLocaleTimeString() || 'N/A'}</span>
                      </div>
                    </div>
                  );
                })}
                
                {/* Running scans indicator */}
                {activeSessions.filter(s => s.status === 'running').length > 0 && Object.keys(liveOutput).length === 0 && (
                  <div className="text-center py-8">
                    <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4"></div>
                    <p className="text-lg font-medium mb-2">Connecting to scan output...</p>
                    <p className="text-muted-foreground">
                      Waiting for output stream from {activeSessions.filter(s => s.status === 'running').length} running scan(s)
                    </p>
                  </div>
                )}
                
                {Object.keys(liveOutput).length === 0 && activeSessions.filter(s => s.status === 'running').length === 0 && (
                  <div className="text-center py-8">
                    <Terminal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Active Scans</p>
                    <p className="text-muted-foreground mb-4">
                      Start a scan from Target Input to see live output here
                    </p>
                    {!isKaliEnvironment && (
                      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mt-4 max-w-md mx-auto">
                        <div className="flex items-start space-x-2">
                          <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                          <div className="text-left">
                            <h4 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">Backend Not Connected</h4>
                            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                              Start the backend server to enable real-time scanning:
                            </p>
                            <code className="text-xs bg-yellow-100 dark:bg-yellow-900/50 px-2 py-1 rounded mt-2 block">
                              cd server && node index.js
                            </code>
                            <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">
                              Then refresh this page and ensure API URL is set to http://localhost:8080 in Settings
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
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
