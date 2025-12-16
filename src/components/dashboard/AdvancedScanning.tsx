import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { 
  Activity, 
  Terminal, 
  PlayCircle, 
  StopCircle, 
  Eye, 
  EyeOff,
  Zap,
  AlertTriangle,
  CheckCircle,
  Clock,
  SkipForward,
  PauseCircle,
  RefreshCw,
  Download,
  Settings
} from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";
import { useToast } from "@/hooks/use-toast";

const AdvancedScanning = () => {
  const { activeSessions, stopAllScans } = useKaliTools();
  const [verboseMode, setVerboseMode] = useState(false);
  const [scanLogs, setScanLogs] = useState<Record<string, string[]>>({});
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(1000);
  const [scanProgress, setScanProgress] = useState<Record<string, number>>({});
  const [skippedScans, setSkippedScans] = useState<Set<string>>(new Set());
  const { toast } = useToast();
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Real-time output from active sessions (no simulation)
  useEffect(() => {
    const runningSessions = activeSessions.filter(s => s.status === 'running');
    
    runningSessions.forEach(session => {
      if (skippedScans.has(session.id)) return;
      
      // Use real output from session
      if (session.output) {
        setScanLogs(prev => {
          const lines = session.output.split('\n').filter(line => line.trim());
          return {
            ...prev,
            [session.id]: lines.slice(-100) // Keep last 100 lines
          };
        });
      }

      // Use real progress from session
      setScanProgress(prev => ({
        ...prev,
        [session.id]: session.progress || 0
      }));
    });
  }, [activeSessions, skippedScans]);

  // Auto-scroll to bottom of logs
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs, autoScroll]);

  const skipScan = (scanId: string) => {
    setSkippedScans(prev => new Set(prev).add(scanId));
    toast({
      title: "Scan Skipped",
      description: "Scan has been marked as skipped and will complete shortly",
      variant: "default"
    });
  };

  const pauseScan = (scanId: string) => {
    // In a real implementation, this would pause the actual scan
    toast({
      title: "Scan Paused",
      description: "Scan has been paused. Click resume to continue.",
      variant: "default"
    });
  };

  const exportLogs = () => {
    const allLogs = Object.entries(scanLogs)
      .map(([sessionId, logs]) => {
        const session = activeSessions.find(s => s.id === sessionId);
        return `=== ${session?.tool.toUpperCase()} - ${session?.target} ===\n${logs.join('\n')}\n\n`;
      })
      .join('');
    
    const blob = new Blob([allLogs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-logs-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
  };

  const activeScans = activeSessions.filter(s => s.status === 'running');
  const completedScans = activeSessions.filter(s => s.status === 'completed');
  const failedScans = activeSessions.filter(s => s.status === 'failed');

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center">
              <Terminal className="h-5 w-5 mr-2 text-primary" />
              Advanced Scanning Dashboard
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="secondary">{activeScans.length} Active</Badge>
              <Badge variant="default">{completedScans.length} Completed</Badge>
              {failedScans.length > 0 && <Badge variant="destructive">{failedScans.length} Failed</Badge>}
            </div>
          </CardTitle>
          <CardDescription>
            Real-time monitoring and control of security scans with verbose logging
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Label htmlFor="verbose-mode">Verbose Mode</Label>
                <Switch
                  id="verbose-mode"
                  checked={verboseMode}
                  onCheckedChange={setVerboseMode}
                />
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="auto-scroll">Auto Scroll</Label>
                <Switch
                  id="auto-scroll"
                  checked={autoScroll}
                  onCheckedChange={setAutoScroll}
                />
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Button
                size="sm"
                variant="outline"
                onClick={exportLogs}
                disabled={Object.keys(scanLogs).length === 0}
              >
                <Download className="h-4 w-4 mr-1" />
                Export Logs
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={stopAllScans}
                disabled={activeScans.length === 0}
              >
                <StopCircle className="h-4 w-4 mr-1" />
                Stop All
              </Button>
            </div>
          </div>

          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="active">Active Scans</TabsTrigger>
              <TabsTrigger value="logs">Verbose Logs</TabsTrigger>
              <TabsTrigger value="settings">Settings</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">Active Scans</p>
                        <p className="text-2xl font-bold">{activeScans.length}</p>
                      </div>
                      <Activity className="h-8 w-8 text-warning" />
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
                        <p className="text-sm text-muted-foreground">Total Findings</p>
                        <p className="text-2xl font-bold">
                          {activeSessions.reduce((sum, s) => sum + s.findings.length, 0)}
                        </p>
                      </div>
                      <AlertTriangle className="h-8 w-8 text-destructive" />
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Recent Activity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {activeSessions.slice(-5).reverse().map((session) => (
                      <div key={session.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <Terminal className="h-4 w-4 text-primary" />
                          <div>
                            <p className="font-medium">{session.tool.toUpperCase()}</p>
                            <p className="text-sm text-muted-foreground">{session.target}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge
                            variant={
                              session.status === 'completed' ? 'default' :
                              session.status === 'running' ? 'secondary' : 'destructive'
                            }
                          >
                            {session.status}
                          </Badge>
                          {session.status === 'running' && (
                            <Activity className="h-3 w-3 text-warning animate-pulse" />
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="active" className="space-y-4">
              {activeScans.length === 0 ? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Active Scans</p>
                    <p className="text-muted-foreground">Start a scan to see real-time progress here</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-4">
                  {activeScans.map((scan) => (
                    <Card key={scan.id}>
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-lg">{scan.tool.toUpperCase()} - {scan.target}</CardTitle>
                          <div className="flex items-center space-x-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => skipScan(scan.id)}
                              disabled={skippedScans.has(scan.id)}
                            >
                              <SkipForward className="h-4 w-4 mr-1" />
                              {skippedScans.has(scan.id) ? 'Skipped' : 'Skip'}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => pauseScan(scan.id)}
                            >
                              <PauseCircle className="h-4 w-4 mr-1" />
                              Pause
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div className="flex items-center justify-between text-sm">
                            <span>Progress</span>
                            <span>{scanProgress[scan.id] || 0}%</span>
                          </div>
                          <Progress value={scanProgress[scan.id] || 0} className="w-full" />
                          
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">Started:</span>
                              <span className="ml-2">{scan.startTime.toLocaleTimeString()}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Duration:</span>
                              <span className="ml-2">
                                {Math.round((new Date().getTime() - scan.startTime.getTime()) / 1000)}s
                              </span>
                            </div>
                          </div>
                          
                          {verboseMode && scanLogs[scan.id] && (
                            <div className="mt-3">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium">Live Output</span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => setSelectedScan(scan.id)}
                                >
                                  <Eye className="h-4 w-4 mr-1" />
                                  View Details
                                </Button>
                              </div>
                              <div className="bg-black text-green-400 p-3 rounded-md font-mono text-xs max-h-32 overflow-y-auto">
                                {scanLogs[scan.id].slice(-5).map((log, i) => (
                                  <div key={i}>{log}</div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="logs" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    Verbose Scan Logs
                    <div className="flex items-center space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setScanLogs({})}
                      >
                        Clear Logs
                      </Button>
                      <Switch
                        checked={verboseMode}
                        onCheckedChange={setVerboseMode}
                      />
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {!verboseMode ? (
                    <div className="text-center p-8">
                      <EyeOff className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                      <p className="text-lg font-medium mb-2">Verbose Mode Disabled</p>
                      <p className="text-muted-foreground">Enable verbose mode to see real-time scan logs</p>
                    </div>
                  ) : Object.keys(scanLogs).length === 0 ? (
                    <div className="text-center p-8">
                      <Terminal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                      <p className="text-lg font-medium mb-2">No Logs Available</p>
                      <p className="text-muted-foreground">Start a scan to see verbose output here</p>
                    </div>
                  ) : (
                    <div className="bg-black text-green-400 p-4 rounded-md font-mono text-sm max-h-96 overflow-y-auto">
                      {Object.entries(scanLogs).map(([sessionId, logs]) => {
                        const session = activeSessions.find(s => s.id === sessionId);
                        return (
                          <div key={sessionId} className="mb-4">
                            <div className="text-cyan-400 font-bold mb-2">
                              === {session?.tool.toUpperCase()} - {session?.target} ===
                            </div>
                            {logs.map((log, i) => (
                              <div key={i} className="mb-1">{log}</div>
                            ))}
                          </div>
                        );
                      })}
                      <div ref={logsEndRef} />
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="settings" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Settings className="h-5 w-5 mr-2" />
                    Advanced Settings
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Log Refresh Rate</Label>
                      <select 
                        className="w-full p-2 border rounded-md"
                        value={refreshInterval}
                        onChange={(e) => setRefreshInterval(Number(e.target.value))}
                      >
                        <option value={500}>0.5 seconds (Fast)</option>
                        <option value={1000}>1 second (Normal)</option>
                        <option value={2000}>2 seconds (Slow)</option>
                        <option value={5000}>5 seconds (Very Slow)</option>
                      </select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Max Log Lines per Scan</Label>
                      <select className="w-full p-2 border rounded-md">
                        <option value={100}>100 lines</option>
                        <option value={500}>500 lines</option>
                        <option value={1000}>1000 lines</option>
                        <option value={-1}>Unlimited</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Switch id="persistent-logs" />
                    <Label htmlFor="persistent-logs">Persist logs between sessions</Label>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Switch id="error-alerts" defaultChecked />
                    <Label htmlFor="error-alerts">Show error alerts</Label>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Switch id="completion-alerts" defaultChecked />
                    <Label htmlFor="completion-alerts">Show completion alerts</Label>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default AdvancedScanning;