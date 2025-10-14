import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { useKaliTools } from "@/hooks/useKaliTools";
import { 
  Shield,
  Smartphone,
  Laptop,
  Computer,
  Network,
  Terminal,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Play,
  X
} from "lucide-react";

interface Agent {
  id: string;
  name: string;
  platform: 'windows' | 'linux' | 'android';
  status: 'online' | 'offline' | 'scanning';
  lastSeen: Date;
  ipAddress: string;
  osVersion: string;
  capabilities: string[];
  currentScan?: string;
}

interface EndpointScanConfig {
  agentId: string;
  scanTypes: ('network' | 'os' | 'application' | 'vulnerability')[];
  target: string;
}

const AgentManagement = () => {
  const { toast } = useToast();
  const { runNetworkScan, runWebScan, runVulnerabilityScan, activeSessions, isKaliEnvironment } = useKaliTools();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [scanConfig, setScanConfig] = useState<EndpointScanConfig>({
    agentId: '',
    scanTypes: ['network', 'os', 'application', 'vulnerability'],
    target: ''
  });

  useEffect(() => {
    const savedAgents = localStorage.getItem('vapt_agents');
    if (savedAgents) {
      const parsed = JSON.parse(savedAgents);
      const agentsWithDates = parsed.map((agent: any) => ({
        ...agent,
        lastSeen: new Date(agent.lastSeen)
      }));
      setAgents(agentsWithDates);
    }
  }, []);

  useEffect(() => {
    if (agents.length > 0) {
      const agentsToSave = agents.map(agent => ({
        ...agent,
        lastSeen: agent.lastSeen.toISOString()
      }));
      localStorage.setItem('vapt_agents', JSON.stringify(agentsToSave));
    }
  }, [agents]);

  const startEndpointScan = async (agent: Agent) => {
    if (!isKaliEnvironment) {
      toast({
        title: "Backend Required",
        description: "Please ensure the Kali backend is running to perform endpoint scans",
        variant: "destructive"
      });
      return;
    }

    if (!scanConfig.target) {
      setScanConfig(prev => ({ ...prev, target: agent.ipAddress }));
    }

    const target = scanConfig.target || agent.ipAddress;

    // Update agent status
    setAgents(prev => prev.map(a => 
      a.id === agent.id ? { ...a, status: 'scanning', currentScan: 'Initializing...' } : a
    ));

    toast({
      title: "Endpoint Scan Started",
      description: `Scanning ${agent.name} at ${target}`,
    });

    try {
      // Network scan
      if (scanConfig.scanTypes.includes('network')) {
        setAgents(prev => prev.map(a => 
          a.id === agent.id ? { ...a, currentScan: 'Network Scanning...' } : a
        ));
        await runNetworkScan(target, 'comprehensive');
      }

      // OS and service detection
      if (scanConfig.scanTypes.includes('os')) {
        setAgents(prev => prev.map(a => 
          a.id === agent.id ? { ...a, currentScan: 'OS Detection...' } : a
        ));
        await runNetworkScan(target, 'service-detection');
      }

      // Web application scan
      if (scanConfig.scanTypes.includes('application')) {
        setAgents(prev => prev.map(a => 
          a.id === agent.id ? { ...a, currentScan: 'Application Scanning...' } : a
        ));
        await runWebScan(target);
      }

      // Vulnerability assessment
      if (scanConfig.scanTypes.includes('vulnerability')) {
        setAgents(prev => prev.map(a => 
          a.id === agent.id ? { ...a, currentScan: 'Vulnerability Assessment...' } : a
        ));
        await runVulnerabilityScan(target);
      }

      setAgents(prev => prev.map(a => 
        a.id === agent.id ? { 
          ...a, 
          status: 'online', 
          currentScan: undefined,
          lastSeen: new Date()
        } : a
      ));

      toast({
        title: "Endpoint Scan Complete",
        description: `Successfully scanned ${agent.name}`,
      });
    } catch (error) {
      setAgents(prev => prev.map(a => 
        a.id === agent.id ? { ...a, status: 'online', currentScan: undefined } : a
      ));

      toast({
        title: "Scan Failed",
        description: error instanceof Error ? error.message : "Failed to complete endpoint scan",
        variant: "destructive"
      });
    }
  };

  const addTestAgent = (platform: 'windows' | 'linux' | 'android') => {
    const newAgent: Agent = {
      id: `agent_${Date.now()}`,
      name: `${platform.charAt(0).toUpperCase() + platform.slice(1)} Endpoint`,
      platform,
      status: 'online',
      lastSeen: new Date(),
      ipAddress: `192.168.1.${Math.floor(Math.random() * 200 + 10)}`,
      osVersion: platform === 'windows' ? 'Windows 11 Pro' : 
                 platform === 'linux' ? 'Ubuntu 22.04 LTS' : 'Android 13',
      capabilities: ['network-scan', 'port-scan', 'vulnerability-scan', 'service-detection']
    };

    setAgents(prev => [...prev, newAgent]);
    toast({
      title: "Agent Added",
      description: `${newAgent.name} has been registered`,
    });
  };

  const removeAgent = (agentId: string) => {
    setAgents(prev => prev.filter(a => a.id !== agentId));
    toast({
      title: "Agent Removed",
      description: "Agent has been unregistered",
    });
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'online': return 'bg-green-500';
      case 'offline': return 'bg-red-500';
      case 'scanning': return 'bg-yellow-500';
      default: return 'bg-gray-500';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'windows': return Computer;
      case 'linux': return Terminal;
      case 'android': return Smartphone;
      default: return Laptop;
    }
  };

  const toggleScanType = (type: 'network' | 'os' | 'application' | 'vulnerability') => {
    setScanConfig(prev => ({
      ...prev,
      scanTypes: prev.scanTypes.includes(type)
        ? prev.scanTypes.filter(t => t !== type)
        : [...prev.scanTypes, type]
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Endpoint Security</h2>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => addTestAgent('windows')}>
            <Computer className="h-4 w-4 mr-2" />
            Add Windows
          </Button>
          <Button variant="outline" onClick={() => addTestAgent('linux')}>
            <Terminal className="h-4 w-4 mr-2" />
            Add Linux
          </Button>
          <Button variant="outline" onClick={() => addTestAgent('android')}>
            <Smartphone className="h-4 w-4 mr-2" />
            Add Android
          </Button>
        </div>
      </div>

      {!isKaliEnvironment && (
        <Card className="border-yellow-500">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <p className="text-sm">Backend not connected. Start the Kali backend to enable endpoint scanning.</p>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="endpoints" className="space-y-4">
        <TabsList>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="scanning">Active Scans</TabsTrigger>
        </TabsList>

        <TabsContent value="endpoints" className="space-y-4">
          {agents.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No Endpoints Registered</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Add endpoints to start comprehensive security testing
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {agents.map((agent) => {
                const PlatformIcon = getPlatformIcon(agent.platform);
                return (
                  <Card key={agent.id}>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <PlatformIcon className="h-6 w-6 text-primary" />
                          <div>
                            <CardTitle className="text-lg">{agent.name}</CardTitle>
                            <p className="text-sm text-muted-foreground">
                              {agent.ipAddress} • {agent.osVersion}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="capitalize">
                            {agent.platform}
                          </Badge>
                          <div className={`w-3 h-3 rounded-full ${getStatusColor(agent.status)}`} />
                          <Badge variant={agent.status === 'online' ? 'default' : 'secondary'}>
                            {agent.status}
                          </Badge>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {agent.currentScan && (
                        <div className="mb-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg flex items-center gap-2">
                          <Activity className="h-4 w-4 text-yellow-500 animate-pulse" />
                          <span className="text-sm font-medium">{agent.currentScan}</span>
                        </div>
                      )}

                      <div className="flex items-center justify-between">
                        <div className="text-sm text-muted-foreground flex items-center gap-2">
                          <Clock className="h-4 w-4" />
                          Last seen: {agent.lastSeen.toLocaleString()}
                        </div>
                        <div className="flex gap-2">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button 
                                size="sm" 
                                disabled={agent.status === 'scanning'}
                                onClick={() => {
                                  setSelectedAgent(agent);
                                  setScanConfig(prev => ({ ...prev, agentId: agent.id, target: agent.ipAddress }));
                                }}
                              >
                                <Play className="h-4 w-4 mr-1" />
                                Scan Endpoint
                              </Button>
                            </DialogTrigger>
                            <DialogContent>
                              <DialogHeader>
                                <DialogTitle>Configure Endpoint Scan</DialogTitle>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div>
                                  <label className="text-sm font-medium mb-2 block">Target IP</label>
                                  <input
                                    type="text"
                                    className="w-full px-3 py-2 border rounded-md"
                                    value={scanConfig.target}
                                    onChange={(e) => setScanConfig(prev => ({ ...prev, target: e.target.value }))}
                                    placeholder="192.168.1.100"
                                  />
                                </div>
                                <div>
                                  <label className="text-sm font-medium mb-2 block">Scan Types</label>
                                  <div className="grid grid-cols-2 gap-2">
                                    {(['network', 'os', 'application', 'vulnerability'] as const).map(type => (
                                      <Button
                                        key={type}
                                        variant={scanConfig.scanTypes.includes(type) ? "default" : "outline"}
                                        size="sm"
                                        onClick={() => toggleScanType(type)}
                                        className="justify-start capitalize"
                                      >
                                        {scanConfig.scanTypes.includes(type) ? (
                                          <CheckCircle className="h-4 w-4 mr-2" />
                                        ) : (
                                          <Network className="h-4 w-4 mr-2" />
                                        )}
                                        {type}
                                      </Button>
                                    ))}
                                  </div>
                                </div>
                                <Button 
                                  className="w-full" 
                                  onClick={() => {
                                    if (selectedAgent) startEndpointScan(selectedAgent);
                                  }}
                                >
                                  Start Comprehensive Scan
                                </Button>
                              </div>
                            </DialogContent>
                          </Dialog>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => removeAgent(agent.id)}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="scanning" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Scans</CardTitle>
            </CardHeader>
            <CardContent>
              {activeSessions.filter(s => s.status === 'running').length === 0 ? (
                <p className="text-muted-foreground text-center py-8">No active scans</p>
              ) : (
                <div className="space-y-3">
                  {activeSessions.filter(s => s.status === 'running').map(session => (
                    <div key={session.id} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium">{session.tool.toUpperCase()}</p>
                          <p className="text-sm text-muted-foreground">{session.target}</p>
                        </div>
                        <Badge variant="outline" className="animate-pulse">
                          {session.progress}%
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AgentManagement;
