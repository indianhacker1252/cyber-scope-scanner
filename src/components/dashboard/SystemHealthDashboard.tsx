import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "@/hooks/use-toast";
import { 
  Activity, Server, Wifi, WifiOff, RefreshCw, Trash2, 
  PlusCircle, Heart, Shield, Clock, BarChart3, Loader2
} from "lucide-react";

interface Agent {
  id: string;
  agent_name: string;
  agent_type: string;
  status: string;
  target_endpoint: string | null;
  last_heartbeat: string | null;
  configuration: any;
  metrics: any;
  created_at: string;
}

const SystemHealthDashboard = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [newAgentName, setNewAgentName] = useState("");
  const [newAgentType, setNewAgentType] = useState("scanner");
  const [newAgentEndpoint, setNewAgentEndpoint] = useState("");

  useEffect(() => {
    loadAgents();
    // Realtime subscription for heartbeat updates
    const channel = supabase
      .channel("audit-agents")
      .on("postgres_changes", { event: "*", schema: "public", table: "audit_agents" }, () => {
        loadAgents();
      })
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, []);

  const loadAgents = async () => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data } = await supabase.from("audit_agents").select("*").eq("user_id", user.id).order("created_at", { ascending: false });
    if (data) setAgents(data);
    setLoading(false);
  };

  const createAgent = async () => {
    if (!newAgentName) {
      toast({ title: "Error", description: "Agent name required", variant: "destructive" });
      return;
    }
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { error } = await supabase.from("audit_agents").insert({
      user_id: user.id,
      agent_name: newAgentName,
      agent_type: newAgentType,
      target_endpoint: newAgentEndpoint || null,
      status: "active",
      configuration: { autoReconnect: true, scanInterval: 300 },
      metrics: { scansCompleted: 0, findingsCount: 0, uptime: 0 },
    });
    if (error) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } else {
      setNewAgentName("");
      setNewAgentEndpoint("");
      toast({ title: "Agent Created", description: `${newAgentName} is now active` });
      loadAgents();
    }
  };

  const updateAgentStatus = async (id: string, status: string) => {
    const { error } = await supabase.from("audit_agents").update({ status, last_heartbeat: new Date().toISOString() }).eq("id", id);
    if (error) toast({ title: "Error", description: error.message, variant: "destructive" });
    else {
      toast({ title: "Agent Updated", description: `Status: ${status}` });
      loadAgents();
    }
  };

  const deleteAgent = async (id: string) => {
    const { error } = await supabase.from("audit_agents").delete().eq("id", id);
    if (error) toast({ title: "Error", description: error.message, variant: "destructive" });
    else {
      toast({ title: "Agent Terminated" });
      loadAgents();
    }
  };

  const heartbeatAge = (hb: string | null) => {
    if (!hb) return "Never";
    const diff = Date.now() - new Date(hb).getTime();
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return `${Math.floor(diff / 3600000)}h ago`;
  };

  const statusColor = (s: string) => {
    switch (s) {
      case "active": return "bg-green-500/20 text-green-400 border-green-500/30";
      case "paused": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "terminated": return "bg-red-500/20 text-red-400 border-red-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const activeCount = agents.filter(a => a.status === "active").length;
  const pausedCount = agents.filter(a => a.status === "paused").length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Activity className="h-6 w-6 text-primary" /> System Health Dashboard
          </h2>
          <p className="text-muted-foreground mt-1">Monitor and manage active audit agents</p>
        </div>
        <Button variant="outline" size="sm" onClick={loadAgents}><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card><CardContent className="pt-4 text-center">
          <Server className="h-8 w-8 mx-auto text-primary mb-2" />
          <p className="text-2xl font-bold text-foreground">{agents.length}</p>
          <p className="text-xs text-muted-foreground">Total Agents</p>
        </CardContent></Card>
        <Card><CardContent className="pt-4 text-center">
          <Wifi className="h-8 w-8 mx-auto text-green-400 mb-2" />
          <p className="text-2xl font-bold text-green-400">{activeCount}</p>
          <p className="text-xs text-muted-foreground">Active</p>
        </CardContent></Card>
        <Card><CardContent className="pt-4 text-center">
          <Clock className="h-8 w-8 mx-auto text-yellow-400 mb-2" />
          <p className="text-2xl font-bold text-yellow-400">{pausedCount}</p>
          <p className="text-xs text-muted-foreground">Paused</p>
        </CardContent></Card>
        <Card><CardContent className="pt-4 text-center">
          <BarChart3 className="h-8 w-8 mx-auto text-blue-400 mb-2" />
          <p className="text-2xl font-bold text-foreground">{agents.reduce((a, b) => a + ((b.metrics as any)?.scansCompleted || 0), 0)}</p>
          <p className="text-xs text-muted-foreground">Total Scans</p>
        </CardContent></Card>
      </div>

      {/* Deploy Agent */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2"><PlusCircle className="h-5 w-5" /> Deploy New Agent</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <Input placeholder="Agent name" value={newAgentName} onChange={(e) => setNewAgentName(e.target.value)} />
            <Select value={newAgentType} onValueChange={setNewAgentType}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="scanner">Scanner</SelectItem>
                <SelectItem value="monitor">Monitor</SelectItem>
                <SelectItem value="crawler">Crawler</SelectItem>
                <SelectItem value="fuzzer">Fuzzer</SelectItem>
              </SelectContent>
            </Select>
            <Input placeholder="Target endpoint (optional)" value={newAgentEndpoint} onChange={(e) => setNewAgentEndpoint(e.target.value)} />
            <Button onClick={createAgent}><PlusCircle className="h-4 w-4 mr-1" /> Deploy</Button>
          </div>
        </CardContent>
      </Card>

      {/* Agent List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2"><Shield className="h-5 w-5" /> Active Agents</CardTitle>
          <CardDescription>{agents.length} agents deployed</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            {loading ? (
              <div className="flex items-center justify-center py-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
            ) : agents.length === 0 ? (
              <p className="text-muted-foreground text-center py-8">No agents deployed yet</p>
            ) : (
              <div className="space-y-3">
                {agents.map((agent) => (
                  <div key={agent.id} className="flex items-center justify-between p-4 rounded-lg border border-border hover:border-primary/20 transition-colors">
                    <div className="flex items-center gap-4">
                      <div className={`p-2 rounded-full ${agent.status === "active" ? "bg-green-500/10" : "bg-muted"}`}>
                        {agent.status === "active" ? <Wifi className="h-5 w-5 text-green-400" /> : <WifiOff className="h-5 w-5 text-muted-foreground" />}
                      </div>
                      <div>
                        <p className="font-medium text-foreground">{agent.agent_name}</p>
                        <p className="text-xs text-muted-foreground">{agent.target_endpoint || "No target"} · {agent.agent_type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right text-xs">
                        <div className="flex items-center gap-1 text-muted-foreground"><Heart className="h-3 w-3" /> {heartbeatAge(agent.last_heartbeat)}</div>
                      </div>
                      <Badge className={statusColor(agent.status)}>{agent.status}</Badge>
                      <div className="flex gap-1">
                        {agent.status === "active" ? (
                          <Button variant="outline" size="sm" onClick={() => updateAgentStatus(agent.id, "paused")}>Pause</Button>
                        ) : agent.status === "paused" ? (
                          <Button variant="outline" size="sm" onClick={() => updateAgentStatus(agent.id, "active")}>Resume</Button>
                        ) : null}
                        <Button variant="destructive" size="sm" onClick={() => deleteAgent(agent.id)}><Trash2 className="h-3 w-3" /></Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
};

export default SystemHealthDashboard;
