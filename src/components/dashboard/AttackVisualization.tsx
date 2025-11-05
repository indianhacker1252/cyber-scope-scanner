import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { 
  Activity, 
  Shield, 
  Target, 
  Zap,
  AlertTriangle,
  CheckCircle,
  Brain,
  TrendingUp,
  Network,
  Eye,
  Lock,
  Unlock,
  Cpu,
  Database,
  GitBranch
} from "lucide-react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface AttackAttempt {
  id: string;
  target: string;
  attack_type: string;
  success: boolean;
  created_at: string;
  technique: string;
}

interface AttackChain {
  id: string;
  chain_name: string;
  target: string;
  status: string;
  current_step: number;
  attack_sequence: any;
  created_at: string;
}

interface TargetIntelligence {
  id: string;
  target: string;
  vulnerabilities: any;
  weak_points: any;
  tech_stack: any;
  last_scanned: string;
}

interface AttackLearning {
  id: string;
  failure_reason: string;
  adaptation_strategy: string;
  success_rate: number;
  created_at: string;
}

const AttackVisualization = () => {
  const { toast } = useToast();
  const [attackAttempts, setAttackAttempts] = useState<AttackAttempt[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [targetIntel, setTargetIntel] = useState<TargetIntelligence[]>([]);
  const [learnings, setLearnings] = useState<AttackLearning[]>([]);
  const [liveMetrics, setLiveMetrics] = useState({
    activeScans: 0,
    totalAttempts: 0,
    successRate: 0,
    vulnerabilitiesFound: 0,
    aiLearnings: 0,
    activeChains: 0
  });

  // Fetch initial data
  const fetchData = useCallback(async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      // Fetch attack attempts
      const { data: attempts } = await supabase
        .from('attack_attempts')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);
      
      // Fetch attack chains
      const { data: chains } = await supabase
        .from('attack_chains')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(20);
      
      // Fetch target intelligence
      const { data: intel } = await supabase
        .from('target_intelligence')
        .select('*')
        .order('last_scanned', { ascending: false })
        .limit(10);
      
      // Fetch learnings
      const { data: learn } = await supabase
        .from('attack_learnings')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(30);

      if (attempts) setAttackAttempts(attempts);
      if (chains) setAttackChains(chains);
      if (intel) setTargetIntel(intel);
      if (learn) setLearnings(learn);

      // Calculate metrics
      const activeChains = chains?.filter(c => c.status === 'running').length || 0;
      const totalAttempts = attempts?.length || 0;
      const successfulAttempts = attempts?.filter(a => a.success).length || 0;
      const successRate = totalAttempts > 0 ? (successfulAttempts / totalAttempts) * 100 : 0;
      const totalVulns = intel?.reduce((acc, t) => {
        const vulns = Array.isArray(t.vulnerabilities) ? t.vulnerabilities.length : 0;
        return acc + vulns;
      }, 0) || 0;

      setLiveMetrics({
        activeScans: activeChains,
        totalAttempts,
        successRate: Math.round(successRate),
        vulnerabilitiesFound: totalVulns,
        aiLearnings: learn?.length || 0,
        activeChains
      });
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, [fetchData]);

  // Setup realtime subscriptions
  useEffect(() => {
    const attackChannel = supabase
      .channel('attack_attempts_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'attack_attempts'
        },
        (payload) => {
          console.log('Attack attempt change:', payload);
          fetchData();
          toast({
            title: "New Attack Activity",
            description: `Attack ${payload.eventType} detected`,
          });
        }
      )
      .subscribe();

    const chainChannel = supabase
      .channel('attack_chains_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'attack_chains'
        },
        (payload) => {
          console.log('Attack chain change:', payload);
          fetchData();
        }
      )
      .subscribe();

    const intelChannel = supabase
      .channel('target_intelligence_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'target_intelligence'
        },
        (payload) => {
          console.log('Target intelligence change:', payload);
          fetchData();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(attackChannel);
      supabase.removeChannel(chainChannel);
      supabase.removeChannel(intelChannel);
    };
  }, [fetchData, toast]);

  // Prepare chart data
  const timelineData = attackAttempts.slice(0, 20).reverse().map((attempt, idx) => ({
    time: idx + 1,
    attempts: idx + 1,
    success: attackAttempts.slice(0, idx + 1).filter(a => a.success).length,
    failed: attackAttempts.slice(0, idx + 1).filter(a => !a.success).length
  }));

  const attackTypeData = Object.entries(
    attackAttempts.reduce((acc, attempt) => {
      acc[attempt.attack_type] = (acc[attempt.attack_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ).map(([name, value]) => ({ name, value }));

  const successRateData = learnings.slice(0, 10).reverse().map((learning, idx) => ({
    learning: `L${idx + 1}`,
    rate: learning.success_rate || 0
  }));

  const COLORS = ['#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#8b5cf6', '#ec4899'];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Live Metrics Header */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: "Active Scans", value: liveMetrics.activeScans, icon: Activity, color: "text-yellow-500", pulse: true },
          { label: "Total Attempts", value: liveMetrics.totalAttempts, icon: Target, color: "text-blue-500" },
          { label: "Success Rate", value: `${liveMetrics.successRate}%`, icon: TrendingUp, color: "text-green-500" },
          { label: "Vulnerabilities", value: liveMetrics.vulnerabilitiesFound, icon: AlertTriangle, color: "text-red-500" },
          { label: "AI Learnings", value: liveMetrics.aiLearnings, icon: Brain, color: "text-purple-500" },
          { label: "Attack Chains", value: liveMetrics.activeChains, icon: GitBranch, color: "text-indigo-500" }
        ].map((metric, idx) => (
          <Card key={idx} className="animate-scale-in" style={{ animationDelay: `${idx * 0.1}s` }}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold">{metric.value}</p>
                  <p className="text-xs text-muted-foreground">{metric.label}</p>
                </div>
                <metric.icon className={`h-8 w-8 ${metric.color} ${metric.pulse ? 'animate-pulse' : ''}`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Main Visualization Tabs */}
      <Tabs defaultValue="timeline" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="chains">Attack Chains</TabsTrigger>
          <TabsTrigger value="intelligence">Target Intel</TabsTrigger>
          <TabsTrigger value="learning">AI Learning</TabsTrigger>
          <TabsTrigger value="live">Live Feed</TabsTrigger>
        </TabsList>

        {/* Timeline View */}
        <TabsContent value="timeline" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary" />
                Attack Activity Timeline
              </CardTitle>
              <CardDescription>Real-time attack attempts and success rates</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area type="monotone" dataKey="success" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="failed" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Attack Types Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={attackTypeData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {attackTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>AI Learning Progress</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={successRateData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="learning" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="rate" fill="#8b5cf6" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Attack Chains View */}
        <TabsContent value="chains" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="h-5 w-5 text-primary" />
                Active Attack Chains
              </CardTitle>
              <CardDescription>Multi-stage attack sequences in progress</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {attackChains.map((chain) => {
                    const sequence = Array.isArray(chain.attack_sequence) ? chain.attack_sequence : [];
                    const progress = sequence.length > 0 ? (chain.current_step / sequence.length) * 100 : 0;
                    
                    return (
                      <Card key={chain.id} className="hover-scale">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h4 className="font-semibold">{chain.chain_name}</h4>
                              <p className="text-sm text-muted-foreground">Target: {chain.target}</p>
                            </div>
                            <Badge variant={chain.status === 'running' ? 'default' : chain.status === 'completed' ? 'secondary' : 'destructive'}>
                              {chain.status === 'running' && <Activity className="h-3 w-3 mr-1 animate-pulse" />}
                              {chain.status}
                            </Badge>
                          </div>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span>Step {chain.current_step} of {sequence.length}</span>
                              <span>{Math.round(progress)}%</span>
                            </div>
                            <Progress value={progress} className="h-2" />
                            <div className="flex flex-wrap gap-2 mt-2">
                              {sequence.map((stage: any, idx: number) => (
                                <Badge key={idx} variant={idx < chain.current_step ? "default" : "outline"} className="text-xs">
                                  {idx < chain.current_step && <CheckCircle className="h-3 w-3 mr-1" />}
                                  {stage.stage || `Stage ${idx + 1}`}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Target Intelligence View */}
        <TabsContent value="intelligence" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5 text-primary" />
                Target Intelligence
              </CardTitle>
              <CardDescription>Discovered vulnerabilities and weak points</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {targetIntel.map((intel) => {
                    const vulns = Array.isArray(intel.vulnerabilities) ? intel.vulnerabilities : [];
                    const weakPoints = Array.isArray(intel.weak_points) ? intel.weak_points : [];
                    
                    return (
                      <Card key={intel.id} className="hover-scale">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h4 className="font-semibold flex items-center gap-2">
                                <Target className="h-4 w-4" />
                                {intel.target}
                              </h4>
                              <p className="text-sm text-muted-foreground">
                                Last scanned: {new Date(intel.last_scanned).toLocaleString()}
                              </p>
                            </div>
                            <Badge variant="destructive">
                              {vulns.length} Vulnerabilities
                            </Badge>
                          </div>
                          
                          {vulns.length > 0 && (
                            <div className="space-y-2 mb-3">
                              <p className="text-sm font-medium">Vulnerabilities:</p>
                              <div className="flex flex-wrap gap-2">
                                {vulns.slice(0, 5).map((vuln: any, idx: number) => (
                                  <Badge key={idx} variant="outline" className="text-xs">
                                    <AlertTriangle className="h-3 w-3 mr-1 text-destructive" />
                                    {typeof vuln === 'string' ? vuln : vuln.name || 'Unknown'}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          {weakPoints.length > 0 && (
                            <div className="space-y-2">
                              <p className="text-sm font-medium">Weak Points:</p>
                              <div className="flex flex-wrap gap-2">
                                {weakPoints.slice(0, 3).map((point: any, idx: number) => (
                                  <Badge key={idx} variant="secondary" className="text-xs">
                                    <Unlock className="h-3 w-3 mr-1" />
                                    {typeof point === 'string' ? point : point.name || 'Unknown'}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Learning View */}
        <TabsContent value="learning" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5 text-primary animate-pulse" />
                AI Learning System
              </CardTitle>
              <CardDescription>Adaptive attack strategies and failure analysis</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {learnings.map((learning) => (
                    <Card key={learning.id} className="hover-scale">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <Badge variant="outline" className="text-xs">
                            Success Rate: {learning.success_rate || 0}%
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {new Date(learning.created_at).toLocaleString()}
                          </span>
                        </div>
                        <div className="space-y-2">
                          <div>
                            <p className="text-sm font-medium">Failure Reason:</p>
                            <p className="text-sm text-muted-foreground">{learning.failure_reason}</p>
                          </div>
                          <div>
                            <p className="text-sm font-medium">Adaptation Strategy:</p>
                            <p className="text-sm text-muted-foreground">{learning.adaptation_strategy}</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Live Feed View */}
        <TabsContent value="live" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-primary animate-pulse" />
                Live Attack Feed
              </CardTitle>
              <CardDescription>Real-time attack activity stream</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {attackAttempts.map((attempt) => (
                    <div
                      key={attempt.id}
                      className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors animate-fade-in"
                    >
                      {attempt.success ? (
                        <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-red-500 flex-shrink-0" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {attempt.attack_type} → {attempt.target}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {attempt.technique} • {new Date(attempt.created_at).toLocaleTimeString()}
                        </p>
                      </div>
                      <Badge variant={attempt.success ? "default" : "destructive"} className="flex-shrink-0">
                        {attempt.success ? 'SUCCESS' : 'FAILED'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* System Status Footer */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-sm font-medium">System Operational</span>
            </div>
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>Real-time Updates: ON</span>
              <span>•</span>
              <span>AI Learning: ACTIVE</span>
              <span>•</span>
              <span>Last Update: {new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AttackVisualization;
