import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { 
  Activity, Shield, Target, Zap, AlertTriangle, CheckCircle, Brain,
  TrendingUp, Network, Eye, Lock, Unlock, Cpu, Database, GitBranch
} from "lucide-react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface AttackAttempt {
  id: string; target: string; attack_type: string; success: boolean;
  created_at: string; technique: string;
}

interface AttackChain {
  id: string; chain_name: string; target: string; status: string;
  current_step: number; attack_sequence: any; created_at: string;
}

interface TargetIntelligence {
  id: string; target: string; vulnerabilities: any; weak_points: any;
  tech_stack: any; last_scanned: string;
}

interface AttackLearning {
  id: string; failure_reason: string; adaptation_strategy: string;
  success_rate: number; created_at: string;
}

interface AILearningEntry {
  id: string; tool_used: string; target: string | null; success: boolean | null;
  findings: any; execution_time: number | null; ai_analysis: string | null;
  improvement_strategy: string | null; created_at: string;
}

const AttackVisualization = () => {
  const { toast } = useToast();
  const [attackAttempts, setAttackAttempts] = useState<AttackAttempt[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [targetIntel, setTargetIntel] = useState<TargetIntelligence[]>([]);
  const [learnings, setLearnings] = useState<AttackLearning[]>([]);
  const [aiLearnings, setAiLearnings] = useState<AILearningEntry[]>([]);
  const [liveMetrics, setLiveMetrics] = useState({
    activeScans: 0, totalAttempts: 0, successRate: 0,
    vulnerabilitiesFound: 0, aiLearnings: 0, activeChains: 0
  });

  const fetchData = useCallback(async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const [attemptsRes, chainsRes, intelRes, learnRes, aiLearnRes] = await Promise.all([
        supabase.from('attack_attempts').select('*').order('created_at', { ascending: false }).limit(50),
        supabase.from('attack_chains').select('*').order('created_at', { ascending: false }).limit(20),
        supabase.from('target_intelligence').select('*').order('last_scanned', { ascending: false }).limit(10),
        supabase.from('attack_learnings').select('*').order('created_at', { ascending: false }).limit(30),
        supabase.from('ai_learnings').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(100),
      ]);

      const attempts = attemptsRes.data || [];
      const chains = chainsRes.data || [];
      const intel = intelRes.data || [];
      const learn = learnRes.data || [];
      const aiLearn = (aiLearnRes.data || []) as AILearningEntry[];

      setAttackAttempts(attempts);
      setAttackChains(chains);
      setTargetIntel(intel);
      setLearnings(learn);
      setAiLearnings(aiLearn);

      // Combine attack_attempts + ai_learnings for accurate metrics
      const aiSuccessful = aiLearn.filter(l => l.success === true).length;
      const aiFailed = aiLearn.filter(l => l.success === false).length;
      const attemptSuccessful = attempts.filter(a => a.success).length;
      const attemptFailed = attempts.filter(a => !a.success).length;

      const totalSuccess = aiSuccessful + attemptSuccessful;
      const totalFailed = aiFailed + attemptFailed;
      const totalAll = totalSuccess + totalFailed;
      const successRate = totalAll > 0 ? Math.round((totalSuccess / totalAll) * 100) : 0;

      const totalVulns = intel.reduce((acc, t) => {
        const vulns = Array.isArray(t.vulnerabilities) ? t.vulnerabilities.length : 0;
        return acc + vulns;
      }, 0);

      // Also count findings from ai_learnings
      const aiFindings = aiLearn.reduce((acc, l) => {
        const findings = Array.isArray(l.findings) ? l.findings.length : 0;
        return acc + findings;
      }, 0);

      setLiveMetrics({
        activeScans: chains.filter(c => c.status === 'running').length,
        totalAttempts: totalAll,
        successRate,
        vulnerabilitiesFound: totalVulns + aiFindings,
        aiLearnings: aiLearn.length,
        activeChains: chains.filter(c => c.status === 'running').length,
      });
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    const attackChannel = supabase
      .channel('attack_viz_attempts')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'attack_attempts' }, () => fetchData())
      .subscribe();
    const learnChannel = supabase
      .channel('attack_viz_learnings')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'ai_learnings' }, () => fetchData())
      .subscribe();

    return () => {
      supabase.removeChannel(attackChannel);
      supabase.removeChannel(learnChannel);
    };
  }, [fetchData]);

  // Build unified timeline from both sources
  const buildTimelineData = () => {
    // Merge ai_learnings (primary source) with attack_attempts
    const events: { time: string; success: boolean; type: string; tool: string }[] = [];

    aiLearnings.forEach(l => {
      events.push({
        time: l.created_at,
        success: l.success === true,
        type: l.tool_used || 'scan',
        tool: l.tool_used || 'unknown',
      });
    });

    attackAttempts.forEach(a => {
      events.push({
        time: a.created_at,
        success: a.success,
        type: a.attack_type,
        tool: a.technique,
      });
    });

    events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());

    // Group by time buckets (every 5 events)
    const bucketSize = Math.max(1, Math.ceil(events.length / 20));
    const timeline: { time: number; success: number; failed: number; total: number }[] = [];

    for (let i = 0; i < events.length; i += bucketSize) {
      const bucket = events.slice(i, i + bucketSize);
      timeline.push({
        time: timeline.length + 1,
        success: bucket.filter(e => e.success).length,
        failed: bucket.filter(e => !e.success).length,
        total: bucket.length,
      });
    }

    return timeline.length > 0 ? timeline : [{ time: 1, success: 0, failed: 0, total: 0 }];
  };

  const timelineData = buildTimelineData();

  // Attack type distribution from both sources
  const buildAttackTypeData = () => {
    const counts: Record<string, { total: number; success: number }> = {};

    aiLearnings.forEach(l => {
      const type = (l.tool_used || 'scan').replace('red-team-', '').replace(/-/g, ' ');
      if (!counts[type]) counts[type] = { total: 0, success: 0 };
      counts[type].total++;
      if (l.success) counts[type].success++;
    });

    attackAttempts.forEach(a => {
      const type = a.attack_type || 'unknown';
      if (!counts[type]) counts[type] = { total: 0, success: 0 };
      counts[type].total++;
      if (a.success) counts[type].success++;
    });

    return Object.entries(counts)
      .map(([name, data]) => ({ name: name.slice(0, 15), value: data.total, success: data.success }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  };

  const attackTypeData = buildAttackTypeData();

  // OWASP coverage from findings
  const owaspCategories = [
    { id: 'A01', name: 'Broken Access', tools: ['cors', 'auth', 'idor', 'bola'] },
    { id: 'A02', name: 'Crypto Failures', tools: ['ssl', 'tls', 'weak-cipher'] },
    { id: 'A03', name: 'Injection', tools: ['sqli', 'xss', 'nosql', 'cmdi', 'ssti', 'lfi'] },
    { id: 'A04', name: 'Insecure Design', tools: ['business-logic', 'race'] },
    { id: 'A05', name: 'Security Misconfig', tools: ['headers', 'directory', 'cors-advanced'] },
    { id: 'A06', name: 'Vuln Components', tools: ['cve', 'tech', 'version'] },
    { id: 'A07', name: 'Auth Failures', tools: ['jwt', 'session', 'cookie', 'brute'] },
    { id: 'A08', name: 'Data Integrity', tools: ['csrf', 'deserialization'] },
    { id: 'A09', name: 'Logging Failures', tools: ['audit', 'monitoring'] },
    { id: 'A10', name: 'SSRF', tools: ['ssrf'] },
  ];

  const owaspCoverage = owaspCategories.map(cat => {
    const covered = aiLearnings.some(l =>
      cat.tools.some(t => (l.tool_used || '').toLowerCase().includes(t))
    );
    const findings = aiLearnings.filter(l =>
      l.success && cat.tools.some(t => (l.tool_used || '').toLowerCase().includes(t))
    ).length;
    return { ...cat, covered, findings };
  });

  const successRateData = aiLearnings
    .filter(l => l.tool_used?.startsWith('red-team'))
    .slice(0, 15).reverse()
    .map((l, idx) => ({
      scan: `S${idx + 1}`,
      findings: Array.isArray(l.findings) ? l.findings.length : 0,
      success: l.success ? 1 : 0,
    }));

  const COLORS = ['#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

  // Unified live feed: merge attack_attempts + ai_learnings
  const liveFeed = [
    ...attackAttempts.map(a => ({
      id: a.id, time: a.created_at, success: a.success,
      label: `${a.attack_type} → ${a.target}`, detail: a.technique, source: 'attempt' as const,
    })),
    ...aiLearnings.slice(0, 30).map(l => ({
      id: l.id, time: l.created_at, success: l.success === true,
      label: `${l.tool_used || 'scan'} → ${l.target || 'target'}`,
      detail: l.ai_analysis || '', source: 'learning' as const,
    })),
  ].sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()).slice(0, 50);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Live Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: "Active Scans", value: liveMetrics.activeScans, icon: Activity, color: "text-yellow-500", pulse: true },
          { label: "Total Operations", value: liveMetrics.totalAttempts, icon: Target, color: "text-blue-500" },
          { label: "Success Rate", value: `${liveMetrics.successRate}%`, icon: TrendingUp, color: liveMetrics.successRate > 30 ? "text-green-500" : "text-yellow-500" },
          { label: "Findings", value: liveMetrics.vulnerabilitiesFound, icon: AlertTriangle, color: "text-red-500" },
          { label: "AI Learnings", value: liveMetrics.aiLearnings, icon: Brain, color: "text-purple-500" },
          { label: "Attack Chains", value: liveMetrics.activeChains, icon: GitBranch, color: "text-indigo-500" },
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

      <Tabs defaultValue="timeline" className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="owasp">OWASP</TabsTrigger>
          <TabsTrigger value="chains">Chains</TabsTrigger>
          <TabsTrigger value="intelligence">Intel</TabsTrigger>
          <TabsTrigger value="learning">Learning</TabsTrigger>
          <TabsTrigger value="live">Live Feed</TabsTrigger>
        </TabsList>

        {/* Timeline */}
        <TabsContent value="timeline" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary" />
                Attack Activity Timeline
              </CardTitle>
              <CardDescription>
                Combined view from scan operations and attack attempts ({liveMetrics.totalAttempts} total operations)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area type="monotone" dataKey="success" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.6} name="Successful" />
                  <Area type="monotone" dataKey="failed" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} name="Failed/No Findings" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle>Attack Types Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={attackTypeData} cx="50%" cy="50%" labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80} fill="#8884d8" dataKey="value">
                      {attackTypeData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle>Scan Results Per Operation</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={successRateData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="scan" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="findings" fill="#8b5cf6" name="Findings" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* OWASP Coverage */}
        <TabsContent value="owasp" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                OWASP Top 10 Coverage
              </CardTitle>
              <CardDescription>Mapping of scan operations to OWASP categories</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {owaspCoverage.map(cat => (
                  <div key={cat.id} className={`p-3 rounded-lg border ${cat.covered ? 'border-green-500/30 bg-green-500/5' : 'border-muted bg-muted/20'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant={cat.covered ? "default" : "outline"} className="text-xs">{cat.id}</Badge>
                        <span className="font-medium text-sm">{cat.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {cat.findings > 0 && (
                          <Badge variant="destructive" className="text-xs">{cat.findings} findings</Badge>
                        )}
                        {cat.covered ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      Tools: {cat.tools.join(', ')}
                    </p>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-3 bg-muted/30 rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Coverage</span>
                  <span className="text-sm font-bold">{owaspCoverage.filter(c => c.covered).length}/10</span>
                </div>
                <Progress value={owaspCoverage.filter(c => c.covered).length * 10} className="mt-2 h-2" />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack Chains */}
        <TabsContent value="chains" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="h-5 w-5 text-primary" />
                Active Attack Chains
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {attackChains.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No attack chains yet. Run a continuous red team operation to generate chains.</p>
                    </div>
                  ) : attackChains.map((chain) => {
                    const sequence = Array.isArray(chain.attack_sequence) ? chain.attack_sequence : [];
                    const progress = sequence.length > 0 ? ((chain.current_step || 0) / sequence.length) * 100 : 100;
                    return (
                      <Card key={chain.id}>
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
                          <Progress value={progress} className="h-2" />
                          {sequence.length > 0 && (
                            <div className="flex flex-wrap gap-2 mt-2">
                              {sequence.slice(0, 6).map((stage: any, idx: number) => (
                                <Badge key={idx} variant={idx < (chain.current_step || 0) ? "default" : "outline"} className="text-xs">
                                  {idx < (chain.current_step || 0) && <CheckCircle className="h-3 w-3 mr-1" />}
                                  {stage.stage || stage.name || `Stage ${idx + 1}`}
                                </Badge>
                              ))}
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

        {/* Target Intelligence */}
        <TabsContent value="intelligence" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5 text-primary" />
                Target Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {targetIntel.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No target intelligence yet. Run scans to populate.</p>
                    </div>
                  ) : targetIntel.map((intel) => {
                    const vulns = Array.isArray(intel.vulnerabilities) ? intel.vulnerabilities : [];
                    const weakPoints = Array.isArray(intel.weak_points) ? intel.weak_points : [];
                    return (
                      <Card key={intel.id}>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h4 className="font-semibold flex items-center gap-2">
                                <Target className="h-4 w-4" /> {intel.target}
                              </h4>
                              <p className="text-sm text-muted-foreground">
                                Last scanned: {new Date(intel.last_scanned).toLocaleString()}
                              </p>
                            </div>
                            <Badge variant="destructive">{vulns.length} Vulns</Badge>
                          </div>
                          {vulns.length > 0 && (
                            <div className="flex flex-wrap gap-2 mb-2">
                              {vulns.slice(0, 5).map((v: any, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  <AlertTriangle className="h-3 w-3 mr-1 text-destructive" />
                                  {typeof v === 'string' ? v : v.name || 'Unknown'}
                                </Badge>
                              ))}
                            </div>
                          )}
                          {weakPoints.length > 0 && (
                            <div className="flex flex-wrap gap-2">
                              {weakPoints.slice(0, 3).map((p: any, i: number) => (
                                <Badge key={i} variant="secondary" className="text-xs">
                                  <Unlock className="h-3 w-3 mr-1" />
                                  {typeof p === 'string' ? p : p.name || 'Unknown'}
                                </Badge>
                              ))}
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

        {/* AI Learning */}
        <TabsContent value="learning" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5 text-primary animate-pulse" />
                AI Learning System ({aiLearnings.length} entries)
              </CardTitle>
              <CardDescription>Real scan outcomes driving AI adaptation</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {aiLearnings.slice(0, 30).map((learning) => {
                    const findingsCount = Array.isArray(learning.findings) ? learning.findings.length : 0;
                    return (
                      <Card key={learning.id} className={`border-l-4 ${learning.success ? 'border-l-green-500' : 'border-l-red-500'}`}>
                        <CardContent className="p-3">
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              {learning.success ? <CheckCircle className="h-4 w-4 text-green-500" /> : <AlertTriangle className="h-4 w-4 text-red-500" />}
                              <span className="font-medium text-sm">{learning.tool_used}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              {findingsCount > 0 && <Badge variant="destructive" className="text-xs">{findingsCount} findings</Badge>}
                              <span className="text-xs text-muted-foreground">
                                {new Date(learning.created_at).toLocaleString()}
                              </span>
                            </div>
                          </div>
                          {learning.target && <p className="text-xs text-muted-foreground">Target: {learning.target}</p>}
                          {learning.improvement_strategy && (
                            <p className="text-xs mt-1 text-muted-foreground line-clamp-2">
                              💡 {learning.improvement_strategy}
                            </p>
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

        {/* Live Feed */}
        <TabsContent value="live" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-primary animate-pulse" />
                Live Activity Feed
              </CardTitle>
              <CardDescription>Real-time combined feed from all scan sources</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {liveFeed.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No activity yet. Start a scan to see live results.</p>
                    </div>
                  ) : liveFeed.map((item) => (
                    <div key={item.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors">
                      {item.success ? (
                        <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-red-500 flex-shrink-0" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{item.label}</p>
                        <p className="text-xs text-muted-foreground truncate">
                          {item.detail} • {new Date(item.time).toLocaleTimeString()}
                        </p>
                      </div>
                      <Badge variant={item.success ? "default" : "destructive"} className="flex-shrink-0 text-xs">
                        {item.success ? 'SUCCESS' : 'FAILED'}
                      </Badge>
                      <Badge variant="outline" className="text-xs">{item.source === 'learning' ? 'AI' : 'ATK'}</Badge>
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
              <span>Data Sources: AI Learnings + Attack Attempts</span>
              <span>•</span>
              <span>OWASP Coverage: {owaspCoverage.filter(c => c.covered).length}/10</span>
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
