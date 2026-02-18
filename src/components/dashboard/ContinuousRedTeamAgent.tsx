/**
 * Continuous Red Team Agent - AI-Powered Autonomous Security Operations
 * Self-learning agent with correlation engine for advanced red-teaming
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import {
  Brain,
  Target,
  Play,
  Pause,
  Square,
  RefreshCw,
  Shield,
  AlertTriangle,
  Activity,
  Zap,
  GitBranch,
  Database,
  TrendingUp,
  Eye,
  Network,
  Bug,
  Lock,
  Crosshair,
  Layers,
  Cpu,
  BarChart3
} from "lucide-react";

interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence: any;
  timestamp: string;
  phase: string;
  tool_used: string;
  exploitable: boolean;
}

interface Correlation {
  id: string;
  findings: string[];
  attack_path: string;
  risk_amplification: number;
  exploitation_probability: number;
  description: string;
}

interface AttackChain {
  id: string;
  name: string;
  steps: any[];
  success_probability: number;
  impact: string;
  mitre_mapping: string[];
}

interface AgentStatus {
  isRunning: boolean;
  phase: string;
  progress: number;
  iteration: number;
  maxIterations: number;
  findings: Finding[];
  correlations: Correlation[];
  attackChains: AttackChain[];
  learningUpdates: any[];
}

interface LearningMetrics {
  modelConfidence: number;
  successfulTechniques: number;
  failedTechniques: number;
  adaptationsApplied: number;
  patternMatchRate: number;
}

const ContinuousRedTeamAgent = () => {
  const { toast } = useToast();
  
  // Agent configuration
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("comprehensive-assessment");
  const [maxIterations, setMaxIterations] = useState(50);
  const [autoAdapt, setAutoAdapt] = useState(true);
  const [stealthMode, setStealthMode] = useState(false);
  
  // Agent status
  const [status, setStatus] = useState<AgentStatus>({
    isRunning: false,
    phase: 'idle',
    progress: 0,
    iteration: 0,
    maxIterations: 50,
    findings: [],
    correlations: [],
    attackChains: [],
    learningUpdates: []
  });
  
  // Learning metrics
  const [learningMetrics, setLearningMetrics] = useState<LearningMetrics>({
    modelConfidence: 0.5,
    successfulTechniques: 0,
    failedTechniques: 0,
    adaptationsApplied: 0,
    patternMatchRate: 0
  });
  
  // Live output
  const [liveOutput, setLiveOutput] = useState<string[]>([]);
  const outputRef = useRef<HTMLDivElement>(null);
  
  // Active tab
  const [activeTab, setActiveTab] = useState("control");

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [liveOutput]);

  const addOutput = useCallback((message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = {
      info: '📡',
      success: '✅',
      warning: '⚠️',
      error: '❌'
    }[type];
    
    setLiveOutput(prev => [...prev, `[${timestamp}] ${prefix} ${message}`]);
  }, []);

  const startContinuousOperation = async () => {
    if (!target) {
      toast({
        title: "Target Required",
        description: "Please enter a target before starting the operation",
        variant: "destructive"
      });
      return;
    }

    setStatus(prev => ({ ...prev, isRunning: true, phase: 'initializing' }));
    setLiveOutput([]);
    addOutput(`Starting continuous red team operation against ${target}`, 'info');
    addOutput(`Objective: ${objective} | Max Iterations: ${maxIterations}`, 'info');
    addOutput(`Auto-Adapt: ${autoAdapt} | Stealth Mode: ${stealthMode}`, 'info');

    const allFindings: Finding[] = [];
    const allCorrelations: Correlation[] = [];
    const allAttackChains: AttackChain[] = [];
    const phases = ['recon', 'scanning', 'subdomain-scan', 'exploitation', 'post-exploit'];

    try {
      for (let i = 0; i < phases.length; i++) {
        const phase = phases[i];

        // subdomain-scan is handled by a dedicated action
        if (phase === 'subdomain-scan') {
          addOutput(`\n━━━ Phase: SUBDOMAIN ENUMERATION ━━━`, 'info');
          addOutput(`Enumerating subdomains → then running SQLi/XSS/CORS/Traversal on each...`, 'info');
          setStatus(prev => ({ ...prev, phase: 'subdomain-scan' }));

          const { data: sdData, error: sdError } = await supabase.functions.invoke('continuous-red-team-agent', {
            body: {
              action: 'run-phase',
              data: { target, phase: 'scanning', config: { auto_adapt: autoAdapt } }
            }
          });
          // subdomain-scan is embedded in the continuous-operation call, so skip inline here
          // We just show progress — actual subdomain scanning runs in the full-op flow
          addOutput(`Subdomain phase initiated — results will appear in findings`, 'info');
          setStatus(prev => ({
            ...prev,
            findings: [...allFindings],
            progress: Math.round(((i + 1) / phases.length) * 100)
          }));
          continue;
        }

        addOutput(`\n━━━ Phase: ${phase.toUpperCase()} ━━━`, 'info');
        setStatus(prev => ({ ...prev, phase }));

        const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
          body: {
            action: 'run-phase',
            data: { target, phase, config: { auto_adapt: autoAdapt, stealth_mode: stealthMode } }
          }
        });

        if (error) {
          addOutput(`${phase}: Edge function error - ${error.message}`, 'error');
          continue;
        }

        if (data?.output && Array.isArray(data.output)) {
          data.output.forEach((line: string) => {
            if (line.includes('[CONFIRMED]')) addOutput(line, 'success');
            else if (line.includes('[UNVERIFIED]')) addOutput(line, 'warning');
            else if (line.includes('findings') && !line.includes('0 findings')) addOutput(line, 'success');
            else addOutput(line, 'info');
          });
        }

        const phaseFindingCount = data?.findings?.length || 0;
        const verifiedCount = data?.verified_count || 0;
        const unverifiedCount = data?.unverified_count || 0;

        if (phaseFindingCount > 0) {
          allFindings.push(...data.findings);
          addOutput(`Phase ${phase}: ${phaseFindingCount} findings (${verifiedCount} confirmed ✅, ${unverifiedCount} unverified ⚠️)`, 'success');
        } else {
          addOutput(`Phase ${phase} complete: 0 findings`, 'warning');
        }

        setStatus(prev => ({
          ...prev,
          findings: [...allFindings],
          progress: Math.round(((i + 1) / phases.length) * 100)
        }));
      }

      // Subdomain-expanded full operation (runs all phases including subdomain enum)
      addOutput(`\n━━━ SUBDOMAIN ATTACK SURFACE EXPANSION ━━━`, 'info');
      addOutput(`Running full attack surface scan including discovered subdomains...`, 'info');
      const { data: fullOp } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: {
          action: 'start-continuous-operation',
          data: { target, objective, max_iterations: 5 }
        }
      });
      if (fullOp?.findings?.length > 0) {
        const newFindings = fullOp.findings.filter((f: any) => f.subdomain);
        if (newFindings.length > 0) {
          allFindings.push(...newFindings);
          addOutput(`Subdomain scan complete: ${newFindings.length} findings across ${fullOp.subdomains_discovered?.length || 0} subdomains`, 'success');
          if (fullOp.subdomains_discovered?.length > 0) {
            addOutput(`Subdomains discovered: ${fullOp.subdomains_discovered.join(', ')}`, 'info');
          }
        }
      }

      if (allFindings.length >= 2) {
        addOutput(`\n━━━ CORRELATION ENGINE ━━━`, 'info');
        const { data: corrData } = await supabase.functions.invoke('continuous-red-team-agent', {
          body: {
            action: 'correlate-findings',
            data: { findings: allFindings, target_context: { target } }
          }
        });
        if (corrData?.correlations) allCorrelations.push(...corrData.correlations);
        if (corrData?.attack_chains) allAttackChains.push(...corrData.attack_chains);
        addOutput(`Correlations: ${allCorrelations.length} | Attack chains: ${allAttackChains.length}`, 'success');
      }

      const verifiedTotal = allFindings.filter((f: any) => f.verified === true).length;
      const subdomainTotal = allFindings.filter((f: any) => f.subdomain).length;
      addOutput(`\n━━━ OPERATION COMPLETE ━━━`, 'success');
      addOutput(`Total findings: ${allFindings.length} | Dual-verified: ${verifiedTotal} | From subdomains: ${subdomainTotal}`, 'success');

      setStatus(prev => ({
        ...prev,
        isRunning: false,
        phase: 'completed',
        progress: 100,
        findings: allFindings,
        correlations: allCorrelations,
        attackChains: allAttackChains,
      }));

      setLearningMetrics(prev => ({
        ...prev,
        successfulTechniques: prev.successfulTechniques + (allFindings.length > 0 ? phases.length : 0),
        failedTechniques: prev.failedTechniques + (allFindings.length === 0 ? phases.length : 0),
        modelConfidence: Math.min(0.95, prev.modelConfidence + (allFindings.length * 0.02))
      }));

      toast({
        title: "Operation Complete",
        description: `Found ${allFindings.length} vulnerabilities (${verifiedTotal} dual-verified) with ${allCorrelations.length} attack paths`
      });

    } catch (error: any) {
      console.error('Operation error:', error);
      addOutput(`Error: ${error.message}`, 'error');
      setStatus(prev => ({ ...prev, isRunning: false, phase: 'error', findings: allFindings }));
      toast({
        title: "Operation Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const correlateFindings = async () => {
    if (status.findings.length < 2) {
      toast({
        title: "Insufficient Data",
        description: "Need at least 2 findings to correlate",
        variant: "destructive"
      });
      return;
    }

    addOutput("Running correlation analysis on findings...", 'info');

    try {
      const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: {
          action: 'correlate-findings',
          data: {
            findings: status.findings,
            target_context: { target }
          }
        }
      });

      if (error) throw error;

      setStatus(prev => ({
        ...prev,
        correlations: data.correlations || [],
        attackChains: data.attack_chains || []
      }));

      addOutput(`Correlation complete - Risk Score: ${data.risk_score}`, 'success');
      
    } catch (error: any) {
      addOutput(`Correlation error: ${error.message}`, 'error');
    }
  };

  const getRecommendations = async () => {
    addOutput("Fetching AI recommendations...", 'info');

    try {
      const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: {
          action: 'get-agent-recommendations',
          data: {
            target,
            current_phase: status.phase,
            existing_findings: status.findings
          }
        }
      });

      if (error) throw error;

      addOutput(`Recommendations received (Confidence: ${Math.round(data.confidence_score * 100)}%)`, 'success');
      data.recommendations?.recommended_tools?.forEach((tool: string) => {
        addOutput(`  → Recommended tool: ${tool}`, 'info');
      });

    } catch (error: any) {
      addOutput(`Recommendation error: ${error.message}`, 'error');
    }
  };

  const fineTuneModel = async () => {
    if (status.learningUpdates.length < 5) {
      toast({
        title: "Insufficient Training Data",
        description: "Need at least 5 learning updates to fine-tune",
        variant: "destructive"
      });
      return;
    }

    addOutput("Fine-tuning agent model with collected data...", 'info');

    try {
      const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: {
          action: 'fine-tune-model',
          data: {
            training_data: status.learningUpdates,
            model_type: 'attack-prediction'
          }
        }
      });

      if (error) throw error;

      setLearningMetrics(prev => ({
        ...prev,
        modelConfidence: data.new_confidence,
        patternMatchRate: data.patterns_extracted / status.learningUpdates.length
      }));

      addOutput(`Model fine-tuned - New confidence: ${Math.round(data.new_confidence * 100)}%`, 'success');
      addOutput(`Patterns extracted: ${data.patterns_extracted}`, 'info');

    } catch (error: any) {
      addOutput(`Fine-tuning error: ${error.message}`, 'error');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'recon': return <Eye className="h-4 w-4" />;
      case 'scanning': return <Network className="h-4 w-4" />;
      case 'exploitation': return <Bug className="h-4 w-4" />;
      case 'post-exploit': return <Lock className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-xl border border-red-500/30">
            <Brain className="h-8 w-8 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Continuous Red Team Agent</h1>
            <p className="text-muted-foreground">AI-powered autonomous security operations with self-learning</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={status.isRunning ? "default" : "secondary"} className="gap-1">
            <Activity className={`h-3 w-3 ${status.isRunning ? 'animate-pulse' : ''}`} />
            {status.phase}
          </Badge>
          <Badge variant="outline" className="gap-1">
            <Cpu className="h-3 w-3" />
            Confidence: {Math.round(learningMetrics.modelConfidence * 100)}%
          </Badge>
        </div>
      </div>

      {/* Learning Metrics Bar */}
      <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-transparent">
        <CardContent className="py-4">
          <div className="grid grid-cols-5 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{learningMetrics.modelConfidence.toFixed(2)}</div>
              <div className="text-xs text-muted-foreground">Model Confidence</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">{learningMetrics.successfulTechniques}</div>
              <div className="text-xs text-muted-foreground">Successful Techniques</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400">{learningMetrics.failedTechniques}</div>
              <div className="text-xs text-muted-foreground">Failed Techniques</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-400">{learningMetrics.adaptationsApplied}</div>
              <div className="text-xs text-muted-foreground">Adaptations Applied</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-400">{(learningMetrics.patternMatchRate * 100).toFixed(0)}%</div>
              <div className="text-xs text-muted-foreground">Pattern Match Rate</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Control Panel */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-5 w-full">
              <TabsTrigger value="control">Control</TabsTrigger>
              <TabsTrigger value="findings">Findings ({status.findings.length})</TabsTrigger>
              <TabsTrigger value="correlations">Correlations</TabsTrigger>
              <TabsTrigger value="chains">Attack Chains</TabsTrigger>
              <TabsTrigger value="learning">Learning</TabsTrigger>
            </TabsList>

            <TabsContent value="control" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    Operation Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Target</Label>
                      <Input
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="example.com or 192.168.1.1"
                        disabled={status.isRunning}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Objective</Label>
                      <select
                        value={objective}
                        onChange={(e) => setObjective(e.target.value)}
                        className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm"
                        disabled={status.isRunning}
                      >
                        <option value="comprehensive-assessment">Comprehensive Assessment</option>
                        <option value="vulnerability-discovery">Vulnerability Discovery</option>
                        <option value="exploitation-focus">Exploitation Focus</option>
                        <option value="stealth-recon">Stealth Reconnaissance</option>
                        <option value="api-security">API Security Testing</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Max Iterations: {maxIterations}</Label>
                    <Slider
                      value={[maxIterations]}
                      onValueChange={(v) => setMaxIterations(v[0])}
                      min={10}
                      max={200}
                      step={10}
                      disabled={status.isRunning}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={autoAdapt}
                          onCheckedChange={setAutoAdapt}
                          disabled={status.isRunning}
                        />
                        <Label>Auto-Adapt</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={stealthMode}
                          onCheckedChange={setStealthMode}
                          disabled={status.isRunning}
                        />
                        <Label>Stealth Mode</Label>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      onClick={startContinuousOperation}
                      disabled={status.isRunning || !target}
                      className="flex-1"
                    >
                      {status.isRunning ? (
                        <>
                          <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                          Running...
                        </>
                      ) : (
                        <>
                          <Play className="mr-2 h-4 w-4" />
                          Start Operation
                        </>
                      )}
                    </Button>
                    <Button variant="outline" onClick={getRecommendations} disabled={status.isRunning}>
                      <Zap className="mr-2 h-4 w-4" />
                      Get AI Recommendations
                    </Button>
                  </div>

                  {status.isRunning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Progress</span>
                        <span>{status.iteration}/{status.maxIterations}</span>
                      </div>
                      <Progress value={(status.iteration / status.maxIterations) * 100} />
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Live Output */}
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Live Output
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-64">
                    <div ref={outputRef} className="p-4 font-mono text-xs space-y-1 bg-black/50 rounded-b-lg">
                      {liveOutput.length === 0 ? (
                        <div className="text-muted-foreground">Awaiting operation start...</div>
                      ) : (
                        liveOutput.map((line, i) => (
                          <div key={i} className={`${
                            line.includes('✅') ? 'text-green-400' :
                            line.includes('⚠️') ? 'text-yellow-400' :
                            line.includes('❌') ? 'text-red-400' :
                            'text-muted-foreground'
                          }`}>
                            {line}
                          </div>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="findings">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Discovered Findings
                  </CardTitle>
                  <CardDescription>
                    Vulnerabilities and issues discovered during operation
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {status.findings.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      No findings yet. Start an operation to discover vulnerabilities.
                    </div>
                  ) : (
                    <ScrollArea className="h-96">
                      <div className="space-y-3">
                        {status.findings.map((finding: any) => (
                          <div
                            key={finding.id}
                            className={`p-3 border rounded-lg bg-card/50 ${
                              finding.verified === false ? 'border-yellow-500/30 opacity-75' : ''
                            }`}
                          >
                            <div className="flex items-start justify-between flex-wrap gap-2">
                              <div className="flex items-center gap-2 flex-1 min-w-0">
                                {getPhaseIcon(finding.subdomain ? 'scanning' : finding.phase)}
                                <span className="font-medium text-sm truncate">{finding.title}</span>
                              </div>
                              <div className="flex items-center gap-1 flex-wrap">
                                {finding.subdomain && (
                                  <Badge variant="outline" className="text-xs border-blue-500/40 text-blue-400">
                                    🌐 Subdomain
                                  </Badge>
                                )}
                                {finding.verified === true && (
                                  <Badge variant="outline" className="text-xs border-green-500/40 text-green-400">
                                    ✅ Verified
                                  </Badge>
                                )}
                                {finding.verified === false && (
                                  <Badge variant="outline" className="text-xs border-yellow-500/40 text-yellow-400">
                                    ⚠️ Unverified
                                  </Badge>
                                )}
                                {finding.exploitable && (
                                  <Badge variant="destructive" className="text-xs">Exploitable</Badge>
                                )}
                                <Badge className={getSeverityColor(finding.severity)}>
                                  {finding.severity}
                                </Badge>
                              </div>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
                              <span>Tool: {finding.tool_used}</span>
                              <span>Phase: {finding.subdomain ? 'subdomain-scan' : finding.phase}</span>
                              {finding.confidence !== undefined && (
                                <span className={finding.confidence >= 0.8 ? 'text-green-400' : finding.confidence >= 0.6 ? 'text-yellow-400' : 'text-red-400'}>
                                  Confidence: {Math.round(finding.confidence * 100)}%
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="correlations">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <GitBranch className="h-5 w-5" />
                        Finding Correlations
                      </CardTitle>
                      <CardDescription>
                        AI-identified attack paths combining multiple findings
                      </CardDescription>
                    </div>
                    <Button onClick={correlateFindings} disabled={status.findings.length < 2}>
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Re-correlate
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {status.correlations.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      No correlations found. Discover more findings or click Re-correlate.
                    </div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-4">
                        {status.correlations.map((correlation) => (
                          <div
                            key={correlation.id}
                            className="p-4 border rounded-lg bg-gradient-to-r from-primary/5 to-transparent"
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-semibold">{correlation.attack_path}</span>
                              <Badge variant="outline">
                                {Math.round(correlation.exploitation_probability * 100)}% Probability
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{correlation.description}</p>
                            <div className="flex items-center gap-4 mt-3">
                              <div className="flex items-center gap-1 text-xs">
                                <TrendingUp className="h-3 w-3" />
                                Risk Amp: {correlation.risk_amplification}x
                              </div>
                              <div className="flex items-center gap-1 text-xs">
                                <Layers className="h-3 w-3" />
                                {correlation.findings.length} findings linked
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="chains">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Crosshair className="h-5 w-5" />
                    Generated Attack Chains
                  </CardTitle>
                  <CardDescription>
                    Multi-stage attack sequences with MITRE ATT&CK mapping
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {status.attackChains.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      No attack chains generated yet. Correlations create attack chains automatically.
                    </div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-4">
                        {status.attackChains.map((chain) => (
                          <div
                            key={chain.id}
                            className="p-4 border rounded-lg"
                          >
                            <div className="flex items-center justify-between mb-3">
                              <span className="font-semibold">{chain.name}</span>
                              <div className="flex items-center gap-2">
                                <Badge className={chain.impact === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}>
                                  {chain.impact}
                                </Badge>
                                <Badge variant="outline">
                                  {Math.round(chain.success_probability * 100)}% Success
                                </Badge>
                              </div>
                            </div>
                            
                            <div className="space-y-2">
                              {chain.steps.map((step: any, idx: number) => (
                                <div key={idx} className="flex items-center gap-2 text-sm">
                                  <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-xs">
                                    {step.order}
                                  </div>
                                  <span className="text-muted-foreground">{step.action}</span>
                                  <span className="text-xs">→ {step.expected_outcome}</span>
                                </div>
                              ))}
                            </div>
                            
                            <div className="flex flex-wrap gap-1 mt-3">
                              {chain.mitre_mapping.slice(0, 3).map((tech: string, idx: number) => (
                                <Badge key={idx} variant="secondary" className="text-xs">
                                  {tech}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="learning">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Database className="h-5 w-5" />
                        Learning & Adaptation
                      </CardTitle>
                      <CardDescription>
                        Self-learning updates and model fine-tuning
                      </CardDescription>
                    </div>
                    <Button onClick={fineTuneModel} disabled={status.learningUpdates.length < 5}>
                      <Brain className="mr-2 h-4 w-4" />
                      Fine-Tune Model
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {status.learningUpdates.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      No learning data yet. Run operations to collect training data.
                    </div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-3">
                        {status.learningUpdates.map((update, idx) => (
                          <div
                            key={idx}
                            className="p-3 border rounded-lg bg-card/50"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{update.technique}</span>
                              <Badge variant={update.success ? "default" : "destructive"}>
                                {update.success ? 'Success' : 'Failed'}
                              </Badge>
                            </div>
                            {update.adaptation_strategy && (
                              <div className="mt-2 p-2 bg-yellow-500/10 rounded text-sm">
                                <span className="text-yellow-400">Adaptation: </span>
                                {update.adaptation_strategy.recommended_action}
                              </div>
                            )}
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                              <span>Confidence: {Math.round((update.confidence || 0.5) * 100)}%</span>
                              <span>Findings: {update.findings_count}</span>
                              <span>Time: {Math.round(update.execution_time / 1000)}s</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Stats Sidebar */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="h-4 w-4" />
                Operation Stats
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total Findings</span>
                <span className="font-mono">{status.findings.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Critical</span>
                <span className="font-mono text-red-400">
                  {status.findings.filter(f => f.severity === 'critical').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">High</span>
                <span className="font-mono text-orange-400">
                  {status.findings.filter(f => f.severity === 'high').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Exploitable</span>
                <span className="font-mono text-yellow-400">
                  {status.findings.filter(f => f.exploitable).length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Correlations</span>
                <span className="font-mono">{status.correlations.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Attack Chains</span>
                <span className="font-mono">{status.attackChains.length}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              {status.findings.length === 0 ? (
                <div className="text-xs text-muted-foreground text-center py-4">
                  No findings to display
                </div>
              ) : (
                <div className="space-y-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                    const count = status.findings.filter(f => f.severity === sev).length;
                    const percentage = (count / status.findings.length) * 100;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="capitalize">{sev}</span>
                          <span>{count}</span>
                        </div>
                        <Progress value={percentage} className="h-1" />
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-primary/10 to-transparent border-primary/20">
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Brain className="h-4 w-4" />
                AI Model Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Confidence</span>
                  <span>{Math.round(learningMetrics.modelConfidence * 100)}%</span>
                </div>
                <Progress value={learningMetrics.modelConfidence * 100} />
              </div>
              <div className="text-xs text-muted-foreground">
                {learningMetrics.modelConfidence >= 0.8 ? (
                  <span className="text-green-400">✓ High confidence - reliable predictions</span>
                ) : learningMetrics.modelConfidence >= 0.6 ? (
                  <span className="text-yellow-400">◐ Moderate - more data recommended</span>
                ) : (
                  <span className="text-orange-400">○ Building knowledge base...</span>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default ContinuousRedTeamAgent;
