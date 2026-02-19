/**
 * Continuous Red Team Agent - AI-Powered Autonomous Security Operations
 * Self-learning agent with correlation engine for advanced red-teaming
 * v3: Subdomain Attack Surface Map | CORS/Traversal/Cookie Tab | POC Detail Modal | Retry Feedback | AI Learning Fix
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
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import {
  Brain,
  Target,
  Play,
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
  BarChart3,
  Globe,
  ChevronRight,
  Code2,
  Filter,
  CheckCircle2,
  XCircle,
  Info
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
  confidence?: number;
  verified?: boolean;
  subdomain?: string;
}

interface SubdomainEntry {
  domain: string;
  live: boolean;
  technologies: string[];
  findings: Finding[];
  riskScore: 'critical' | 'high' | 'medium' | 'low' | 'clean';
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

// Scan types that belong to each category for the dedicated filter tab
const DEDICATED_SCAN_TYPES = {
  cors: ['cors-advanced', 'cors-test', 'cors'],
  traversal: ['dir-traversal', 'path-traversal', 'directory', 'lfi'],
  cookie: ['cookies', 'cookie-hijack', 'session', 'csrf'],
};

function categorizeFinding(finding: Finding): 'cors' | 'traversal' | 'cookie' | 'other' {
  const t = (finding.tool_used || finding.type || '').toLowerCase();
  if (DEDICATED_SCAN_TYPES.cors.some(s => t.includes(s))) return 'cors';
  if (DEDICATED_SCAN_TYPES.traversal.some(s => t.includes(s))) return 'traversal';
  if (DEDICATED_SCAN_TYPES.cookie.some(s => t.includes(s))) return 'cookie';
  const title = (finding.title || '').toLowerCase();
  if (title.includes('cors') || title.includes('cross-origin')) return 'cors';
  if (title.includes('traversal') || title.includes('lfi') || title.includes('path') || title.includes('directory')) return 'traversal';
  if (title.includes('cookie') || title.includes('session') || title.includes('csrf') || title.includes('hijack')) return 'cookie';
  return 'other';
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
  
  // Subdomain attack surface map
  const [subdomainMap, setSubdomainMap] = useState<SubdomainEntry[]>([]);

  // Dedicated CORS/Traversal/Cookie tab filter
  const [dedFilterType, setDedFilterType] = useState<'all' | 'cors' | 'traversal' | 'cookie'>('all');

  // POC detail modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [pocModalOpen, setPocModalOpen] = useState(false);
  
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
    const prefix = { info: '📡', success: '✅', warning: '⚠️', error: '❌' }[type];
    setLiveOutput(prev => [...prev, `[${timestamp}] ${prefix} ${message}`]);
  }, []);

  // Build subdomain attack surface map from findings
  const buildSubdomainMap = useCallback((findings: Finding[]) => {
    const subdomainFindings = findings.filter(f => f.subdomain);
    const subdomainSet = new Map<string, SubdomainEntry>();

    subdomainFindings.forEach(f => {
      const domain = f.subdomain!;
      if (!subdomainSet.has(domain)) {
        subdomainSet.set(domain, {
          domain,
          live: true,
          technologies: [],
          findings: [],
          riskScore: 'clean'
        });
      }
      const entry = subdomainSet.get(domain)!;
      entry.findings.push(f);
      // Extract tech from evidence
      if (f.evidence?.raw?.name?.toLowerCase().includes('technology')) {
        const tech = f.title.replace(/^.*\]\s*/, '').replace('Technology:', '').trim();
        if (tech && !entry.technologies.includes(tech)) entry.technologies.push(tech);
      }
      // Update risk score
      const sev = f.severity;
      if (sev === 'critical') entry.riskScore = 'critical';
      else if (sev === 'high' && entry.riskScore !== 'critical') entry.riskScore = 'high';
      else if (sev === 'medium' && !['critical','high'].includes(entry.riskScore)) entry.riskScore = 'medium';
      else if (sev === 'low' && entry.riskScore === 'clean') entry.riskScore = 'low';
    });

    setSubdomainMap(Array.from(subdomainSet.values()));
  }, []);

  // Record learning to DB with proper fields
  const recordLearning = useCallback(async (
    toolUsed: string,
    scanTarget: string,
    findings: Finding[],
    executionTime: number,
    phase: string
  ) => {
    try {
      const successfulTypes = findings.filter(f => f.severity !== 'info').map(f => f.type);
      const improvement_strategy = findings.length > 0
        ? `[${phase}] ${toolUsed} found ${findings.length} vuln(s): ${[...new Set(successfulTypes)].join(', ')}. Confidence: ${findings.filter(f=>f.verified).length}/${findings.length} dual-verified. Recommend deepening ${toolUsed} with expanded endpoints.`
        : `[${phase}] ${toolUsed} returned 0 findings on ${scanTarget}. Try expanding scan scope, adjusting encoding, or testing with authenticated session.`;

      const { error: insertError } = await supabase.from('ai_learnings').insert([{
        tool_used: `red-team-${phase}-${toolUsed}`,
        target: scanTarget,
        findings: findings as any,
        success: findings.length > 0,
        execution_time: executionTime,
        ai_analysis: `Phase: ${phase} | Tool: ${toolUsed} | Target: ${scanTarget} | Found: ${findings.length} | Verified: ${findings.filter(f=>f.verified).length} | Categories: ${[...new Set(findings.map(f=>f.type))].join(', ')}`,
        improvement_strategy,
        user_id: (await supabase.auth.getUser()).data.user?.id ?? '',
      }]);
      if (insertError) console.warn('[AI Learning] Insert error:', insertError.message);
    } catch (e) {
      console.warn('[AI Learning] Record failed:', e);
    }
  }, []);

  const startContinuousOperation = async () => {
    if (!target) {
      toast({ title: "Target Required", description: "Please enter a target before starting", variant: "destructive" });
      return;
    }

    setStatus(prev => ({ ...prev, isRunning: true, phase: 'initializing', progress: 0, findings: [], correlations: [], attackChains: [], learningUpdates: [] }));
    setLiveOutput([]);
    setSubdomainMap([]);
    addOutput(`Starting continuous red team operation against ${target}`, 'info');
    addOutput(`Objective: ${objective} | Auto-Adapt: ${autoAdapt} | Stealth: ${stealthMode}`, 'info');

    const allFindings: Finding[] = [];
    const allCorrelations: Correlation[] = [];
    const allAttackChains: AttackChain[] = [];
    const phases = ['recon', 'scanning', 'exploitation', 'post-exploit'];

    try {
      for (let i = 0; i < phases.length; i++) {
        const phase = phases[i];
        const phaseStart = Date.now();
        addOutput(`\n━━━ Phase: ${phase.toUpperCase()} ━━━`, 'info');
        setStatus(prev => ({ ...prev, phase }));

        const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
          body: {
            action: 'run-phase',
            data: { target, phase, config: { auto_adapt: autoAdapt, stealth_mode: stealthMode } }
          }
        });

        const phaseTime = Date.now() - phaseStart;

        if (error) {
          addOutput(`${phase}: Edge function error - ${error.message}`, 'error');
          continue;
        }

        if (data?.output && Array.isArray(data.output)) {
          data.output.forEach((line: string) => {
            if (line.includes('[CONFIRMED]') || line.includes('[VULNERABLE]') || line.includes('[CRITICAL]')) addOutput(line, 'success');
            else if (line.includes('[UNVERIFIED]') || line.includes('[POSSIBLE]')) addOutput(line, 'warning');
            else if (line.includes('[AUTO-RETRY]')) addOutput(line, 'warning');
            else if (line.includes('[SAFE]')) addOutput(line, 'info');
            else addOutput(line, 'info');
          });
        }

        const phaseFindings: Finding[] = data?.findings || [];
        const verifiedCount = data?.verified_count || 0;
        const unverifiedCount = data?.unverified_count || 0;

        if (phaseFindings.length > 0) {
          allFindings.push(...phaseFindings);
          addOutput(`Phase ${phase}: ${phaseFindings.length} findings (${verifiedCount} ✅ verified, ${unverifiedCount} ⚠️ unverified)`, 'success');
          // Record AI learning per phase
          await recordLearning(phase, target, phaseFindings, phaseTime, phase);
        } else {
          addOutput(`Phase ${phase} complete: 0 findings`, 'warning');
          await recordLearning(phase, target, [], phaseTime, phase);
        }

        setStatus(prev => ({
          ...prev,
          findings: [...allFindings],
          progress: Math.round(((i + 1) / (phases.length + 2)) * 100)
        }));
      }

      // Full operation with subdomain enumeration
      addOutput(`\n━━━ SUBDOMAIN ATTACK SURFACE EXPANSION ━━━`, 'info');
      addOutput(`Enumerating subdomains → running SQLi/XSS/CORS/Traversal on each...`, 'info');
      setStatus(prev => ({ ...prev, phase: 'subdomain-scan' }));

      const sdStart = Date.now();
      const { data: fullOp, error: fullError } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: {
          action: 'start-continuous-operation',
          data: { target, objective, max_iterations: 5 }
        }
      });

      if (!fullError && fullOp?.findings) {
        const subFindings = fullOp.findings.filter((f: any) => f.subdomain);
        const primaryFindings = fullOp.findings.filter((f: any) => !f.subdomain);
        
        // Merge new primary findings not already in allFindings
        primaryFindings.forEach((f: Finding) => {
          if (!allFindings.some(af => af.title === f.title && af.type === f.type)) {
            allFindings.push(f);
          }
        });

        if (subFindings.length > 0) {
          allFindings.push(...subFindings);
          const sdCount = fullOp.subdomains_discovered?.length || 0;
          addOutput(`Subdomain scan: ${subFindings.length} findings across ${sdCount} subdomains`, 'success');
          if (fullOp.subdomains_discovered?.length > 0) {
            addOutput(`Discovered: ${fullOp.subdomains_discovered.join(', ')}`, 'info');
          }
          await recordLearning('subdomain-enum', target, subFindings, Date.now() - sdStart, 'subdomain-scan');
          buildSubdomainMap(allFindings);
        } else {
          addOutput(`Subdomain scan: no live subdomains found — focusing on primary target`, 'warning');
        }
      }

      setStatus(prev => ({
        ...prev,
        findings: [...allFindings],
        progress: Math.round((phases.length + 1) / (phases.length + 2) * 100)
      }));

      // Correlation engine
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
      const subTotal = allFindings.filter((f: any) => f.subdomain).length;
      const corsTotal = allFindings.filter(f => categorizeFinding(f) === 'cors').length;
      const traversalTotal = allFindings.filter(f => categorizeFinding(f) === 'traversal').length;
      const cookieTotal = allFindings.filter(f => categorizeFinding(f) === 'cookie').length;

      addOutput(`\n━━━ OPERATION COMPLETE ━━━`, 'success');
      addOutput(`Total: ${allFindings.length} findings | Verified: ${verifiedTotal} | Subdomains: ${subTotal}`, 'success');
      addOutput(`Categories: CORS(${corsTotal}) Traversal(${traversalTotal}) Cookie(${cookieTotal})`, 'info');

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
        modelConfidence: Math.min(0.95, prev.modelConfidence + (allFindings.length * 0.01)),
        adaptationsApplied: prev.adaptationsApplied + allFindings.filter((f: any) => f.retried).length,
      }));

      toast({
        title: "Operation Complete",
        description: `Found ${allFindings.length} vulnerabilities (${verifiedTotal} dual-verified) | ${allCorrelations.length} attack paths`
      });

    } catch (error: any) {
      console.error('Operation error:', error);
      addOutput(`Error: ${error.message}`, 'error');
      setStatus(prev => ({ ...prev, isRunning: false, phase: 'error', findings: allFindings }));
      toast({ title: "Operation Failed", description: error.message, variant: "destructive" });
    }
  };

  const correlateFindings = async () => {
    if (status.findings.length < 2) {
      toast({ title: "Insufficient Data", description: "Need at least 2 findings to correlate", variant: "destructive" });
      return;
    }
    addOutput("Running correlation analysis...", 'info');
    try {
      const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: { action: 'correlate-findings', data: { findings: status.findings, target_context: { target } } }
      });
      if (error) throw error;
      setStatus(prev => ({ ...prev, correlations: data.correlations || [], attackChains: data.attack_chains || [] }));
      addOutput(`Correlation complete - Risk Score: ${data.risk_score}`, 'success');
    } catch (error: any) {
      addOutput(`Correlation error: ${error.message}`, 'error');
    }
  };

  const getRecommendations = async () => {
    addOutput("Fetching AI recommendations...", 'info');
    try {
      const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: { action: 'get-agent-recommendations', data: { target, current_phase: status.phase, existing_findings: status.findings } }
      });
      if (error) throw error;
      addOutput(`Recommendations (Confidence: ${Math.round(data.confidence_score * 100)}%)`, 'success');
      data.recommendations?.recommended_tools?.forEach((tool: string) => addOutput(`  → ${tool}`, 'info'));
    } catch (error: any) {
      addOutput(`Recommendation error: ${error.message}`, 'error');
    }
  };

  const openPocModal = (finding: Finding) => {
    setSelectedFinding(finding);
    setPocModalOpen(true);
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

  const getRiskBadgeColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'border-red-500/40 text-red-400 bg-red-500/10';
      case 'high': return 'border-orange-500/40 text-orange-400 bg-orange-500/10';
      case 'medium': return 'border-yellow-500/40 text-yellow-400 bg-yellow-500/10';
      case 'low': return 'border-blue-500/40 text-blue-400 bg-blue-500/10';
      default: return 'border-green-500/40 text-green-400 bg-green-500/10';
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

  // Filter dedicated findings
  const dedicatedFindings = status.findings.filter(f => {
    const cat = categorizeFinding(f);
    if (dedFilterType === 'all') return cat !== 'other';
    return cat === dedFilterType;
  });

  const FindingCard = ({ finding, showPoc = true }: { finding: Finding; showPoc?: boolean }) => (
    <div
      className={`p-3 border rounded-lg bg-card/50 ${finding.verified === false ? 'border-yellow-500/30 opacity-80' : 'border-border'}`}
    >
      <div className="flex items-start justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {getPhaseIcon(finding.subdomain ? 'scanning' : finding.phase)}
          <span className="font-medium text-sm truncate">{finding.title}</span>
        </div>
        <div className="flex items-center gap-1 flex-wrap">
          {finding.subdomain && (
            <Badge variant="outline" className="text-xs border-blue-500/40 text-blue-400">🌐 {finding.subdomain}</Badge>
          )}
          {finding.verified === true && (
            <Badge variant="outline" className="text-xs border-green-500/40 text-green-400">✅ Verified</Badge>
          )}
          {finding.verified === false && (
            <Badge variant="outline" className="text-xs border-yellow-500/40 text-yellow-400">⚠️ Unverified</Badge>
          )}
          {finding.exploitable && (
            <Badge variant="destructive" className="text-xs">Exploitable</Badge>
          )}
          <Badge className={`text-xs ${getSeverityColor(finding.severity)}`}>{finding.severity}</Badge>
        </div>
      </div>
      <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{finding.description}</p>
      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
        <span>Tool: {finding.tool_used}</span>
        <span>Phase: {finding.subdomain ? 'subdomain-scan' : finding.phase}</span>
        {finding.confidence !== undefined && (
          <span className={finding.confidence >= 0.8 ? 'text-green-400' : finding.confidence >= 0.6 ? 'text-yellow-400' : 'text-red-400'}>
            Confidence: {Math.round(finding.confidence * 100)}%
          </span>
        )}
        {showPoc && finding.evidence?.raw?.poc && (
          <Button
            variant="outline"
            size="sm"
            className="text-xs h-5 px-2 ml-auto"
            onClick={() => openPocModal(finding)}
          >
            <Code2 className="h-3 w-3 mr-1" />
            View POC
          </Button>
        )}
      </div>
    </div>
  );

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
            <p className="text-muted-foreground">AI-powered autonomous security operations with self-learning & subdomain expansion</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={status.isRunning ? "default" : "secondary"} className="gap-1">
            <Activity className={`h-3 w-3 ${status.isRunning ? 'animate-pulse' : ''}`} />
            {status.phase}
          </Badge>
          <Badge variant="outline" className="gap-1">
            <Cpu className="h-3 w-3" />
            AI Confidence: {Math.round(learningMetrics.modelConfidence * 100)}%
          </Badge>
        </div>
      </div>

      {/* Learning Metrics Bar */}
      <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-transparent">
        <CardContent className="py-4">
          <div className="grid grid-cols-5 gap-4">
            {[
              { label: 'Model Confidence', value: learningMetrics.modelConfidence.toFixed(2), color: 'text-primary' },
              { label: 'Successful Techniques', value: learningMetrics.successfulTechniques, color: 'text-green-400' },
              { label: 'Failed Techniques', value: learningMetrics.failedTechniques, color: 'text-red-400' },
              { label: 'Adaptations Applied', value: learningMetrics.adaptationsApplied, color: 'text-yellow-400' },
              { label: 'Pattern Match Rate', value: `${(learningMetrics.patternMatchRate * 100).toFixed(0)}%`, color: 'text-blue-400' },
            ].map(m => (
              <div key={m.label} className="text-center">
                <div className={`text-2xl font-bold ${m.color}`}>{m.value}</div>
                <div className="text-xs text-muted-foreground">{m.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Panel */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-7 w-full text-xs">
              <TabsTrigger value="control">Control</TabsTrigger>
              <TabsTrigger value="findings">
                Findings
                {status.findings.length > 0 && <Badge className="ml-1 text-xs h-4 px-1">{status.findings.length}</Badge>}
              </TabsTrigger>
              <TabsTrigger value="surface">
                <Globe className="h-3 w-3 mr-1" />
                Surface
              </TabsTrigger>
              <TabsTrigger value="specialized">
                <Filter className="h-3 w-3 mr-1" />
                CORS/Trav
              </TabsTrigger>
              <TabsTrigger value="correlations">Correlations</TabsTrigger>
              <TabsTrigger value="chains">Chains</TabsTrigger>
              <TabsTrigger value="learning">Learning</TabsTrigger>
            </TabsList>

            {/* === CONTROL TAB === */}
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
                    <Slider value={[maxIterations]} onValueChange={(v) => setMaxIterations(v[0])} min={10} max={200} step={10} disabled={status.isRunning} />
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="flex items-center space-x-2">
                      <Switch checked={autoAdapt} onCheckedChange={setAutoAdapt} disabled={status.isRunning} />
                      <Label>Auto-Adapt</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch checked={stealthMode} onCheckedChange={setStealthMode} disabled={status.isRunning} />
                      <Label>Stealth Mode</Label>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button onClick={startContinuousOperation} disabled={status.isRunning || !target} className="flex-1">
                      {status.isRunning ? (
                        <><RefreshCw className="mr-2 h-4 w-4 animate-spin" />Running...</>
                      ) : (
                        <><Play className="mr-2 h-4 w-4" />Start Operation</>
                      )}
                    </Button>
                    <Button variant="outline" onClick={getRecommendations} disabled={status.isRunning}>
                      <Zap className="mr-2 h-4 w-4" />AI Recommendations
                    </Button>
                  </div>

                  {status.isRunning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Phase: {status.phase}</span>
                        <span>{status.progress}%</span>
                      </div>
                      <Progress value={status.progress} />
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Live Output */}
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Real-Time Scan Output
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-72">
                    <div ref={outputRef} className="p-4 font-mono text-xs space-y-1 bg-black/50 rounded-b-lg">
                      {liveOutput.length === 0 ? (
                        <div className="text-muted-foreground">Awaiting operation start...</div>
                      ) : (
                        liveOutput.map((line, i) => (
                          <div key={i} className={
                            line.includes('✅') || line.includes('[VULNERABLE]') || line.includes('[CRITICAL]') ? 'text-green-400' :
                            line.includes('⚠️') || line.includes('[POSSIBLE]') || line.includes('[AUTO-RETRY]') ? 'text-yellow-400' :
                            line.includes('❌') ? 'text-red-400' :
                            line.includes('━━━') ? 'text-primary font-bold' :
                            'text-muted-foreground'
                          }>
                            {line}
                          </div>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            {/* === FINDINGS TAB === */}
            <TabsContent value="findings">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5" />
                        All Discovered Findings ({status.findings.length})
                      </CardTitle>
                      <CardDescription>
                        {status.findings.filter(f => f.verified).length} dual-verified ✅ | {status.findings.filter(f => f.subdomain).length} from subdomains 🌐
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {status.findings.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No findings yet. Start an operation to discover vulnerabilities.</div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-3">
                        {status.findings.map((finding: any) => (
                          <FindingCard key={finding.id} finding={finding} />
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === SUBDOMAIN ATTACK SURFACE MAP === */}
            <TabsContent value="surface">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe className="h-5 w-5" />
                    Subdomain Attack Surface Map
                  </CardTitle>
                  <CardDescription>
                    {subdomainMap.length} subdomains discovered — click a row to see findings
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {subdomainMap.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Globe className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      No subdomains mapped yet. Run an operation with subdomain expansion.
                    </div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-2">
                        {/* Header */}
                        <div className="grid grid-cols-5 gap-2 text-xs font-medium text-muted-foreground px-3 py-2 border-b border-border">
                          <span className="col-span-2">Subdomain</span>
                          <span>Status</span>
                          <span>Risk Level</span>
                          <span>Findings</span>
                        </div>
                        {subdomainMap.map((entry) => (
                          <div key={entry.domain} className="grid grid-cols-5 gap-2 items-center px-3 py-3 rounded-lg border border-border hover:bg-muted/30 transition-colors">
                            <div className="col-span-2">
                              <div className="font-mono text-sm font-medium flex items-center gap-1">
                                <Globe className="h-3 w-3 text-blue-400" />
                                {entry.domain}
                              </div>
                              {entry.technologies.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {entry.technologies.slice(0, 2).map(t => (
                                    <span key={t} className="text-xs bg-muted px-1 rounded">{t}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                            <div>
                              <Badge variant="outline" className="text-xs border-green-500/40 text-green-400 gap-1">
                                <CheckCircle2 className="h-3 w-3" />
                                Live
                              </Badge>
                            </div>
                            <div>
                              <Badge variant="outline" className={`text-xs ${getRiskBadgeColor(entry.riskScore)}`}>
                                {entry.riskScore.toUpperCase()}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-sm">{entry.findings.length}</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 px-2 text-xs"
                                onClick={() => {
                                  setActiveTab('findings');
                                  // Filter is implicit since subdomain findings show subdomain badge
                                }}
                              >
                                <ChevronRight className="h-3 w-3" />
                              </Button>
                            </div>
                          </div>
                        ))}
                        
                        {/* Summary stats */}
                        <div className="mt-4 p-3 rounded-lg bg-muted/20 border border-border">
                          <div className="grid grid-cols-4 gap-4 text-center">
                            {['critical', 'high', 'medium', 'low'].map(sev => {
                              const count = subdomainMap.filter(e => e.riskScore === sev).length;
                              return (
                                <div key={sev}>
                                  <div className={`text-lg font-bold ${sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-yellow-400' : 'text-blue-400'}`}>{count}</div>
                                  <div className="text-xs text-muted-foreground capitalize">{sev}</div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === CORS / TRAVERSAL / COOKIE DEDICATED TAB === */}
            <TabsContent value="specialized">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Filter className="h-5 w-5" />
                        CORS / Directory Traversal / Cookie Hijacking
                      </CardTitle>
                      <CardDescription>
                        Real-time specialized findings — click any finding for full POC detail
                      </CardDescription>
                    </div>
                    <div className="flex gap-1">
                      {(['all', 'cors', 'traversal', 'cookie'] as const).map(f => (
                        <Button
                          key={f}
                          variant={dedFilterType === f ? 'default' : 'outline'}
                          size="sm"
                          className="text-xs h-7"
                          onClick={() => setDedFilterType(f)}
                        >
                          {f === 'all' ? 'All' : f === 'cors' ? '🌐 CORS' : f === 'traversal' ? '📂 Traversal' : '🍪 Cookie'}
                          {f !== 'all' && (
                            <Badge className="ml-1 text-xs h-4 px-1" variant="secondary">
                              {status.findings.filter(finding => categorizeFinding(finding) === f).length}
                            </Badge>
                          )}
                        </Button>
                      ))}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {/* Live output stream for specialized scans */}
                  {status.isRunning && (
                    <div className="mb-4 p-3 rounded-lg bg-black/40 border border-border">
                      <div className="text-xs text-primary font-mono mb-1">🔴 Live Scan Output ({status.phase})</div>
                      <ScrollArea className="h-24">
                        <div className="font-mono text-xs space-y-0.5">
                          {liveOutput.filter(l => {
                            const lower = l.toLowerCase();
                            if (dedFilterType === 'cors') return lower.includes('cors') || lower.includes('origin');
                            if (dedFilterType === 'traversal') return lower.includes('traversal') || lower.includes('lfi') || lower.includes('path');
                            if (dedFilterType === 'cookie') return lower.includes('cookie') || lower.includes('session') || lower.includes('hijack');
                            return lower.includes('cors') || lower.includes('traversal') || lower.includes('cookie') || lower.includes('session');
                          }).slice(-10).map((line, i) => (
                            <div key={i} className={line.includes('✅') || line.includes('[VULNERABLE]') ? 'text-green-400' : line.includes('⚠️') ? 'text-yellow-400' : 'text-muted-foreground'}>
                              {line}
                            </div>
                          ))}
                          {liveOutput.length === 0 && <div className="text-muted-foreground">Waiting for scan to start...</div>}
                        </div>
                      </ScrollArea>
                    </div>
                  )}

                  {dedicatedFindings.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Filter className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      No {dedFilterType === 'all' ? 'CORS/Traversal/Cookie' : dedFilterType} findings yet.
                      <p className="text-xs mt-1">Run an operation — exploitation & post-exploit phases will populate this tab.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[480px]">
                      <div className="space-y-3">
                        {dedicatedFindings.map((finding) => {
                          const cat = categorizeFinding(finding);
                          return (
                            <div
                              key={finding.id}
                              className="p-4 border border-border rounded-lg bg-card/50 hover:bg-card/80 transition-colors cursor-pointer"
                              onClick={() => openPocModal(finding)}
                            >
                              <div className="flex items-start justify-between flex-wrap gap-2">
                                <div className="flex items-center gap-2 flex-1 min-w-0">
                                  <span className="text-lg">
                                    {cat === 'cors' ? '🌐' : cat === 'traversal' ? '📂' : '🍪'}
                                  </span>
                                  <div className="min-w-0">
                                    <div className="font-medium text-sm truncate">{finding.title}</div>
                                    <div className="text-xs text-muted-foreground uppercase">{cat}</div>
                                  </div>
                                </div>
                                <div className="flex items-center gap-1 flex-wrap">
                                  {finding.subdomain && <Badge variant="outline" className="text-xs border-blue-500/40 text-blue-400">🌐 {finding.subdomain}</Badge>}
                                  {finding.verified === true && <Badge variant="outline" className="text-xs border-green-500/40 text-green-400">✅ Verified</Badge>}
                                  {finding.verified === false && <Badge variant="outline" className="text-xs border-yellow-500/40 text-yellow-400">⚠️ Unverified</Badge>}
                                  <Badge className={`text-xs ${getSeverityColor(finding.severity)}`}>{finding.severity}</Badge>
                                  <Button variant="outline" size="sm" className="text-xs h-6 px-2">
                                    <Code2 className="h-3 w-3 mr-1" />POC
                                  </Button>
                                </div>
                              </div>
                              <p className="text-sm text-muted-foreground mt-2 line-clamp-2">{finding.description}</p>
                              <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                                <span>Tool: {finding.tool_used}</span>
                                {finding.confidence !== undefined && (
                                  <span className={finding.confidence >= 0.8 ? 'text-green-400' : 'text-yellow-400'}>
                                    Confidence: {Math.round(finding.confidence * 100)}%
                                  </span>
                                )}
                                <span className="ml-auto text-primary text-xs">Click for full POC →</span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === CORRELATIONS TAB === */}
            <TabsContent value="correlations">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2"><GitBranch className="h-5 w-5" />Finding Correlations</CardTitle>
                      <CardDescription>AI-identified attack paths combining multiple findings</CardDescription>
                    </div>
                    <Button onClick={correlateFindings} disabled={status.findings.length < 2}>
                      <RefreshCw className="mr-2 h-4 w-4" />Re-correlate
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {status.correlations.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No correlations yet. Discover more findings or click Re-correlate.</div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-4">
                        {status.correlations.map((c) => (
                          <div key={c.id} className="p-4 border rounded-lg bg-gradient-to-r from-primary/5 to-transparent">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-semibold">{c.attack_path}</span>
                              <Badge variant="outline">{Math.round(c.exploitation_probability * 100)}% Probability</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{c.description}</p>
                            <div className="flex items-center gap-4 mt-3">
                              <div className="flex items-center gap-1 text-xs"><TrendingUp className="h-3 w-3" />Risk Amp: {c.risk_amplification}x</div>
                              <div className="flex items-center gap-1 text-xs"><Layers className="h-3 w-3" />{c.findings.length} findings linked</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === ATTACK CHAINS TAB === */}
            <TabsContent value="chains">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><Crosshair className="h-5 w-5" />Generated Attack Chains</CardTitle>
                  <CardDescription>Multi-stage attack sequences with MITRE ATT&CK mapping</CardDescription>
                </CardHeader>
                <CardContent>
                  {status.attackChains.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No attack chains generated yet.</div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-4">
                        {status.attackChains.map((chain) => (
                          <div key={chain.id} className="p-4 border rounded-lg">
                            <div className="flex items-center justify-between mb-3">
                              <span className="font-semibold">{chain.name}</span>
                              <div className="flex items-center gap-2">
                                <Badge className={chain.impact === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}>{chain.impact}</Badge>
                                <Badge variant="outline">{Math.round(chain.success_probability * 100)}% Success</Badge>
                              </div>
                            </div>
                            <div className="space-y-2">
                              {chain.steps.map((step: any, idx: number) => (
                                <div key={idx} className="flex items-center gap-2 text-sm">
                                  <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-xs">{step.order}</div>
                                  <span className="text-muted-foreground">{step.action}</span>
                                  <span className="text-xs">→ {step.expected_outcome}</span>
                                </div>
                              ))}
                            </div>
                            <div className="flex flex-wrap gap-1 mt-3">
                              {chain.mitre_mapping.slice(0, 4).map((tech: string, idx: number) => (
                                <Badge key={idx} variant="secondary" className="text-xs">{tech}</Badge>
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

            {/* === LEARNING TAB === */}
            <TabsContent value="learning">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><Database className="h-5 w-5" />AI Learning & Adaptation Log</CardTitle>
                  <CardDescription>All scan outcomes recorded to ai_learnings for model fine-tuning</CardDescription>
                </CardHeader>
                <CardContent>
                  {status.learningUpdates.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Brain className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      No learning data yet. Run operations to collect training data.
                      <p className="text-xs mt-1 text-muted-foreground">Each phase result is automatically recorded with tool_used, findings, and improvement_strategy.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-3">
                        {status.learningUpdates.map((update, idx) => (
                          <div key={idx} className="p-3 border rounded-lg bg-card/50">
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{update.technique}</span>
                              <Badge variant={update.success ? "default" : "destructive"}>{update.success ? 'Success' : 'Failed'}</Badge>
                            </div>
                            {update.adaptation_strategy && (
                              <div className="mt-2 p-2 bg-yellow-500/10 rounded text-sm">
                                <span className="text-yellow-400">Adaptation: </span>
                                {typeof update.adaptation_strategy === 'string' ? update.adaptation_strategy : update.adaptation_strategy?.recommended_action}
                              </div>
                            )}
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                              <span>Confidence: {Math.round((update.confidence || 0.5) * 100)}%</span>
                              <span>Findings: {update.findings_count}</span>
                              {update.execution_time && <span>Time: {Math.round(update.execution_time / 1000)}s</span>}
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
              <CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="h-4 w-4" />Operation Stats</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: 'Total Findings', value: status.findings.length, color: '' },
                { label: 'Critical', value: status.findings.filter(f => f.severity === 'critical').length, color: 'text-red-400' },
                { label: 'High', value: status.findings.filter(f => f.severity === 'high').length, color: 'text-orange-400' },
                { label: 'Exploitable', value: status.findings.filter(f => f.exploitable).length, color: 'text-yellow-400' },
                { label: '🌐 Subdomain', value: status.findings.filter(f => f.subdomain).length, color: 'text-blue-400' },
                { label: '✅ Verified', value: status.findings.filter(f => f.verified).length, color: 'text-green-400' },
                { label: '🌐 CORS Issues', value: status.findings.filter(f => categorizeFinding(f) === 'cors').length, color: 'text-purple-400' },
                { label: '📂 Traversal', value: status.findings.filter(f => categorizeFinding(f) === 'traversal').length, color: 'text-orange-300' },
                { label: '🍪 Cookie Issues', value: status.findings.filter(f => categorizeFinding(f) === 'cookie').length, color: 'text-yellow-300' },
                { label: 'Correlations', value: status.correlations.length, color: '' },
                { label: 'Attack Chains', value: status.attackChains.length, color: '' },
              ].map(s => (
                <div key={s.label} className="flex justify-between">
                  <span className="text-muted-foreground text-sm">{s.label}</span>
                  <span className={`font-mono ${s.color}`}>{s.value}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2"><Shield className="h-4 w-4" />Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {status.findings.length === 0 ? (
                <div className="text-xs text-muted-foreground text-center py-4">No findings to display</div>
              ) : (
                <div className="space-y-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                    const count = status.findings.filter(f => f.severity === sev).length;
                    const pct = (count / status.findings.length) * 100;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="capitalize">{sev}</span>
                          <span>{count}</span>
                        </div>
                        <Progress value={pct} className="h-1" />
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-primary/10 to-transparent border-primary/20">
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2"><Brain className="h-4 w-4" />AI Model Status</CardTitle>
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
                  <span className="text-green-400">✓ High confidence — reliable predictions</span>
                ) : learningMetrics.modelConfidence >= 0.6 ? (
                  <span className="text-yellow-400">◐ Moderate — more data recommended</span>
                ) : (
                  <span className="text-orange-400">○ Building knowledge base...</span>
                )}
              </div>
              <div className="text-xs text-muted-foreground border-t border-border pt-2">
                <Info className="h-3 w-3 inline mr-1" />
                All scan outcomes auto-recorded to AI Learning DB with tool_used + improvement_strategy fields.
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* POC Detail Modal */}
      <Dialog open={pocModalOpen} onOpenChange={setPocModalOpen}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5 text-primary" />
              {selectedFinding?.title}
            </DialogTitle>
            <DialogDescription className="flex items-center gap-2 flex-wrap mt-1">
              {selectedFinding && (
                <>
                  <Badge className={getSeverityColor(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
                  {selectedFinding.verified === true && <Badge variant="outline" className="border-green-500/40 text-green-400">✅ Dual-Verified</Badge>}
                  {selectedFinding.verified === false && <Badge variant="outline" className="border-yellow-500/40 text-yellow-400">⚠️ Unverified — Use with caution</Badge>}
                  {selectedFinding.confidence !== undefined && (
                    <Badge variant="outline">Confidence: {Math.round(selectedFinding.confidence * 100)}%</Badge>
                  )}
                  {selectedFinding.subdomain && <Badge variant="outline" className="border-blue-500/40 text-blue-400">🌐 {selectedFinding.subdomain}</Badge>}
                </>
              )}
            </DialogDescription>
          </DialogHeader>

          {selectedFinding && (
            <div className="space-y-4 mt-2">
              {/* Description */}
              <div>
                <h4 className="text-sm font-semibold mb-1 text-foreground">Vulnerability Description</h4>
                <p className="text-sm text-muted-foreground leading-relaxed">{selectedFinding.description}</p>
              </div>

              {/* POC */}
              {selectedFinding.evidence?.raw?.poc && (
                <div>
                  <h4 className="text-sm font-semibold mb-1 text-foreground flex items-center gap-1">
                    <Code2 className="h-4 w-4 text-primary" />
                    Proof of Concept (PoC)
                  </h4>
                  <pre className="p-3 bg-black/60 rounded-lg text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap border border-green-500/20 max-h-48">
                    {selectedFinding.evidence.raw.poc}
                  </pre>
                </div>
              )}

              {/* Remediation */}
              {selectedFinding.evidence?.raw?.remediation && (
                <div>
                  <h4 className="text-sm font-semibold mb-1 text-foreground flex items-center gap-1">
                    <Shield className="h-4 w-4 text-blue-400" />
                    Remediation
                  </h4>
                  <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg text-sm text-muted-foreground whitespace-pre-wrap">
                    {selectedFinding.evidence.raw.remediation}
                  </div>
                </div>
              )}

              {/* Raw Evidence */}
              <div>
                <h4 className="text-sm font-semibold mb-1 text-foreground">Technical Evidence</h4>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {[
                    { label: 'Scan Type', value: selectedFinding.tool_used },
                    { label: 'Phase', value: selectedFinding.phase },
                    { label: 'Timestamp', value: new Date(selectedFinding.timestamp).toLocaleString() },
                    { label: 'Exploitable', value: selectedFinding.exploitable ? 'Yes ⚠️' : 'No' },
                    { label: 'Verification', value: selectedFinding.verified ? 'Dual-verified (2 techniques)' : 'Single technique' },
                    { label: 'Target', value: selectedFinding.evidence?.target || selectedFinding.subdomain || target },
                  ].map(item => (
                    <div key={item.label} className="p-2 bg-muted/30 rounded">
                      <span className="text-muted-foreground">{item.label}: </span>
                      <span className="font-medium">{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Verification warning for unverified */}
              {selectedFinding.verified === false && (
                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400 mt-0.5 shrink-0" />
                  <div className="text-sm text-yellow-300">
                    <strong>Possible False Positive:</strong> This finding was not confirmed by a secondary verification technique. Manually verify before including in report. Confidence: {Math.round((selectedFinding.confidence || 0.45) * 100)}%.
                  </div>
                </div>
              )}

              {/* Verified badge */}
              {selectedFinding.verified === true && (
                <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg flex gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                  <div className="text-sm text-green-300">
                    <strong>Dual-Verified:</strong> This finding was confirmed by two independent scanning techniques. High confidence ({Math.round((selectedFinding.confidence || 0.9) * 100)}%) — safe to include in report.
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ContinuousRedTeamAgent;
