/**
 * Continuous Red Team Agent - AI-Powered Autonomous Security Operations
 * v4: OWASP Top 10 Full Coverage | AI Reasoning Chatbox | Connection Check | Tech-Aware Payloads | Target Tree | Vuln KB
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
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import {
  Brain, Target, Play, RefreshCw, Shield, AlertTriangle, Activity, Zap,
  GitBranch, Database, TrendingUp, Eye, Network, Bug, Lock, Crosshair,
  Layers, Cpu, BarChart3, Globe, ChevronRight, Code2, Filter,
  CheckCircle2, XCircle, Info, MessageSquare, Send, TreePine,
  Wifi, WifiOff, BookOpen, ChevronDown
} from "lucide-react";

// ===== INTERFACES =====
interface Finding {
  id: string; type: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string; description: string; evidence: any; timestamp: string;
  phase: string; tool_used: string; exploitable: boolean;
  confidence?: number; verified?: boolean; subdomain?: string;
}

interface SubdomainEntry {
  domain: string; live: boolean; technologies: string[]; findings: Finding[];
  riskScore: 'critical' | 'high' | 'medium' | 'low' | 'clean';
}

interface Correlation { id: string; findings: string[]; attack_path: string; risk_amplification: number; exploitation_probability: number; description: string; }
interface AttackChain { id: string; name: string; steps: any[]; success_probability: number; impact: string; mitre_mapping: string[]; }

interface AgentStatus {
  isRunning: boolean; phase: string; progress: number; iteration: number; maxIterations: number;
  findings: Finding[]; correlations: Correlation[]; attackChains: AttackChain[]; learningUpdates: any[];
}

interface LearningMetrics {
  modelConfidence: number; successfulTechniques: number; failedTechniques: number;
  adaptationsApplied: number; patternMatchRate: number;
}

interface AIThought {
  thought: string; actions?: string[]; risk_assessment?: string; owasp_coverage?: string[];
  isHuman?: boolean; timestamp: string;
}

interface TargetTreeNode {
  name: string; type: string; children?: TargetTreeNode[]; count?: number;
  severity?: string; verified?: boolean; port?: number; service?: string;
  summary?: any; exploits?: string[];
}

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

// ===== TREE COMPONENT =====
const TreeNodeComponent = ({ node, depth = 0 }: { node: TargetTreeNode; depth?: number }) => {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;
  const icon = node.type === 'domain' ? '🌐' : node.type === 'subdomain' ? '🔗' : node.type === 'endpoint' ? '📡' :
    node.type === 'technology' ? '⚙️' : node.type === 'port' ? '🔌' : node.type === 'vulnerability' ? '🐛' : node.type === 'group' ? '📁' : '📄';
  const sevColor = node.severity === 'critical' ? 'text-red-400' : node.severity === 'high' ? 'text-orange-400' :
    node.severity === 'medium' ? 'text-yellow-400' : '';

  return (
    <div style={{ marginLeft: depth * 16 }}>
      <div
        className={`flex items-center gap-1.5 py-1 px-2 rounded hover:bg-muted/30 cursor-pointer text-sm ${sevColor}`}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {hasChildren && <ChevronDown className={`h-3 w-3 transition-transform ${expanded ? '' : '-rotate-90'}`} />}
        {!hasChildren && <span className="w-3" />}
        <span>{icon}</span>
        <span className="font-mono truncate">{node.name}</span>
        {node.count !== undefined && <Badge variant="secondary" className="text-xs h-4 px-1 ml-1">{node.count}</Badge>}
        {node.verified && <CheckCircle2 className="h-3 w-3 text-green-400" />}
        {node.severity && <Badge className={`text-xs h-4 px-1 ${sevColor}`}>{node.severity}</Badge>}
      </div>
      {expanded && hasChildren && node.children!.map((child, i) => (
        <TreeNodeComponent key={`${child.name}-${i}`} node={child} depth={depth + 1} />
      ))}
    </div>
  );
};

const ContinuousRedTeamAgent = () => {
  const { toast } = useToast();
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("comprehensive-assessment");
  const [maxIterations, setMaxIterations] = useState(50);
  const [autoAdapt, setAutoAdapt] = useState(true);
  const [stealthMode, setStealthMode] = useState(false);

  const [status, setStatus] = useState<AgentStatus>({
    isRunning: false, phase: 'idle', progress: 0, iteration: 0, maxIterations: 50,
    findings: [], correlations: [], attackChains: [], learningUpdates: []
  });

  const [learningMetrics, setLearningMetrics] = useState<LearningMetrics>({
    modelConfidence: 0.5, successfulTechniques: 0, failedTechniques: 0, adaptationsApplied: 0, patternMatchRate: 0
  });

  const [subdomainMap, setSubdomainMap] = useState<SubdomainEntry[]>([]);
  const [dedFilterType, setDedFilterType] = useState<'all' | 'cors' | 'traversal' | 'cookie'>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [pocModalOpen, setPocModalOpen] = useState(false);
  const [liveOutput, setLiveOutput] = useState<string[]>([]);
  const outputRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState("control");

  // AI Chatbox state
  const [aiThoughts, setAiThoughts] = useState<AIThought[]>([]);
  const [humanInput, setHumanInput] = useState("");
  const chatRef = useRef<HTMLDivElement>(null);

  // Target tree
  const [targetTree, setTargetTree] = useState<TargetTreeNode | null>(null);

  // Connection status
  const [connectionStatus, setConnectionStatus] = useState<any>(null);
  const [checkingConnection, setCheckingConnection] = useState(false);

  // Vuln KB
  const [vulnKB, setVulnKB] = useState<any[]>([]);
  const [kbUpdating, setKbUpdating] = useState(false);

  // Detected tech/ports
  const [detectedTech, setDetectedTech] = useState<string[]>([]);
  const [detectedPorts, setDetectedPorts] = useState<number[]>([]);

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [liveOutput]);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [aiThoughts]);

  const addOutput = useCallback((message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = { info: '📡', success: '✅', warning: '⚠️', error: '❌' }[type];
    setLiveOutput(prev => [...prev, `[${timestamp}] ${prefix} ${message}`]);
  }, []);

  const addAIThought = useCallback((thought: string, actions?: string[], owasp?: string[]) => {
    setAiThoughts(prev => [...prev, { thought, actions, owasp_coverage: owasp, timestamp: new Date().toLocaleTimeString() }]);
  }, []);

  // ===== CONNECTION CHECK =====
  const checkConnection = async () => {
    if (!target) return;
    setCheckingConnection(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-scan-orchestrator', {
        body: { action: 'check-connection', data: { target } }
      });
      if (error) throw error;
      setConnectionStatus(data);
      if (!data.reachable) {
        toast({ title: "Target Unreachable", description: data.recommendation, variant: "destructive" });
      } else {
        toast({ title: "Connection OK", description: `${target} is reachable (${data.results?.find((r: any) => r.reachable)?.latency}ms)` });
      }
    } catch (e: any) {
      setConnectionStatus({ reachable: false, recommendation: e.message });
      toast({ title: "Connection Check Failed", description: e.message, variant: "destructive" });
    }
    setCheckingConnection(false);
  };

  // ===== AI REASONING =====
  const getAIThought = async (phase: string, context: any, correction?: string) => {
    try {
      const { data } = await supabase.functions.invoke('ai-scan-orchestrator', {
        body: { action: 'ai-reasoning', data: { target, phase, context, humanCorrection: correction } }
      });
      if (data?.thought) {
        addAIThought(data.thought, data.actions, data.owasp_coverage);
      }
    } catch { /* non-critical */ }
  };

  // ===== SEND HUMAN CORRECTION =====
  const sendHumanCorrection = async () => {
    if (!humanInput.trim()) return;
    const correction = humanInput.trim();
    setHumanInput("");
    setAiThoughts(prev => [...prev, { thought: correction, isHuman: true, timestamp: new Date().toLocaleTimeString() }]);
    addOutput(`🧑 Human correction: ${correction}`, 'info');
    await getAIThought(status.phase, { findings_count: status.findings.length, correction_applied: true }, correction);
  };

  // ===== UPDATE VULN KB =====
  const updateKB = async () => {
    setKbUpdating(true);
    try {
      const { data } = await supabase.functions.invoke('ai-scan-orchestrator', {
        body: { action: 'update-vuln-kb', data: {} }
      });
      if (data?.entries) {
        setVulnKB(data.entries);
        toast({ title: "Knowledge Base Updated", description: `${data.entries.length} entries loaded (${data.source})` });
      }
    } catch (e: any) {
      toast({ title: "KB Update Failed", description: e.message, variant: "destructive" });
    }
    setKbUpdating(false);
  };

  // ===== BUILD TARGET TREE =====
  const buildTree = async () => {
    try {
      const { data } = await supabase.functions.invoke('ai-scan-orchestrator', {
        body: {
          action: 'build-target-tree',
          data: {
            target,
            findings: status.findings,
            subdomains: subdomainMap.map(s => s.domain),
            techStack: detectedTech,
            ports: detectedPorts,
          }
        }
      });
      if (data?.tree) setTargetTree(data.tree);
    } catch { /* non-critical */ }
  };

  const buildSubdomainMap = useCallback((findings: Finding[]) => {
    const subdomainFindings = findings.filter(f => f.subdomain);
    const subdomainSet = new Map<string, SubdomainEntry>();
    subdomainFindings.forEach(f => {
      const domain = f.subdomain!;
      if (!subdomainSet.has(domain)) {
        subdomainSet.set(domain, { domain, live: true, technologies: [], findings: [], riskScore: 'clean' });
      }
      const entry = subdomainSet.get(domain)!;
      entry.findings.push(f);
      const sev = f.severity;
      if (sev === 'critical') entry.riskScore = 'critical';
      else if (sev === 'high' && entry.riskScore !== 'critical') entry.riskScore = 'high';
      else if (sev === 'medium' && !['critical','high'].includes(entry.riskScore)) entry.riskScore = 'medium';
      else if (sev === 'low' && entry.riskScore === 'clean') entry.riskScore = 'low';
    });
    setSubdomainMap(Array.from(subdomainSet.values()));
  }, []);

  const recordLearning = useCallback(async (toolUsed: string, scanTarget: string, findings: Finding[], executionTime: number, phase: string) => {
    try {
      const successfulTypes = findings.filter(f => f.severity !== 'info').map(f => f.type);
      const improvement_strategy = findings.length > 0
        ? `[${phase}] ${toolUsed} found ${findings.length} vuln(s): ${[...new Set(successfulTypes)].join(', ')}. Confidence: ${findings.filter(f=>f.verified).length}/${findings.length} dual-verified.`
        : `[${phase}] ${toolUsed} returned 0 findings on ${scanTarget}. Try expanding scope or adjusting encoding.`;
      await supabase.from('ai_learnings').insert([{
        tool_used: `red-team-${phase}-${toolUsed}`,
        target: scanTarget, findings: findings as any, success: findings.length > 0,
        execution_time: executionTime, ai_analysis: `Phase: ${phase} | Tool: ${toolUsed} | Found: ${findings.length}`,
        improvement_strategy, user_id: (await supabase.auth.getUser()).data.user?.id ?? '',
      }]);
    } catch (e) { console.warn('[AI Learning] Record failed:', e); }
  }, []);

  // ===== MAIN OPERATION =====
  const startContinuousOperation = async () => {
    if (!target) {
      toast({ title: "Target Required", description: "Please enter a target", variant: "destructive" });
      return;
    }

    // Step 1: Connection check
    addOutput(`Checking connection to ${target}...`, 'info');
    addAIThought(`Let me first verify connectivity to ${target} before starting any scans. This prevents wasted time on unreachable targets.`);

    setCheckingConnection(true);
    let connResult: any;
    try {
      const { data } = await supabase.functions.invoke('ai-scan-orchestrator', {
        body: { action: 'check-connection', data: { target } }
      });
      connResult = data;
      setConnectionStatus(data);
    } catch (e: any) {
      connResult = { reachable: false, recommendation: e.message };
    }
    setCheckingConnection(false);

    if (!connResult?.reachable) {
      addOutput(`Target ${target} is UNREACHABLE. Scan aborted.`, 'error');
      addAIThought(`❌ Connection failed to ${target}. The target is not responding on HTTP or HTTPS. Scan cannot proceed.`);
      toast({ title: "Scan Aborted", description: "Target is unreachable", variant: "destructive" });
      return;
    }

    addOutput(`✓ Connection verified (${connResult.results?.find((r: any) => r.reachable)?.latency}ms)`, 'success');
    addAIThought(`✅ Target is reachable. Server: ${connResult.results?.find((r: any) => r.reachable)?.server || 'unknown'}. Starting full OWASP Top 10 assessment.`, ['recon', 'tech-detection', 'owasp-scan']);

    // Start main operation
    setStatus(prev => ({ ...prev, isRunning: true, phase: 'initializing', progress: 0, findings: [], correlations: [], attackChains: [], learningUpdates: [] }));
    setLiveOutput([]);
    setSubdomainMap([]);
    setAiThoughts(prev => prev); // Keep existing thoughts
    setTargetTree(null);

    const allFindings: Finding[] = [];
    const allCorrelations: Correlation[] = [];
    const allAttackChains: AttackChain[] = [];
    const phases = ['recon', 'scanning', 'exploitation', 'post-exploit'];

    try {
      // Step 2: AI reasoning for each phase
      for (let i = 0; i < phases.length; i++) {
        const phase = phases[i];
        const phaseStart = Date.now();
        addOutput(`\n━━━ Phase: ${phase.toUpperCase()} ━━━`, 'info');
        setStatus(prev => ({ ...prev, phase }));

        // Get AI thinking before phase
        await getAIThought(phase, { findings_count: allFindings.length, target, detected_tech: detectedTech });

        const { data, error } = await supabase.functions.invoke('continuous-red-team-agent', {
          body: { action: 'run-phase', data: { target, phase, config: { auto_adapt: autoAdapt, stealth_mode: stealthMode } } }
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
            else addOutput(line, 'info');
          });
        }

        const phaseFindings: Finding[] = data?.findings || [];

        // Extract tech from recon phase
        if (phase === 'recon' && phaseFindings.length > 0) {
          const techFindings = phaseFindings.filter(f => f.type?.toLowerCase().includes('technology') || f.tool_used === 'tech');
          const newTech = techFindings.map(f => f.title.replace(/Technology:\s*/i, '').trim()).filter(Boolean);
          if (newTech.length > 0) {
            setDetectedTech(prev => [...new Set([...prev, ...newTech])]);
            addAIThought(`Detected technologies: ${newTech.join(', ')}. I'll select payloads tailored to these technologies.`, ['tech-aware-payloads']);
          }
          // Extract ports
          const portFindings = phaseFindings.filter(f => f.title?.includes('Port'));
          const ports = portFindings.map(f => parseInt(f.title.match(/\d+/)?.[0] || '0')).filter(p => p > 0);
          if (ports.length > 0) {
            setDetectedPorts(prev => [...new Set([...prev, ...ports])]);
          }
        }

        if (phaseFindings.length > 0) {
          allFindings.push(...phaseFindings);
          addOutput(`Phase ${phase}: ${phaseFindings.length} findings (${data?.verified_count || 0} ✅ verified)`, 'success');
          await recordLearning(phase, target, phaseFindings, phaseTime, phase);
        } else {
          addOutput(`Phase ${phase} complete: 0 findings`, 'warning');
          await recordLearning(phase, target, [], phaseTime, phase);
        }

        setStatus(prev => ({
          ...prev, findings: [...allFindings],
          progress: Math.round(((i + 1) / (phases.length + 2)) * 100)
        }));
      }

      // Step 3: AI-generated payloads based on detected tech
      if (detectedTech.length > 0 || detectedPorts.length > 0) {
        addAIThought(`Generating AI-powered payloads based on detected technologies: ${detectedTech.join(', ')} and ports: ${detectedPorts.join(', ')}`, ['ai-payload-generation']);
        try {
          const { data: exploitData } = await supabase.functions.invoke('ai-scan-orchestrator', {
            body: { action: 'select-exploits', data: { techStack: detectedTech, ports: detectedPorts, target } }
          });
          if (exploitData?.exploit_notes) {
            exploitData.exploit_notes.forEach((note: string) => addOutput(`🎯 Auto-exploit: ${note}`, 'info'));
          }
        } catch { /* non-critical */ }
      }

      // Step 4: Subdomain expansion
      addOutput(`\n━━━ SUBDOMAIN ATTACK SURFACE EXPANSION ━━━`, 'info');
      addAIThought(`Now expanding attack surface by enumerating subdomains and testing each with full OWASP Top 10 coverage.`, ['subdomain-enum', 'owasp-full']);
      setStatus(prev => ({ ...prev, phase: 'subdomain-scan' }));

      const sdStart = Date.now();
      const { data: fullOp, error: fullError } = await supabase.functions.invoke('continuous-red-team-agent', {
        body: { action: 'start-continuous-operation', data: { target, objective, max_iterations: 5 } }
      });

      if (!fullError && fullOp?.findings) {
        const subFindings = fullOp.findings.filter((f: any) => f.subdomain);
        const primaryFindings = fullOp.findings.filter((f: any) => !f.subdomain);
        primaryFindings.forEach((f: Finding) => {
          if (!allFindings.some(af => af.title === f.title && af.type === f.type)) allFindings.push(f);
        });
        if (subFindings.length > 0) {
          allFindings.push(...subFindings);
          addOutput(`Subdomain scan: ${subFindings.length} findings across ${fullOp.subdomains_discovered?.length || 0} subdomains`, 'success');
          await recordLearning('subdomain-enum', target, subFindings, Date.now() - sdStart, 'subdomain-scan');
          buildSubdomainMap(allFindings);
        }
      }

      // Step 5: Build target tree
      setStatus(prev => ({ ...prev, findings: [...allFindings], progress: 90 }));

      // Step 6: Correlation
      if (allFindings.length >= 2) {
        addOutput(`\n━━━ CORRELATION ENGINE ━━━`, 'info');
        addAIThought(`Correlating ${allFindings.length} findings to identify multi-stage attack paths and risk amplification patterns.`);
        const { data: corrData } = await supabase.functions.invoke('continuous-red-team-agent', {
          body: { action: 'correlate-findings', data: { findings: allFindings, target_context: { target } } }
        });
        if (corrData?.correlations) allCorrelations.push(...corrData.correlations);
        if (corrData?.attack_chains) allAttackChains.push(...corrData.attack_chains);
      }

      const verifiedTotal = allFindings.filter(f => f.verified === true).length;
      addOutput(`\n━━━ OPERATION COMPLETE ━━━`, 'success');
      addOutput(`Total: ${allFindings.length} findings | Verified: ${verifiedTotal}`, 'success');
      addAIThought(`Operation complete. Found ${allFindings.length} vulnerabilities (${verifiedTotal} dual-verified). ${allCorrelations.length} attack paths identified.`);

      setStatus(prev => ({
        ...prev, isRunning: false, phase: 'completed', progress: 100,
        findings: allFindings, correlations: allCorrelations, attackChains: allAttackChains,
      }));

      // Build tree after completion
      setTimeout(() => buildTree(), 500);

      toast({ title: "Operation Complete", description: `Found ${allFindings.length} vulnerabilities (${verifiedTotal} dual-verified)` });

    } catch (error: any) {
      addOutput(`Error: ${error.message}`, 'error');
      addAIThought(`❌ Operation failed: ${error.message}. Check target accessibility and retry.`);
      setStatus(prev => ({ ...prev, isRunning: false, phase: 'error', findings: allFindings }));
      toast({ title: "Operation Failed", description: error.message, variant: "destructive" });
    }
  };

  const correlateFindings = async () => {
    if (status.findings.length < 2) return;
    const { data } = await supabase.functions.invoke('continuous-red-team-agent', {
      body: { action: 'correlate-findings', data: { findings: status.findings, target_context: { target } } }
    });
    if (data) setStatus(prev => ({ ...prev, correlations: data.correlations || [], attackChains: data.attack_chains || [] }));
  };

  const openPocModal = (finding: Finding) => { setSelectedFinding(finding); setPocModalOpen(true); };

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

  const dedicatedFindings = status.findings.filter(f => {
    const cat = categorizeFinding(f);
    if (dedFilterType === 'all') return cat !== 'other';
    return cat === dedFilterType;
  });

  const FindingCard = ({ finding, showPoc = true }: { finding: Finding; showPoc?: boolean }) => (
    <div className={`p-3 border rounded-lg bg-card/50 ${finding.verified === false ? 'border-yellow-500/30 opacity-80' : 'border-border'}`}>
      <div className="flex items-start justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <span className="font-medium text-sm truncate">{finding.title}</span>
        </div>
        <div className="flex items-center gap-1 flex-wrap">
          {finding.subdomain && <Badge variant="outline" className="text-xs border-blue-500/40 text-blue-400">🌐 {finding.subdomain}</Badge>}
          {finding.verified === true && <Badge variant="outline" className="text-xs border-green-500/40 text-green-400">✅ Verified</Badge>}
          {finding.verified === false && <Badge variant="outline" className="text-xs border-yellow-500/40 text-yellow-400">⚠️ Unverified</Badge>}
          {finding.exploitable && <Badge variant="destructive" className="text-xs">Exploitable</Badge>}
          <Badge className={`text-xs ${getSeverityColor(finding.severity)}`}>{finding.severity}</Badge>
        </div>
      </div>
      <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{finding.description}</p>
      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
        <span>Tool: {finding.tool_used}</span>
        {finding.confidence !== undefined && (
          <span className={finding.confidence >= 0.8 ? 'text-green-400' : 'text-yellow-400'}>
            Confidence: {Math.round(finding.confidence * 100)}%
          </span>
        )}
        {showPoc && finding.evidence?.raw?.poc && (
          <Button variant="outline" size="sm" className="text-xs h-5 px-2 ml-auto" onClick={() => openPocModal(finding)}>
            <Code2 className="h-3 w-3 mr-1" />View POC
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
            <p className="text-muted-foreground text-sm">OWASP Top 10 • AI Reasoning • Tech-Aware Payloads • Auto-Exploit</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {connectionStatus && (
            <Badge variant={connectionStatus.reachable ? "default" : "destructive"} className="gap-1">
              {connectionStatus.reachable ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
              {connectionStatus.reachable ? 'Connected' : 'Unreachable'}
            </Badge>
          )}
          <Badge variant={status.isRunning ? "default" : "secondary"} className="gap-1">
            <Activity className={`h-3 w-3 ${status.isRunning ? 'animate-pulse' : ''}`} />
            {status.phase}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Panel */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-9 w-full text-xs">
              <TabsTrigger value="control">Control</TabsTrigger>
              <TabsTrigger value="ai-chat"><MessageSquare className="h-3 w-3 mr-0.5" />AI Chat</TabsTrigger>
              <TabsTrigger value="findings">Findings{status.findings.length > 0 && <Badge className="ml-1 text-xs h-4 px-1">{status.findings.length}</Badge>}</TabsTrigger>
              <TabsTrigger value="tree"><TreePine className="h-3 w-3 mr-0.5" />Tree</TabsTrigger>
              <TabsTrigger value="surface"><Globe className="h-3 w-3 mr-0.5" />Surface</TabsTrigger>
              <TabsTrigger value="specialized"><Filter className="h-3 w-3 mr-0.5" />CORS/Trav</TabsTrigger>
              <TabsTrigger value="correlations">Correlations</TabsTrigger>
              <TabsTrigger value="chains">Chains</TabsTrigger>
              <TabsTrigger value="vuln-kb"><BookOpen className="h-3 w-3 mr-0.5" />KB</TabsTrigger>
            </TabsList>

            {/* === CONTROL TAB === */}
            <TabsContent value="control" className="space-y-4">
              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2"><Target className="h-5 w-5" />Operation Configuration</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Target</Label>
                      <div className="flex gap-2">
                        <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" disabled={status.isRunning} className="flex-1" />
                        <Button variant="outline" size="sm" onClick={checkConnection} disabled={checkingConnection || !target}>
                          {checkingConnection ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Wifi className="h-4 w-4" />}
                        </Button>
                      </div>
                      {connectionStatus && (
                        <div className={`text-xs ${connectionStatus.reachable ? 'text-green-400' : 'text-red-400'}`}>
                          {connectionStatus.recommendation}
                        </div>
                      )}
                    </div>
                    <div className="space-y-2">
                      <Label>Objective</Label>
                      <select value={objective} onChange={(e) => setObjective(e.target.value)} className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm" disabled={status.isRunning}>
                        <option value="comprehensive-assessment">Comprehensive (OWASP Top 10)</option>
                        <option value="vulnerability-discovery">Vulnerability Discovery</option>
                        <option value="exploitation-focus">Exploitation Focus</option>
                        <option value="stealth-recon">Stealth Reconnaissance</option>
                        <option value="api-security">API Security Testing</option>
                      </select>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="flex items-center space-x-2"><Switch checked={autoAdapt} onCheckedChange={setAutoAdapt} disabled={status.isRunning} /><Label>Auto-Adapt</Label></div>
                    <div className="flex items-center space-x-2"><Switch checked={stealthMode} onCheckedChange={setStealthMode} disabled={status.isRunning} /><Label>Stealth Mode</Label></div>
                  </div>

                  <div className="flex gap-2">
                    <Button onClick={startContinuousOperation} disabled={status.isRunning || !target} className="flex-1">
                      {status.isRunning ? <><RefreshCw className="mr-2 h-4 w-4 animate-spin" />Running...</> : <><Play className="mr-2 h-4 w-4" />Start Operation</>}
                    </Button>
                  </div>

                  {status.isRunning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm"><span>Phase: {status.phase}</span><span>{status.progress}%</span></div>
                      <Progress value={status.progress} />
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Live Output */}
              <Card>
                <CardHeader className="py-3"><CardTitle className="text-sm flex items-center gap-2"><Activity className="h-4 w-4" />Real-Time Scan Output</CardTitle></CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-64">
                    <div ref={outputRef} className="p-4 font-mono text-xs space-y-1 bg-black/50 rounded-b-lg">
                      {liveOutput.length === 0 ? (
                        <div className="text-muted-foreground">Awaiting operation start...</div>
                      ) : liveOutput.map((line, i) => (
                        <div key={i} className={
                          line.includes('✅') || line.includes('[VULNERABLE]') ? 'text-green-400' :
                          line.includes('⚠️') || line.includes('[POSSIBLE]') ? 'text-yellow-400' :
                          line.includes('❌') ? 'text-red-400' :
                          line.includes('━━━') ? 'text-primary font-bold' :
                          line.includes('🎯') ? 'text-cyan-400' :
                          line.includes('🧑') ? 'text-blue-400 font-semibold' :
                          'text-muted-foreground'
                        }>{line}</div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            {/* === AI CHAT TAB === */}
            <TabsContent value="ai-chat" className="space-y-0">
              <Card className="h-[600px] flex flex-col">
                <CardHeader className="py-3 border-b border-border shrink-0">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Brain className="h-4 w-4 text-primary" />AI Reasoning — Live Thought Process
                  </CardTitle>
                  <CardDescription className="text-xs">AI shares its thinking in real-time. You can correct it to avoid false positives.</CardDescription>
                </CardHeader>
                <CardContent className="flex-1 p-0 flex flex-col overflow-hidden">
                  <ScrollArea className="flex-1">
                    <div ref={chatRef} className="p-4 space-y-3">
                      {aiThoughts.length === 0 ? (
                        <div className="text-center py-12 text-muted-foreground">
                          <Brain className="h-12 w-12 mx-auto mb-2 opacity-30" />
                          <p>AI reasoning will appear here once a scan starts.</p>
                          <p className="text-xs mt-1">You can type corrections to guide the AI.</p>
                        </div>
                      ) : aiThoughts.map((t, i) => (
                        <div key={i} className={`flex gap-3 ${t.isHuman ? 'justify-end' : ''}`}>
                          {!t.isHuman && (
                            <div className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                              <Brain className="h-4 w-4 text-primary" />
                            </div>
                          )}
                          <div className={`max-w-[80%] rounded-lg p-3 ${t.isHuman ? 'bg-blue-500/20 border border-blue-500/30' : 'bg-muted/30 border border-border'}`}>
                            <p className="text-sm">{t.thought}</p>
                            {t.actions && t.actions.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {t.actions.map((a, j) => <Badge key={j} variant="outline" className="text-xs">{a}</Badge>)}
                              </div>
                            )}
                            {t.owasp_coverage && t.owasp_coverage.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {t.owasp_coverage.map((o, j) => <Badge key={j} variant="secondary" className="text-xs">{o}</Badge>)}
                              </div>
                            )}
                            <div className="text-xs text-muted-foreground mt-1">{t.timestamp}</div>
                          </div>
                          {t.isHuman && (
                            <div className="w-7 h-7 rounded-full bg-blue-500/20 flex items-center justify-center shrink-0">
                              <span className="text-xs">🧑</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                  <div className="border-t border-border p-3 shrink-0">
                    <div className="flex gap-2">
                      <Textarea
                        value={humanInput}
                        onChange={(e) => setHumanInput(e.target.value)}
                        placeholder="Correct AI reasoning, e.g. 'Skip WordPress scans, this is a Node.js app' or 'Focus on API endpoints'"
                        className="flex-1 min-h-[40px] max-h-[80px] text-sm resize-none"
                        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendHumanCorrection(); } }}
                      />
                      <Button onClick={sendHumanCorrection} disabled={!humanInput.trim()} size="sm">
                        <Send className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* === FINDINGS TAB === */}
            <TabsContent value="findings">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5" />All Findings ({status.findings.length})</CardTitle>
                  <CardDescription>{status.findings.filter(f => f.verified).length} verified ✅ | {status.findings.filter(f => f.subdomain).length} from subdomains 🌐</CardDescription>
                </CardHeader>
                <CardContent>
                  {status.findings.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No findings yet.</div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-3">
                        {status.findings.map((f) => <FindingCard key={f.id} finding={f} />)}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === TARGET TREE TAB === */}
            <TabsContent value="tree">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2"><TreePine className="h-5 w-5" />Target Tree Visualization</CardTitle>
                      <CardDescription>Hierarchical view: Domain → Subdomains → Endpoints → Tech → Ports → Vulnerabilities</CardDescription>
                    </div>
                    <Button variant="outline" size="sm" onClick={buildTree} disabled={status.findings.length === 0}>
                      <RefreshCw className="h-4 w-4 mr-1" />Rebuild
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {!targetTree ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <TreePine className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      <p>Run a scan to generate the target tree visualization.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="font-mono text-sm">
                        <TreeNodeComponent node={targetTree} />
                      </div>
                      {targetTree.children?.find(c => c.name === 'Vulnerabilities')?.summary && (
                        <div className="mt-4 p-3 rounded-lg bg-muted/20 border border-border">
                          <div className="grid grid-cols-6 gap-2 text-center text-xs">
                            {Object.entries(targetTree.children!.find(c => c.name === 'Vulnerabilities')!.summary!).filter(([k]) => k !== 'total').map(([sev, count]) => (
                              <div key={sev}>
                                <div className={`text-lg font-bold ${sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-yellow-400' : sev === 'verified' ? 'text-green-400' : 'text-blue-400'}`}>{count as number}</div>
                                <div className="capitalize">{sev}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === SURFACE TAB === */}
            <TabsContent value="surface">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><Globe className="h-5 w-5" />Subdomain Attack Surface Map</CardTitle>
                </CardHeader>
                <CardContent>
                  {subdomainMap.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground"><Globe className="h-12 w-12 mx-auto mb-2 opacity-30" /><p>No subdomains mapped yet.</p></div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-2">
                        {subdomainMap.map(entry => (
                          <div key={entry.domain} className="grid grid-cols-4 gap-2 items-center px-3 py-3 rounded-lg border border-border hover:bg-muted/30">
                            <div className="font-mono text-sm">{entry.domain}</div>
                            <Badge variant="outline" className="text-xs border-green-500/40 text-green-400 w-fit"><CheckCircle2 className="h-3 w-3 mr-1" />Live</Badge>
                            <Badge variant="outline" className={`text-xs ${getRiskBadgeColor(entry.riskScore)} w-fit`}>{entry.riskScore.toUpperCase()}</Badge>
                            <span className="font-bold text-sm">{entry.findings.length} findings</span>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === CORS/TRAV/COOKIE TAB === */}
            <TabsContent value="specialized">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <CardTitle className="flex items-center gap-2"><Filter className="h-5 w-5" />CORS / Traversal / Cookie</CardTitle>
                    <div className="flex gap-1">
                      {(['all', 'cors', 'traversal', 'cookie'] as const).map(f => (
                        <Button key={f} variant={dedFilterType === f ? 'default' : 'outline'} size="sm" className="text-xs h-7" onClick={() => setDedFilterType(f)}>
                          {f === 'all' ? 'All' : f === 'cors' ? '🌐 CORS' : f === 'traversal' ? '📂 Traversal' : '🍪 Cookie'}
                        </Button>
                      ))}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {dedicatedFindings.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground"><Filter className="h-12 w-12 mx-auto mb-2 opacity-30" /><p>No findings yet.</p></div>
                  ) : (
                    <ScrollArea className="h-[480px]">
                      <div className="space-y-3">
                        {dedicatedFindings.map(f => (
                          <div key={f.id} className="p-3 border border-border rounded-lg bg-card/50 hover:bg-card/80 cursor-pointer" onClick={() => openPocModal(f)}>
                            <div className="flex items-start justify-between gap-2">
                              <span className="font-medium text-sm truncate">{f.title}</span>
                              <div className="flex items-center gap-1">
                                {f.verified === true && <Badge variant="outline" className="text-xs border-green-500/40 text-green-400">✅</Badge>}
                                <Badge className={`text-xs ${getSeverityColor(f.severity)}`}>{f.severity}</Badge>
                              </div>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{f.description}</p>
                          </div>
                        ))}
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
                    <CardTitle className="flex items-center gap-2"><GitBranch className="h-5 w-5" />Finding Correlations</CardTitle>
                    <Button onClick={correlateFindings} disabled={status.findings.length < 2} size="sm"><RefreshCw className="mr-1 h-4 w-4" />Re-correlate</Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {status.correlations.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No correlations yet.</div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-3">
                        {status.correlations.map(c => (
                          <div key={c.id} className="p-4 border rounded-lg bg-gradient-to-r from-primary/5 to-transparent">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-semibold">{c.attack_path}</span>
                              <Badge variant="outline">{Math.round(c.exploitation_probability * 100)}%</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{c.description}</p>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === CHAINS TAB === */}
            <TabsContent value="chains">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><Crosshair className="h-5 w-5" />Attack Chains</CardTitle>
                </CardHeader>
                <CardContent>
                  {status.attackChains.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No attack chains yet.</div>
                  ) : (
                    <ScrollArea className="h-80">
                      <div className="space-y-3">
                        {status.attackChains.map(chain => (
                          <div key={chain.id} className="p-4 border rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-semibold">{chain.name}</span>
                              <Badge className={chain.impact === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}>{chain.impact}</Badge>
                            </div>
                            <div className="space-y-1">
                              {chain.steps.map((step: any, idx: number) => (
                                <div key={idx} className="flex items-center gap-2 text-sm">
                                  <div className="w-5 h-5 rounded-full bg-primary/20 flex items-center justify-center text-xs">{step.order}</div>
                                  <span className="text-muted-foreground">{step.action}</span>
                                </div>
                              ))}
                            </div>
                            <div className="flex flex-wrap gap-1 mt-2">
                              {chain.mitre_mapping.slice(0, 4).map((t: string, j: number) => <Badge key={j} variant="secondary" className="text-xs">{t}</Badge>)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === VULN KB TAB === */}
            <TabsContent value="vuln-kb">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2"><BookOpen className="h-5 w-5" />Vulnerability Knowledge Base</CardTitle>
                      <CardDescription>Latest CVEs and attack techniques — auto-updated daily via AI</CardDescription>
                    </div>
                    <Button variant="outline" size="sm" onClick={updateKB} disabled={kbUpdating}>
                      {kbUpdating ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
                      Update Now
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {vulnKB.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <BookOpen className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      <p>Click "Update Now" to fetch the latest vulnerability intelligence.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-2">
                        {vulnKB.map((entry: any, i: number) => (
                          <div key={i} className="p-3 border border-border rounded-lg bg-card/50">
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs font-mono">{entry.cve || 'N/A'}</Badge>
                                  <span className="font-medium text-sm truncate">{entry.name}</span>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">Affected: {entry.affected}</p>
                              </div>
                              <Badge className={`text-xs ${getSeverityColor(entry.severity)}`}>{entry.severity}</Badge>
                            </div>
                            <div className="mt-2 text-xs text-muted-foreground">
                              <strong>Test: </strong>{entry.test_method}
                            </div>
                            {entry.payload && (
                              <pre className="mt-1 p-2 bg-black/40 rounded text-xs font-mono text-green-300 overflow-x-auto">{entry.payload}</pre>
                            )}
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
            <CardHeader className="py-3"><CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="h-4 w-4" />Stats</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {[
                { label: 'Total Findings', value: status.findings.length, color: '' },
                { label: 'Critical', value: status.findings.filter(f => f.severity === 'critical').length, color: 'text-red-400' },
                { label: 'High', value: status.findings.filter(f => f.severity === 'high').length, color: 'text-orange-400' },
                { label: '✅ Verified', value: status.findings.filter(f => f.verified).length, color: 'text-green-400' },
                { label: '🌐 Subdomains', value: subdomainMap.length, color: 'text-blue-400' },
                { label: 'Correlations', value: status.correlations.length, color: '' },
                { label: 'Attack Chains', value: status.attackChains.length, color: '' },
                { label: 'Technologies', value: detectedTech.length, color: 'text-cyan-400' },
                { label: 'Open Ports', value: detectedPorts.length, color: 'text-purple-400' },
              ].map(s => (
                <div key={s.label} className="flex justify-between">
                  <span className="text-muted-foreground text-sm">{s.label}</span>
                  <span className={`font-mono ${s.color}`}>{s.value}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm flex items-center gap-2"><Shield className="h-4 w-4" />Severity</CardTitle></CardHeader>
            <CardContent>
              {status.findings.length === 0 ? (
                <div className="text-xs text-muted-foreground text-center py-4">No data</div>
              ) : (
                <div className="space-y-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                    const count = status.findings.filter(f => f.severity === sev).length;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs"><span className="capitalize">{sev}</span><span>{count}</span></div>
                        <Progress value={(count / status.findings.length) * 100} className="h-1" />
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {detectedTech.length > 0 && (
            <Card>
              <CardHeader className="py-3"><CardTitle className="text-sm">⚙️ Detected Tech</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {detectedTech.map(t => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                </div>
              </CardContent>
            </Card>
          )}

          {detectedPorts.length > 0 && (
            <Card>
              <CardHeader className="py-3"><CardTitle className="text-sm">🔌 Open Ports</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {detectedPorts.map(p => <Badge key={p} variant="secondary" className="text-xs font-mono">{p}</Badge>)}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* POC Detail Modal */}
      <Dialog open={pocModalOpen} onOpenChange={setPocModalOpen}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Code2 className="h-5 w-5 text-primary" />{selectedFinding?.title}</DialogTitle>
            <DialogDescription className="flex items-center gap-2 flex-wrap mt-1">
              {selectedFinding && (
                <>
                  <Badge className={getSeverityColor(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
                  {selectedFinding.verified === true && <Badge variant="outline" className="border-green-500/40 text-green-400">✅ Dual-Verified</Badge>}
                  {selectedFinding.verified === false && <Badge variant="outline" className="border-yellow-500/40 text-yellow-400">⚠️ Unverified</Badge>}
                  {selectedFinding.confidence !== undefined && <Badge variant="outline">Confidence: {Math.round(selectedFinding.confidence * 100)}%</Badge>}
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          {selectedFinding && (
            <div className="space-y-4 mt-2">
              <div><h4 className="text-sm font-semibold mb-1">Description</h4><p className="text-sm text-muted-foreground">{selectedFinding.description}</p></div>
              {selectedFinding.evidence?.raw?.poc && (
                <div>
                  <h4 className="text-sm font-semibold mb-1 flex items-center gap-1"><Code2 className="h-4 w-4 text-primary" />Proof of Concept</h4>
                  <pre className="p-3 bg-black/60 rounded-lg text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap border border-green-500/20 max-h-48">{selectedFinding.evidence.raw.poc}</pre>
                </div>
              )}
              {selectedFinding.evidence?.raw?.remediation && (
                <div>
                  <h4 className="text-sm font-semibold mb-1 flex items-center gap-1"><Shield className="h-4 w-4 text-blue-400" />Remediation</h4>
                  <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg text-sm text-muted-foreground whitespace-pre-wrap">{selectedFinding.evidence.raw.remediation}</div>
                </div>
              )}
              <div>
                <h4 className="text-sm font-semibold mb-1">Evidence</h4>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {[
                    { label: 'Tool', value: selectedFinding.tool_used },
                    { label: 'Phase', value: selectedFinding.phase },
                    { label: 'Time', value: new Date(selectedFinding.timestamp).toLocaleString() },
                    { label: 'Exploitable', value: selectedFinding.exploitable ? 'Yes ⚠️' : 'No' },
                    { label: 'Verified', value: selectedFinding.verified ? 'Dual-verified' : 'Single' },
                    { label: 'Target', value: selectedFinding.evidence?.target || selectedFinding.subdomain || target },
                  ].map(item => (
                    <div key={item.label} className="p-2 bg-muted/30 rounded">
                      <span className="text-muted-foreground">{item.label}: </span><span className="font-medium">{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>
              {selectedFinding.verified === false && (
                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400 mt-0.5 shrink-0" />
                  <div className="text-sm text-yellow-300"><strong>Possible False Positive:</strong> Not confirmed by secondary technique. Confidence: {Math.round((selectedFinding.confidence || 0.45) * 100)}%.</div>
                </div>
              )}
              {selectedFinding.verified === true && (
                <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg flex gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                  <div className="text-sm text-green-300"><strong>Dual-Verified:</strong> Confirmed by two techniques. Confidence: {Math.round((selectedFinding.confidence || 0.9) * 100)}%.</div>
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
