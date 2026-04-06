import { useState, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Target, Shield, Search, Zap, Bug, FileText, CheckCircle,
  AlertTriangle, XCircle, Loader2, Play, Clock, Globe, Code
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Finding {
  phase: string;
  type: string;
  severity: string;
  title: string;
  details: string;
  owasp?: string;
  endpoint?: string;
  payload?: string;
  remediation?: string;
  confidence?: string;
  verified?: boolean;
  cvss?: number;
}

interface PoC {
  findingId: string;
  severity: string;
  script: string;
  language: string;
}

interface WorkflowResult {
  target: string;
  startedAt: string;
  completedAt?: string;
  summary?: {
    totalFindings: number;
    verifiedFindings: number;
    eliminatedFP: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    pocCount: number;
    techStack: string[];
    cloudProvider: string;
  };
  findings?: Finding[];
  phases?: {
    recon?: { techStack: string[]; endpoints: string[]; cloudProvider: string; findings: Finding[] };
    fuzzing?: { findings: Finding[] };
    cveCorrelation?: { findings: Finding[] };
    owaspDeepDive?: { findings: Finding[] };
    pocGeneration?: { pocs: PoC[] };
    fpElimination?: { verified: number; eliminated: number };
    remediation?: { remediations: any[] };
  };
}

const PHASES = [
  { id: "recon", label: "Recon & Surface Mapping", icon: Search, color: "text-blue-400" },
  { id: "fuzzing", label: "Differential Fuzzing", icon: Zap, color: "text-yellow-400" },
  { id: "cve", label: "CVE Correlation", icon: Bug, color: "text-orange-400" },
  { id: "owasp", label: "OWASP Deep Dive", icon: Shield, color: "text-red-400" },
  { id: "poc", label: "PoC Generation", icon: Code, color: "text-purple-400" },
  { id: "fp", label: "FP Elimination", icon: XCircle, color: "text-green-400" },
  { id: "remediation", label: "Remediation", icon: CheckCircle, color: "text-emerald-400" },
];

const severityColor = (s: string) => {
  switch (s) {
    case "critical": return "bg-red-600 text-white";
    case "high": return "bg-orange-500 text-white";
    case "medium": return "bg-yellow-500 text-black";
    case "low": return "bg-blue-500 text-white";
    default: return "bg-muted text-muted-foreground";
  }
};

const VAPTWorkflow = () => {
  const [target, setTarget] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [currentPhase, setCurrentPhase] = useState(-1);
  const [result, setResult] = useState<WorkflowResult | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();

  const runWorkflow = useCallback(async () => {
    if (!target.trim()) {
      toast({ title: "Target Required", description: "Enter a target domain or URL.", variant: "destructive" });
      return;
    }

    setIsRunning(true);
    setCurrentPhase(0);
    setResult(null);

    try {
      // Simulate phase progression for UX
      const phaseInterval = setInterval(() => {
        setCurrentPhase(prev => Math.min(prev + 1, 6));
      }, 8000);

      const { data, error } = await supabase.functions.invoke("vapt-workflow-engine", {
        body: { action: "full-workflow", target: target.trim() },
      });

      clearInterval(phaseInterval);

      if (error) throw error;

      setResult(data);
      setCurrentPhase(7);

      toast({
        title: "Workflow Complete",
        description: `Found ${data.summary?.verifiedFindings || 0} verified findings (${data.summary?.eliminatedFP || 0} false positives eliminated).`,
      });

      // Store findings in scan_reports
      if (data.findings?.length > 0) {
        const { data: userData } = await supabase.auth.getUser();
        if (userData.user) {
          for (const finding of data.findings.slice(0, 20)) {
            await supabase.from("scan_reports").insert({
              user_id: userData.user.id,
              target: target.trim(),
              scan_type: "vapt-workflow",
              vulnerability_name: finding.title,
              severity: finding.severity,
              scan_output: finding.details,
              proof_of_concept: finding.payload || null,
            });
          }
        }
      }
    } catch (err: any) {
      console.error("Workflow error:", err);
      toast({ title: "Workflow Error", description: err.message || "Failed to run workflow", variant: "destructive" });
    } finally {
      setIsRunning(false);
    }
  }, [target, toast]);

  const progress = isRunning ? Math.min(((currentPhase + 1) / 7) * 100, 95) : result ? 100 : 0;

  return (
    <div className="space-y-6">
      {/* Header & Target Input */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-6 w-6 text-primary" />
            VAPT Workflow Engine — Principal Analyst Mode
          </CardTitle>
          <CardDescription>
            7-Phase PTES workflow: Recon → Differential Fuzzing → CVE Correlation → OWASP Deep Dive → PoC → FP Elimination → Remediation
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Input
              placeholder="e.g., example.com or https://target-app.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isRunning}
              className="flex-1"
            />
            <Button onClick={runWorkflow} disabled={isRunning || !target.trim()} className="min-w-[160px]">
              {isRunning ? <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Running...</> : <><Play className="h-4 w-4 mr-2" /> Launch Workflow</>}
            </Button>
          </div>

          {/* Phase Progress */}
          {(isRunning || result) && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Workflow Progress</span>
                <span className="font-mono">{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
              <div className="grid grid-cols-7 gap-1">
                {PHASES.map((phase, i) => {
                  const Icon = phase.icon;
                  const status = i < currentPhase ? "done" : i === currentPhase && isRunning ? "running" : "pending";
                  return (
                    <div key={phase.id} className={`flex flex-col items-center gap-1 p-2 rounded text-xs ${status === "done" ? "bg-green-500/10" : status === "running" ? "bg-yellow-500/10 animate-pulse" : "bg-muted/30"}`}>
                      <Icon className={`h-4 w-4 ${status === "done" ? "text-green-400" : status === "running" ? "text-yellow-400" : "text-muted-foreground"}`} />
                      <span className="text-center leading-tight">{phase.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Card className="border-red-500/30">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold text-red-400">{result.summary?.critical || 0}</div>
                <div className="text-xs text-muted-foreground">Critical</div>
              </CardContent>
            </Card>
            <Card className="border-orange-500/30">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">{result.summary?.high || 0}</div>
                <div className="text-xs text-muted-foreground">High</div>
              </CardContent>
            </Card>
            <Card className="border-yellow-500/30">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold text-yellow-400">{result.summary?.medium || 0}</div>
                <div className="text-xs text-muted-foreground">Medium</div>
              </CardContent>
            </Card>
            <Card className="border-blue-500/30">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold text-blue-400">{result.summary?.low || 0}</div>
                <div className="text-xs text-muted-foreground">Low</div>
              </CardContent>
            </Card>
            <Card className="border-green-500/30">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold text-green-400">{result.summary?.eliminatedFP || 0}</div>
                <div className="text-xs text-muted-foreground">FP Eliminated</div>
              </CardContent>
            </Card>
          </div>

          {/* Detail Tabs */}
          <Card>
            <CardContent className="p-0">
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
                  <TabsTrigger value="overview" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary">Overview</TabsTrigger>
                  <TabsTrigger value="findings" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary">
                    Findings ({result.findings?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="recon" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary">Recon</TabsTrigger>
                  <TabsTrigger value="pocs" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary">
                    PoCs ({result.phases?.pocGeneration?.pocs?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="remediation" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary">Remediation</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="p-4 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <h3 className="font-semibold flex items-center gap-2"><Globe className="h-4 w-4" /> Target Info</h3>
                      <div className="bg-muted p-3 rounded-lg text-sm space-y-1">
                        <p><span className="text-muted-foreground">Target:</span> {result.target}</p>
                        <p><span className="text-muted-foreground">Cloud:</span> {result.summary?.cloudProvider || "Unknown"}</p>
                        <p><span className="text-muted-foreground">Started:</span> {new Date(result.startedAt).toLocaleString()}</p>
                        {result.completedAt && <p><span className="text-muted-foreground">Completed:</span> {new Date(result.completedAt).toLocaleString()}</p>}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <h3 className="font-semibold flex items-center gap-2"><Shield className="h-4 w-4" /> Tech Stack</h3>
                      <div className="flex flex-wrap gap-2">
                        {result.summary?.techStack?.map((tech, i) => (
                          <Badge key={i} variant="outline">{tech}</Badge>
                        ))}
                        {(!result.summary?.techStack || result.summary.techStack.length === 0) && (
                          <span className="text-sm text-muted-foreground">No technologies detected</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h3 className="font-semibold">Discovered Endpoints</h3>
                    <div className="flex flex-wrap gap-2">
                      {result.phases?.recon?.endpoints?.map((ep, i) => (
                        <Badge key={i} variant="secondary" className="font-mono text-xs">{ep}</Badge>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="findings" className="p-0">
                  <ScrollArea className="h-[500px]">
                    <div className="divide-y divide-border">
                      {result.findings?.sort((a, b) => {
                        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                        return (order[a.severity as keyof typeof order] ?? 4) - (order[b.severity as keyof typeof order] ?? 4);
                      }).map((finding, i) => (
                        <div key={i} className="p-4 space-y-2">
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-center gap-2">
                              <Badge className={severityColor(finding.severity)}>{finding.severity.toUpperCase()}</Badge>
                              <span className="font-medium text-sm">{finding.title}</span>
                            </div>
                            {finding.confidence && <Badge variant="outline" className="text-xs">{finding.confidence} confidence</Badge>}
                          </div>
                          <p className="text-sm text-muted-foreground">{finding.details}</p>
                          <div className="flex flex-wrap gap-2 text-xs">
                            {finding.owasp && <Badge variant="outline">{finding.owasp}</Badge>}
                            {finding.endpoint && <Badge variant="outline" className="font-mono">{finding.endpoint}</Badge>}
                            <Badge variant="outline">{finding.phase}</Badge>
                          </div>
                          {finding.remediation && (
                            <div className="bg-green-500/10 p-2 rounded text-xs text-green-300">
                              <strong>Fix:</strong> {finding.remediation}
                            </div>
                          )}
                        </div>
                      ))}
                      {(!result.findings || result.findings.length === 0) && (
                        <div className="p-8 text-center text-muted-foreground">No findings detected</div>
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="recon" className="p-4 space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Phase 1: Reconnaissance Results</h3>
                    {result.phases?.recon?.findings?.map((f, i) => (
                      <div key={i} className="bg-muted p-3 rounded-lg text-sm">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={severityColor(f.severity)}>{f.severity}</Badge>
                          <span className="font-medium">{f.title}</span>
                        </div>
                        <p className="text-muted-foreground">{f.details}</p>
                      </div>
                    ))}
                    <h3 className="font-semibold mt-4">Phase 2: Differential Fuzzing Results</h3>
                    {result.phases?.fuzzing?.findings?.map((f, i) => (
                      <div key={i} className="bg-muted p-3 rounded-lg text-sm">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={severityColor(f.severity)}>{f.severity}</Badge>
                          <span className="font-medium">{f.title}</span>
                        </div>
                        <p className="text-muted-foreground">{f.details}</p>
                        {f.payload && <code className="text-xs bg-background p-1 rounded mt-1 block">Payload: {f.payload}</code>}
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="pocs" className="p-4 space-y-4">
                  {result.phases?.pocGeneration?.pocs?.map((poc, i) => (
                    <div key={i} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Badge className={severityColor(poc.severity)}>{poc.severity}</Badge>
                        <span className="font-medium text-sm">{poc.findingId}</span>
                        <Badge variant="outline">{poc.language}</Badge>
                      </div>
                      <pre className="bg-muted p-3 rounded-lg text-xs overflow-auto max-h-64 font-mono">
                        {poc.script}
                      </pre>
                    </div>
                  ))}
                  {(!result.phases?.pocGeneration?.pocs || result.phases.pocGeneration.pocs.length === 0) && (
                    <div className="text-center text-muted-foreground p-8">No PoCs generated (no critical/high findings)</div>
                  )}
                </TabsContent>

                <TabsContent value="remediation" className="p-4 space-y-4">
                  {result.phases?.remediation?.remediations?.map((rem: any, i: number) => (
                    <div key={i} className="bg-muted p-4 rounded-lg space-y-2">
                      <div className="flex items-center gap-2">
                        <Badge variant={rem.priority === "P1" ? "destructive" : "outline"}>{rem.priority}</Badge>
                        <span className="font-medium text-sm">{rem.finding}</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        <div className="bg-yellow-500/10 p-2 rounded">
                          <strong className="text-yellow-400">Short-term:</strong>
                          <p className="text-muted-foreground mt-1">{rem.shortTermFix}</p>
                        </div>
                        <div className="bg-green-500/10 p-2 rounded">
                          <strong className="text-green-400">Root-cause:</strong>
                          <p className="text-muted-foreground mt-1">{rem.rootCauseFix}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                  {(!result.phases?.remediation?.remediations || result.phases.remediation.remediations.length === 0) && (
                    <div className="text-center text-muted-foreground p-8">No remediation strategies generated</div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};

export default VAPTWorkflow;
