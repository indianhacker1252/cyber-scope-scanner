import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "@/hooks/use-toast";
import { 
  Shield, Play, FileText, Terminal, AlertTriangle, CheckCircle, 
  XCircle, Clock, Code, Download, Loader2, RefreshCw, Eye
} from "lucide-react";

interface Finding {
  title: string;
  severity: string;
  target: string;
  vulnerabilityType: string;
}

interface EvidenceRecord {
  id: string;
  finding_title: string;
  finding_severity: string;
  target: string;
  vulnerability_type: string | null;
  poc_script: string | null;
  script_language: string | null;
  execution_output: string | null;
  execution_status: string | null;
  remediation_report: string | null;
  cvss_score: number | null;
  created_at: string;
  validated_at: string | null;
}

const ValidationWorkspace = () => {
  const [finding, setFinding] = useState<Finding>({ title: "", severity: "medium", target: "", vulnerabilityType: "" });
  const [scriptLanguage, setScriptLanguage] = useState("python");
  const [generatedScript, setGeneratedScript] = useState("");
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isReporting, setIsReporting] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [activeTab, setActiveTab] = useState("editor");
  const [currentEvidenceId, setCurrentEvidenceId] = useState<string | null>(null);
  const [report, setReport] = useState("");
  const [evidenceHistory, setEvidenceHistory] = useState<EvidenceRecord[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null);
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => { loadHistory(); }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalOutput]);

  const loadHistory = async () => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data } = await supabase
      .from("validation_evidence")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(50);
    if (data) setEvidenceHistory(data as EvidenceRecord[]);
  };

  const appendTerminal = (line: string) => {
    setTerminalOutput(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${line}`]);
  };

  const generatePoC = async () => {
    if (!finding.title || !finding.target) {
      toast({ title: "Error", description: "Please provide finding title and target", variant: "destructive" });
      return;
    }

    setIsGenerating(true);
    setTerminalOutput([]);
    appendTerminal("🔧 Generating PoC validation script...");

    try {
      const { data, error } = await supabase.functions.invoke("validation-scaffolder", {
        body: {
          finding: finding.title,
          target: finding.target,
          vulnerabilityType: finding.vulnerabilityType,
          severity: finding.severity,
          language: scriptLanguage,
        },
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      setGeneratedScript(data.script);
      appendTerminal("✅ PoC script generated successfully");
      appendTerminal(`📝 Language: ${scriptLanguage}`);

      // Save to DB
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        const { data: record } = await supabase.from("validation_evidence").insert({
          user_id: user.id,
          finding_title: finding.title,
          finding_severity: finding.severity,
          target: finding.target,
          vulnerability_type: finding.vulnerabilityType,
          poc_script: data.script,
          script_language: scriptLanguage,
          execution_status: "script_generated",
        }).select().single();
        if (record) setCurrentEvidenceId(record.id);
      }

      setShowModal(true);
      setActiveTab("editor");
      toast({ title: "PoC Generated", description: "Review and edit the script before execution" });
    } catch (err: any) {
      appendTerminal(`❌ Error: ${err.message}`);
      toast({ title: "Generation Failed", description: err.message, variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  };

  const executeValidation = async () => {
    if (!generatedScript) return;

    setIsExecuting(true);
    setActiveTab("terminal");
    appendTerminal("🚀 Starting sandboxed validation execution...");
    appendTerminal("⏱️ Timeout: 20 seconds | Sandbox: RESTRICTED");
    appendTerminal("─".repeat(60));

    try {
      const { data, error } = await supabase.functions.invoke("safe-execution-engine", {
        body: {
          script: generatedScript,
          language: scriptLanguage,
          target: finding.target,
          evidenceId: currentEvidenceId,
        },
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      const outputLines = (data.output || "").split("\n");
      for (const line of outputLines) {
        appendTerminal(line);
      }
      appendTerminal("─".repeat(60));
      appendTerminal(`⏱️ Execution time: ${data.executionTime}ms`);
      appendTerminal(`📊 Status: ${data.status?.toUpperCase()}`);

      toast({ title: "Validation Complete", description: `Status: ${data.status}` });
      loadHistory();
    } catch (err: any) {
      appendTerminal(`❌ Execution error: ${err.message}`);
      toast({ title: "Execution Failed", description: err.message, variant: "destructive" });
    } finally {
      setIsExecuting(false);
    }
  };

  const generateReport = async () => {
    if (!currentEvidenceId) {
      toast({ title: "Error", description: "No evidence to report on", variant: "destructive" });
      return;
    }

    setIsReporting(true);
    setActiveTab("report");
    appendTerminal("📄 Generating remediation report...");

    try {
      const { data, error } = await supabase.functions.invoke("audit-report-generator", {
        body: { evidenceId: currentEvidenceId },
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      setReport(data.report);
      appendTerminal(`✅ Report generated | CVSS: ${data.cvssScore || "N/A"}`);
      toast({ title: "Report Generated", description: `CVSS Score: ${data.cvssScore || "Pending"}` });
      loadHistory();
    } catch (err: any) {
      appendTerminal(`❌ Report error: ${err.message}`);
      toast({ title: "Report Failed", description: err.message, variant: "destructive" });
    } finally {
      setIsReporting(false);
    }
  };

  const viewEvidence = (ev: EvidenceRecord) => {
    setSelectedEvidence(ev);
    setFinding({ title: ev.finding_title, severity: ev.finding_severity, target: ev.target, vulnerabilityType: ev.vulnerability_type || "" });
    setGeneratedScript(ev.poc_script || "");
    setCurrentEvidenceId(ev.id);
    setReport(ev.remediation_report || "");
    setTerminalOutput(ev.execution_output ? ev.execution_output.split("\n").map(l => l) : []);
    setShowModal(true);
    setActiveTab(ev.remediation_report ? "report" : ev.execution_output ? "terminal" : "editor");
  };

  const severityColor = (s: string) => {
    switch (s) {
      case "critical": return "bg-red-500/20 text-red-400 border-red-500/30";
      case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "low": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const statusIcon = (s: string | null) => {
    switch (s) {
      case "completed": return <CheckCircle className="h-4 w-4 text-green-400" />;
      case "failed": case "timeout": return <XCircle className="h-4 w-4 text-red-400" />;
      case "script_generated": return <Code className="h-4 w-4 text-blue-400" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" /> Security Validation Workspace
          </h2>
          <p className="text-muted-foreground mt-1">Verify flagged findings with AI-generated PoC scripts and sandboxed execution</p>
        </div>
        <Button variant="outline" size="sm" onClick={loadHistory}><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
      </div>

      {/* Finding Input */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg">New Validation Request</CardTitle>
          <CardDescription>Enter the flagged finding details to generate a PoC validation script</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Finding Title</label>
              <Input placeholder="e.g., Reflected XSS in search parameter" value={finding.title}
                onChange={(e) => setFinding(p => ({ ...p, title: e.target.value }))} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Target URL</label>
              <Input placeholder="https://target.com/endpoint" value={finding.target}
                onChange={(e) => setFinding(p => ({ ...p, target: e.target.value }))} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Vulnerability Type</label>
              <Input placeholder="e.g., XSS, SQLi, SSRF, IDOR" value={finding.vulnerabilityType}
                onChange={(e) => setFinding(p => ({ ...p, vulnerabilityType: e.target.value }))} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">Severity</label>
                <Select value={finding.severity} onValueChange={(v) => setFinding(p => ({ ...p, severity: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">Script Language</label>
                <Select value={scriptLanguage} onValueChange={setScriptLanguage}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="nodejs">Node.js</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          <Button onClick={generatePoC} disabled={isGenerating} className="w-full">
            {isGenerating ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating PoC...</> : <><Code className="h-4 w-4 mr-2" /> Generate PoC Validation Script</>}
          </Button>
        </CardContent>
      </Card>

      {/* Evidence History */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2"><FileText className="h-5 w-5" /> Validation Evidence Log</CardTitle>
          <CardDescription>{evidenceHistory.length} validation records</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2">
              {evidenceHistory.length === 0 && (
                <p className="text-muted-foreground text-center py-8">No validation records yet. Generate your first PoC above.</p>
              )}
              {evidenceHistory.map((ev) => (
                <div key={ev.id} className="flex items-center justify-between p-3 rounded-lg border border-border hover:border-primary/30 transition-colors cursor-pointer" onClick={() => viewEvidence(ev)}>
                  <div className="flex items-center gap-3">
                    {statusIcon(ev.execution_status)}
                    <div>
                      <p className="font-medium text-sm text-foreground">{ev.finding_title}</p>
                      <p className="text-xs text-muted-foreground">{ev.target} · {new Date(ev.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={severityColor(ev.finding_severity)}>{ev.finding_severity}</Badge>
                    {ev.cvss_score && <Badge variant="outline">CVSS {ev.cvss_score}</Badge>}
                    <Button variant="ghost" size="icon"><Eye className="h-4 w-4" /></Button>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Validation Modal */}
      <Dialog open={showModal} onOpenChange={setShowModal}>
        <DialogContent className="max-w-5xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" /> Validation Workspace: {finding.title}
            </DialogTitle>
            <DialogDescription className="flex items-center gap-2">
              <Badge className={severityColor(finding.severity)}>{finding.severity}</Badge>
              <span>{finding.target}</span>
            </DialogDescription>
          </DialogHeader>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="editor"><Code className="h-4 w-4 mr-1" /> Script Editor</TabsTrigger>
              <TabsTrigger value="terminal"><Terminal className="h-4 w-4 mr-1" /> Execution Terminal</TabsTrigger>
              <TabsTrigger value="report"><FileText className="h-4 w-4 mr-1" /> Audit Report</TabsTrigger>
            </TabsList>

            <TabsContent value="editor" className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">Review and edit the PoC script before execution. Ensure it's safe for the target environment.</p>
                <div className="flex gap-2">
                  <Badge variant="outline">{scriptLanguage}</Badge>
                  <Badge variant="outline" className="text-yellow-400 border-yellow-500/30">
                    <AlertTriangle className="h-3 w-3 mr-1" /> Human Review Required
                  </Badge>
                </div>
              </div>
              <Textarea
                value={generatedScript}
                onChange={(e) => setGeneratedScript(e.target.value)}
                className="font-mono text-sm min-h-[400px] bg-background border-border"
                placeholder="PoC script will appear here after generation..."
              />
              <div className="flex gap-2">
                <Button onClick={executeValidation} disabled={isExecuting || !generatedScript} className="flex-1">
                  {isExecuting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Executing...</> : <><Play className="h-4 w-4 mr-2" /> Run Validation</>}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="terminal" className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">Real-time execution output from the sandboxed environment</p>
                <Badge variant="outline">Sandbox: RESTRICTED</Badge>
              </div>
              <div ref={terminalRef} className="bg-black rounded-lg p-4 font-mono text-sm text-green-400 min-h-[400px] max-h-[500px] overflow-y-auto border border-green-900/30">
                {terminalOutput.length === 0 ? (
                  <p className="text-muted-foreground">$ Waiting for execution...</p>
                ) : (
                  terminalOutput.map((line, i) => (
                    <div key={i} className={`${line.includes("[ERROR]") ? "text-red-400" : line.includes("[STATUS]") ? "text-yellow-400" : line.includes("✅") ? "text-green-400" : ""}`}>
                      {line}
                    </div>
                  ))
                )}
                {isExecuting && <span className="animate-pulse">▌</span>}
              </div>
              <div className="flex gap-2">
                <Button onClick={executeValidation} disabled={isExecuting || !generatedScript} variant="outline">
                  <RefreshCw className="h-4 w-4 mr-1" /> Re-run
                </Button>
                <Button onClick={generateReport} disabled={isReporting || !currentEvidenceId}>
                  {isReporting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating...</> : <><FileText className="h-4 w-4 mr-2" /> Generate Report</>}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="report" className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">AI-generated remediation report following industry standards</p>
                {report && <Button variant="outline" size="sm" onClick={() => { navigator.clipboard.writeText(report); toast({ title: "Copied to clipboard" }); }}>
                  <Download className="h-4 w-4 mr-1" /> Copy Report
                </Button>}
              </div>
              <ScrollArea className="h-[500px]">
                {report ? (
                  <div className="prose prose-invert max-w-none p-4 bg-card rounded-lg border border-border">
                    <pre className="whitespace-pre-wrap text-sm text-foreground font-sans">{report}</pre>
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-[400px] text-muted-foreground">
                    <p>Execute a validation first, then generate the report</p>
                  </div>
                )}
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ValidationWorkspace;
