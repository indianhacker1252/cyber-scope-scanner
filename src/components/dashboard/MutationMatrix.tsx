import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import {
  Shield,
  Zap,
  Brain,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowRight,
  RotateCcw,
  Activity,
  Target,
  Lock,
  Unlock,
  Cpu,
  Play,
  Square,
} from "lucide-react";

// ─── Types ───
interface PayloadInput {
  raw: string;
  attackType: string;
  parameter: string;
  injectionPoint: "query" | "body" | "header" | "path" | "cookie";
}

interface MutationAttempt {
  id: string;
  target: string;
  parameter: string;
  original_payload: string;
  mutated_payload: string | null;
  attempt_number: number;
  max_retries: number;
  http_status: number | null;
  error_reason: string | null;
  mutation_strategy: string | null;
  status: string;
  chain_id: string | null;
  created_at: string;
}

interface ChainGroup {
  chainId: string;
  target: string;
  parameter: string;
  attempts: MutationAttempt[];
  finalStatus: string;
}

const STATUS_ICONS: Record<string, any> = {
  pending: Activity,
  firing: Zap,
  blocked: Shield,
  mutating: Brain,
  success: CheckCircle,
  defended: Lock,
  error: XCircle,
};

const STATUS_COLORS: Record<string, string> = {
  pending: "text-muted-foreground",
  firing: "text-yellow-500",
  blocked: "text-destructive",
  mutating: "text-purple-500",
  success: "text-green-500",
  defended: "text-blue-500",
  error: "text-red-400",
};

const ATTACK_TYPES = [
  { value: "xss", label: "XSS (Cross-Site Scripting)" },
  { value: "sqli", label: "SQL Injection" },
  { value: "traversal", label: "Path Traversal" },
  { value: "ssrf", label: "SSRF" },
  { value: "ssti", label: "SSTI (Template Injection)" },
  { value: "cmdi", label: "Command Injection" },
  { value: "xxe", label: "XXE" },
  { value: "idor", label: "IDOR" },
];

const SAMPLE_PAYLOADS: Record<string, string> = {
  xss: '<script>alert(document.cookie)</script>',
  sqli: "' OR 1=1 UNION SELECT null,username,password FROM users--",
  traversal: "../../../../etc/passwd",
  ssrf: "http://127.0.0.1:80/admin",
  ssti: "{{7*7}}",
  cmdi: "; cat /etc/passwd",
  xxe: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  idor: "user_id=1",
};

const MutationMatrix = () => {
  const { toast } = useToast();
  const [target, setTarget] = useState("");
  const [parameter, setParameter] = useState("q");
  const [attackType, setAttackType] = useState("xss");
  const [injectionPoint, setInjectionPoint] = useState<PayloadInput["injectionPoint"]>("query");
  const [payloadText, setPayloadText] = useState("");
  const [maxRetries, setMaxRetries] = useState(3);
  const [isRunning, setIsRunning] = useState(false);
  const [attempts, setAttempts] = useState<MutationAttempt[]>([]);
  const [chainGroups, setChainGroups] = useState<ChainGroup[]>([]);
  const [liveEvents, setLiveEvents] = useState<string[]>([]);

  // Fetch existing attempts
  const fetchAttempts = useCallback(async () => {
    const { data } = await supabase
      .from("mutation_attempts")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(200);

    if (data) {
      setAttempts(data as MutationAttempt[]);
      // Group by chain_id
      const groups: Record<string, MutationAttempt[]> = {};
      data.forEach((a: any) => {
        const key = a.chain_id || a.id;
        if (!groups[key]) groups[key] = [];
        groups[key].push(a as MutationAttempt);
      });
      const sorted = Object.entries(groups)
        .map(([chainId, atts]) => ({
          chainId,
          target: atts[0].target,
          parameter: atts[0].parameter,
          attempts: atts.sort((a, b) => a.attempt_number - b.attempt_number),
          finalStatus: atts[atts.length - 1].status,
        }))
        .sort((a, b) => new Date(b.attempts[0].created_at).getTime() - new Date(a.attempts[0].created_at).getTime());
      setChainGroups(sorted);
    }
  }, []);

  useEffect(() => {
    fetchAttempts();
  }, [fetchAttempts]);

  // Realtime subscription
  useEffect(() => {
    const channel = supabase
      .channel("mutation_attempts_realtime")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "mutation_attempts" },
        (payload: any) => {
          const record = payload.new as MutationAttempt;
          const eventType = payload.eventType;

          // Live event feed
          let eventMsg = "";
          if (eventType === "INSERT") {
            if (record.status === "firing") eventMsg = `🎯 FIRING payload at ${record.parameter} → attempt #${record.attempt_number}`;
          } else if (eventType === "UPDATE") {
            switch (record.status) {
              case "blocked":
                eventMsg = `🛡️ BLOCKED (HTTP ${record.http_status}) → ${record.parameter}`;
                break;
              case "mutating":
                eventMsg = `🧬 MUTATION_START → AI generating obfuscated payload...`;
                break;
              case "success":
                eventMsg = `✅ MUTATION_SUCCESS → Payload bypassed WAF on ${record.parameter}!`;
                break;
              case "defended":
                eventMsg = `🔒 MAX_RETRIES_REACHED → ${record.parameter} is defended`;
                break;
              case "error":
                eventMsg = `⚠️ ERROR → ${record.error_reason}`;
                break;
            }
          }

          if (eventMsg) {
            setLiveEvents((prev) => [`[${new Date().toLocaleTimeString()}] ${eventMsg}`, ...prev].slice(0, 100));
          }

          fetchAttempts();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [fetchAttempts]);

  // Auto-fill sample payload
  useEffect(() => {
    setPayloadText(SAMPLE_PAYLOADS[attackType] || "");
  }, [attackType]);

  // Launch attack execution
  const launchAttack = async () => {
    if (!target || !payloadText) {
      toast({ title: "Missing fields", description: "Enter target URL and payload", variant: "destructive" });
      return;
    }

    setIsRunning(true);
    setLiveEvents((prev) => [`[${new Date().toLocaleTimeString()}] 🚀 Launching mutation attack loop against ${target}...`, ...prev]);

    try {
      const payloads: PayloadInput[] = payloadText.split("\n").filter(Boolean).map((raw) => ({
        raw: raw.trim(),
        attackType,
        parameter,
        injectionPoint,
      }));

      const response = await supabase.functions.invoke("attack-execution-loop", {
        body: {
          target,
          payloads: payloads.map((p) => ({ ...p, encoded: encodeURIComponent(p.raw) })),
          maxRetries,
          techStack: [],
        },
      });

      if (response.error) throw response.error;

      const report = response.data;
      toast({
        title: "Execution Complete",
        description: `✅ ${report.successCount} success | 🛡️ ${report.blockedCount} blocked | 🔒 ${report.defendedCount} defended`,
      });

      setLiveEvents((prev) => [
        `[${new Date().toLocaleTimeString()}] 📊 COMPLETE: ${report.successCount}/${report.totalPayloads} payloads succeeded`,
        ...prev,
      ]);
    } catch (error: any) {
      toast({ title: "Execution Error", description: error.message, variant: "destructive" });
      setLiveEvents((prev) => [`[${new Date().toLocaleTimeString()}] ❌ ERROR: ${error.message}`, ...prev]);
    } finally {
      setIsRunning(false);
    }
  };

  // Stats
  const totalAttempts = attempts.length;
  const successCount = attempts.filter((a) => a.status === "success").length;
  const blockedCount = attempts.filter((a) => a.status === "blocked").length;
  const defendedCount = attempts.filter((a) => a.status === "defended").length;
  const mutatingCount = attempts.filter((a) => a.status === "mutating" || a.status === "firing").length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total Attempts", value: totalAttempts, icon: Target, color: "text-blue-500" },
          { label: "Successful Bypasses", value: successCount, icon: Unlock, color: "text-green-500" },
          { label: "WAF Blocks", value: blockedCount, icon: Shield, color: "text-destructive" },
          { label: "Defended", value: defendedCount, icon: Lock, color: "text-muted-foreground" },
          { label: "Active Mutations", value: mutatingCount, icon: Brain, color: "text-purple-500", pulse: true },
        ].map((stat, idx) => (
          <Card key={idx}>
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-2xl font-bold">{stat.value}</p>
                <p className="text-xs text-muted-foreground">{stat.label}</p>
              </div>
              <stat.icon className={`h-7 w-7 ${stat.color} ${(stat as any).pulse ? "animate-pulse" : ""}`} />
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="launch" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="launch">🚀 Launch</TabsTrigger>
          <TabsTrigger value="chains">🔗 Mutation Chains</TabsTrigger>
          <TabsTrigger value="live">⚡ Live Feed</TabsTrigger>
          <TabsTrigger value="history">📋 History</TabsTrigger>
        </TabsList>

        {/* Launch Tab */}
        <TabsContent value="launch" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-primary" />
                Payload Mutation & Retry Engine
              </CardTitle>
              <CardDescription>
                Fire payloads, detect WAF blocks, AI-mutate, and autonomously retry
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Target URL</label>
                  <Input
                    placeholder="https://target.com/search"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Parameter Name</label>
                  <Input
                    placeholder="q"
                    value={parameter}
                    onChange={(e) => setParameter(e.target.value)}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Attack Type</label>
                  <Select value={attackType} onValueChange={setAttackType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {ATTACK_TYPES.map((t) => (
                        <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Injection Point</label>
                  <Select value={injectionPoint} onValueChange={(v: any) => setInjectionPoint(v)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="query">Query Parameter</SelectItem>
                      <SelectItem value="body">POST Body</SelectItem>
                      <SelectItem value="header">HTTP Header</SelectItem>
                      <SelectItem value="cookie">Cookie</SelectItem>
                      <SelectItem value="path">URL Path</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Max Retries</label>
                  <Select value={String(maxRetries)} onValueChange={(v) => setMaxRetries(parseInt(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {[1, 2, 3, 4, 5].map((n) => (
                        <SelectItem key={n} value={String(n)}>{n} retries</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Payloads (one per line)</label>
                <Textarea
                  className="font-mono text-sm min-h-[120px]"
                  placeholder="Enter payloads, one per line..."
                  value={payloadText}
                  onChange={(e) => setPayloadText(e.target.value)}
                />
              </div>

              <Button
                onClick={launchAttack}
                disabled={isRunning || !target || !payloadText}
                className="w-full"
                size="lg"
              >
                {isRunning ? (
                  <>
                    <RotateCcw className="h-4 w-4 mr-2 animate-spin" />
                    Executing Mutation Loop...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Launch Mutation Attack
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Mutation Chains Tab — Visual Timeline */}
        <TabsContent value="chains" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-primary" />
                Mutation Chain Visualization
              </CardTitle>
              <CardDescription>Visual timeline of payload mutation and retry chains</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-6">
                  {chainGroups.length === 0 && (
                    <p className="text-center text-muted-foreground py-12">No mutation chains yet. Launch an attack to begin.</p>
                  )}
                  {chainGroups.map((chain) => (
                    <Card key={chain.chainId} className="border-l-4 border-l-primary">
                      <CardContent className="p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-semibold text-sm">{chain.target}</p>
                            <p className="text-xs text-muted-foreground">Parameter: {chain.parameter}</p>
                          </div>
                          <Badge variant={chain.finalStatus === "success" ? "default" : chain.finalStatus === "defended" ? "secondary" : "destructive"}>
                            {chain.finalStatus.toUpperCase()}
                          </Badge>
                        </div>

                        {/* Timeline visualization */}
                        <div className="flex items-center gap-1 flex-wrap">
                          {chain.attempts.map((attempt, idx) => {
                            const Icon = STATUS_ICONS[attempt.status] || Activity;
                            const color = STATUS_COLORS[attempt.status] || "text-muted-foreground";
                            return (
                              <div key={attempt.id} className="flex items-center gap-1">
                                <div className="flex flex-col items-center gap-1 p-2 rounded-lg bg-muted/50 min-w-[120px]">
                                  <Icon className={`h-5 w-5 ${color} ${attempt.status === "mutating" || attempt.status === "firing" ? "animate-pulse" : ""}`} />
                                  <span className="text-[10px] font-medium">{attempt.status.toUpperCase()}</span>
                                  {attempt.http_status && (
                                    <Badge variant="outline" className="text-[10px]">HTTP {attempt.http_status}</Badge>
                                  )}
                                  {attempt.mutation_strategy && (
                                    <Badge variant="secondary" className="text-[10px]">{attempt.mutation_strategy}</Badge>
                                  )}
                                  <p className="text-[10px] text-muted-foreground font-mono max-w-[110px] truncate">
                                    {attempt.mutated_payload || attempt.original_payload}
                                  </p>
                                </div>
                                {idx < chain.attempts.length - 1 && (
                                  <ArrowRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Live Feed Tab */}
        <TabsContent value="live" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary animate-pulse" />
                Live Mutation Events
              </CardTitle>
              <CardDescription>Real-time broadcast of MUTATION_START, MUTATION_SUCCESS, MAX_RETRIES_REACHED</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-1 font-mono text-sm">
                  {liveEvents.length === 0 && (
                    <p className="text-center text-muted-foreground py-12">Waiting for mutation events...</p>
                  )}
                  {liveEvents.map((event, idx) => (
                    <div key={idx} className="p-2 rounded bg-muted/30 hover:bg-muted/60 transition-colors animate-fade-in">
                      {event}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* History Tab */}
        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Attempt History</CardTitle>
              <CardDescription>All recorded mutation attempts</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {attempts.slice(0, 50).map((attempt) => {
                    const Icon = STATUS_ICONS[attempt.status] || Activity;
                    const color = STATUS_COLORS[attempt.status] || "text-muted-foreground";
                    return (
                      <div key={attempt.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                        <Icon className={`h-4 w-4 ${color} flex-shrink-0`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">
                            {attempt.target} → {attempt.parameter}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Attempt #{attempt.attempt_number}/{attempt.max_retries} •{" "}
                            {attempt.mutation_strategy || "original"} •{" "}
                            {new Date(attempt.created_at).toLocaleTimeString()}
                          </p>
                          {attempt.error_reason && (
                            <p className="text-xs text-destructive truncate">{attempt.error_reason}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {attempt.http_status && (
                            <Badge variant="outline" className="text-xs">HTTP {attempt.http_status}</Badge>
                          )}
                          <Badge variant={attempt.status === "success" ? "default" : attempt.status === "defended" ? "secondary" : "destructive"} className="text-xs">
                            {attempt.status}
                          </Badge>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default MutationMatrix;
