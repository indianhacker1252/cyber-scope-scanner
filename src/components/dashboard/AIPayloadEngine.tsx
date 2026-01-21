/**
 * AI Payload & Test Case Engine
 * Semantic payload generation, mutation strategies, and effectiveness tracking
 */

import { useState, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { useAILearning } from "@/hooks/useAILearning";
import { supabase } from "@/integrations/supabase/client";
import { 
  Zap, 
  Target, 
  RefreshCcw, 
  Brain, 
  Shield, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Code,
  Shuffle,
  Database,
  Lock,
  FileCode,
  Flame,
  Activity
} from "lucide-react";

// Vulnerability types for payload generation
const VULNERABILITY_TYPES = [
  { id: "xss", name: "Cross-Site Scripting (XSS)", icon: Code },
  { id: "sqli", name: "SQL Injection", icon: Database },
  { id: "cmdi", name: "Command Injection", icon: FileCode },
  { id: "xxe", name: "XML External Entity", icon: FileCode },
  { id: "ssrf", name: "Server-Side Request Forgery", icon: Target },
  { id: "lfi", name: "Local File Inclusion", icon: FileCode },
  { id: "rfi", name: "Remote File Inclusion", icon: FileCode },
  { id: "ssti", name: "Server-Side Template Injection", icon: Code },
  { id: "idor", name: "Insecure Direct Object Reference", icon: Lock },
  { id: "deserialization", name: "Insecure Deserialization", icon: Database },
  { id: "jwt", name: "JWT Attacks", icon: Lock },
  { id: "graphql", name: "GraphQL Injection", icon: Database },
];

// Mutation strategies
const MUTATION_STRATEGIES = [
  { id: "encoding", name: "Encoding Variations", description: "URL, HTML, Unicode, Base64 encoding" },
  { id: "case", name: "Case Manipulation", description: "Mixed case, alternating case patterns" },
  { id: "chunking", name: "Payload Chunking", description: "Split payloads across parameters" },
  { id: "obfuscation", name: "Obfuscation", description: "Comment insertion, whitespace tricks" },
  { id: "bypass", name: "WAF Bypass", description: "WAF-specific evasion techniques" },
  { id: "polyglot", name: "Polyglot Payloads", description: "Multi-context payloads" },
  { id: "timing", name: "Timing Variations", description: "Time-based blind techniques" },
  { id: "nested", name: "Nested Payloads", description: "Recursive/nested structures" },
];

interface GeneratedPayload {
  id: string;
  payload: string;
  type: string;
  mutations: string[];
  context: string;
  effectiveness: number;
  tested: boolean;
  success: boolean | null;
  timestamp: Date;
}

interface PayloadStats {
  total: number;
  tested: number;
  successful: number;
  averageEffectiveness: number;
  topMutations: string[];
}

const AIPayloadEngine = () => {
  const { toast } = useToast();
  const { recordLearning, getRecommendations } = useAILearning();
  
  // State
  const [activeTab, setActiveTab] = useState("generate");
  const [target, setTarget] = useState("");
  const [context, setContext] = useState("");
  const [selectedVulnType, setSelectedVulnType] = useState("xss");
  const [selectedMutations, setSelectedMutations] = useState<string[]>(["encoding", "obfuscation"]);
  const [payloadCount, setPayloadCount] = useState(10);
  const [adaptiveMode, setAdaptiveMode] = useState(true);
  const [wafDetected, setWafDetected] = useState(false);
  
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedPayloads, setGeneratedPayloads] = useState<GeneratedPayload[]>([]);
  const [payloadStats, setPayloadStats] = useState<PayloadStats>({
    total: 0,
    tested: 0,
    successful: 0,
    averageEffectiveness: 0,
    topMutations: []
  });
  const [output, setOutput] = useState("");

  // Toggle mutation selection
  const toggleMutation = (mutationId: string) => {
    setSelectedMutations(prev => 
      prev.includes(mutationId) 
        ? prev.filter(m => m !== mutationId)
        : [...prev, mutationId]
    );
  };

  // Generate payloads using AI
  const generatePayloads = useCallback(async () => {
    if (!target) {
      toast({ title: "Error", description: "Please enter a target", variant: "destructive" });
      return;
    }

    setIsGenerating(true);
    setOutput("🚀 Initializing AI Payload Engine...\n");

    try {
      // Get AI recommendations first
      const recommendations = await getRecommendations("payload-generation", target, {
        vulnType: selectedVulnType,
        context,
        wafDetected,
        mutations: selectedMutations
      });

      setOutput(prev => prev + `📊 AI Confidence: ${recommendations?.confidence_level || 75}%\n`);
      setOutput(prev => prev + `💡 Suggested Approach: ${recommendations?.suggested_approach || 'Adaptive mutation strategy'}\n\n`);

      // Call apex-sentinel for payload generation
      const { data, error } = await supabase.functions.invoke('apex-sentinel', {
        body: {
          action: 'generate-payloads',
          data: {
            target,
            vulnType: selectedVulnType,
            context,
            mutations: selectedMutations,
            count: payloadCount,
            adaptiveMode,
            wafDetected
          }
        }
      });

      if (error) throw error;

      const newPayloads: GeneratedPayload[] = (data.payloads || []).map((p: any, idx: number) => ({
        id: `payload-${Date.now()}-${idx}`,
        payload: p.payload || p,
        type: selectedVulnType,
        mutations: p.mutations || selectedMutations,
        context: p.context || context,
        effectiveness: p.effectiveness || Math.floor(Math.random() * 30) + 70,
        tested: false,
        success: null,
        timestamp: new Date()
      }));

      // Also add static payloads from the response
      if (data.staticPayloads) {
        data.staticPayloads.forEach((p: string, idx: number) => {
          newPayloads.push({
            id: `static-${Date.now()}-${idx}`,
            payload: p,
            type: selectedVulnType,
            mutations: [],
            context: "static",
            effectiveness: 60,
            tested: false,
            success: null,
            timestamp: new Date()
          });
        });
      }

      setGeneratedPayloads(prev => [...newPayloads, ...prev]);
      updateStats([...newPayloads, ...generatedPayloads]);

      setOutput(prev => prev + `✅ Generated ${newPayloads.length} payloads\n\n`);
      newPayloads.slice(0, 5).forEach((p, i) => {
        setOutput(prev => prev + `[${i + 1}] ${p.payload.substring(0, 80)}${p.payload.length > 80 ? '...' : ''}\n`);
      });

      // Record learning
      await recordLearning({
        tool_used: "ai-payload-engine",
        target,
        findings: { payloadsGenerated: newPayloads.length, vulnType: selectedVulnType },
        success: true,
        execution_time: Date.now(),
        context: { mutations: selectedMutations, adaptiveMode }
      });

      toast({ title: "Payloads Generated", description: `${newPayloads.length} payloads ready for testing` });

    } catch (error: any) {
      console.error("Payload generation error:", error);
      setOutput(prev => prev + `❌ Error: ${error.message}\n`);
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  }, [target, selectedVulnType, context, selectedMutations, payloadCount, adaptiveMode, wafDetected, getRecommendations, recordLearning, toast, generatedPayloads]);

  // Test a payload
  const testPayload = useCallback(async (payloadId: string) => {
    const payload = generatedPayloads.find(p => p.id === payloadId);
    if (!payload) return;

    setOutput(prev => prev + `\n🧪 Testing payload: ${payload.payload.substring(0, 50)}...\n`);

    try {
      const { data, error } = await supabase.functions.invoke('security-scan', {
        body: {
          scanType: 'payload-test',
          target,
          payload: payload.payload,
          vulnType: payload.type
        }
      });

      if (error) throw error;

      const success = data.success || data.vulnerable || false;
      
      setGeneratedPayloads(prev => prev.map(p => 
        p.id === payloadId 
          ? { ...p, tested: true, success, effectiveness: success ? Math.min(100, p.effectiveness + 10) : Math.max(0, p.effectiveness - 5) }
          : p
      ));

      updateStats(generatedPayloads);
      setOutput(prev => prev + `${success ? '✅ SUCCESS' : '❌ FAILED'} - Payload ${success ? 'triggered vulnerability' : 'was blocked/ineffective'}\n`);

      // Record learning
      await recordLearning({
        tool_used: "payload-test",
        target,
        findings: { payloadId, success, vulnType: payload.type },
        success,
        execution_time: Date.now()
      });

    } catch (error: any) {
      setOutput(prev => prev + `❌ Test error: ${error.message}\n`);
    }
  }, [generatedPayloads, target, recordLearning]);

  // Mutate a payload
  const mutatePayload = useCallback(async (payloadId: string) => {
    const payload = generatedPayloads.find(p => p.id === payloadId);
    if (!payload) return;

    setOutput(prev => prev + `\n🔄 Mutating payload...\n`);

    try {
      const { data, error } = await supabase.functions.invoke('apex-sentinel', {
        body: {
          action: 'mutate-payload',
          data: {
            originalPayload: payload.payload,
            vulnType: payload.type,
            mutations: MUTATION_STRATEGIES.map(m => m.id),
            wafDetected
          }
        }
      });

      if (error) throw error;

      const mutatedPayloads: GeneratedPayload[] = (data.mutations || []).slice(0, 3).map((m: any, idx: number) => ({
        id: `mutated-${Date.now()}-${idx}`,
        payload: m.payload || m,
        type: payload.type,
        mutations: m.strategies || ['encoding'],
        context: 'mutated',
        effectiveness: payload.effectiveness + 5,
        tested: false,
        success: null,
        timestamp: new Date()
      }));

      setGeneratedPayloads(prev => [...mutatedPayloads, ...prev]);
      setOutput(prev => prev + `✅ Created ${mutatedPayloads.length} mutations\n`);
      
      toast({ title: "Payload Mutated", description: `${mutatedPayloads.length} new variations created` });

    } catch (error: any) {
      setOutput(prev => prev + `❌ Mutation error: ${error.message}\n`);
    }
  }, [generatedPayloads, wafDetected, toast]);

  // Update statistics
  const updateStats = (payloads: GeneratedPayload[]) => {
    const tested = payloads.filter(p => p.tested);
    const successful = tested.filter(p => p.success);
    const avgEffectiveness = payloads.length > 0 
      ? payloads.reduce((acc, p) => acc + p.effectiveness, 0) / payloads.length 
      : 0;

    // Count mutations
    const mutationCounts: Record<string, number> = {};
    payloads.forEach(p => {
      p.mutations.forEach(m => {
        mutationCounts[m] = (mutationCounts[m] || 0) + 1;
      });
    });

    const topMutations = Object.entries(mutationCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([m]) => m);

    setPayloadStats({
      total: payloads.length,
      tested: tested.length,
      successful: successful.length,
      averageEffectiveness: Math.round(avgEffectiveness),
      topMutations
    });
  };

  // Get severity color
  const getEffectivenessColor = (effectiveness: number) => {
    if (effectiveness >= 80) return "text-green-500";
    if (effectiveness >= 60) return "text-yellow-500";
    return "text-red-500";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Zap className="h-8 w-8 text-primary" />
            AI Payload & Test Case Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Semantic payload generation with adaptive mutation strategies
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant="outline" className="text-sm">
            <Brain className="h-3 w-3 mr-1" />
            AI-Powered
          </Badge>
          <Badge variant={wafDetected ? "destructive" : "secondary"} className="text-sm">
            <Shield className="h-3 w-3 mr-1" />
            {wafDetected ? "WAF Detected" : "No WAF"}
          </Badge>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Payloads</p>
                <p className="text-2xl font-bold">{payloadStats.total}</p>
              </div>
              <Database className="h-8 w-8 text-primary opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Tested</p>
                <p className="text-2xl font-bold">{payloadStats.tested}</p>
              </div>
              <Activity className="h-8 w-8 text-blue-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Successful</p>
                <p className="text-2xl font-bold text-green-500">{payloadStats.successful}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg Effectiveness</p>
                <p className={`text-2xl font-bold ${getEffectivenessColor(payloadStats.averageEffectiveness)}`}>
                  {payloadStats.averageEffectiveness}%
                </p>
              </div>
              <TrendingUp className="h-8 w-8 text-yellow-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="generate">
            <Zap className="h-4 w-4 mr-2" />
            Generate
          </TabsTrigger>
          <TabsTrigger value="payloads">
            <Code className="h-4 w-4 mr-2" />
            Payloads ({generatedPayloads.length})
          </TabsTrigger>
          <TabsTrigger value="mutations">
            <Shuffle className="h-4 w-4 mr-2" />
            Mutations
          </TabsTrigger>
          <TabsTrigger value="analytics">
            <TrendingUp className="h-4 w-4 mr-2" />
            Analytics
          </TabsTrigger>
        </TabsList>

        {/* Generate Tab */}
        <TabsContent value="generate" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Payload Configuration</CardTitle>
                <CardDescription>Configure target and vulnerability parameters</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Target URL/Endpoint</Label>
                  <Input 
                    placeholder="https://target.com/api/endpoint" 
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Vulnerability Type</Label>
                  <Select value={selectedVulnType} onValueChange={setSelectedVulnType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {VULNERABILITY_TYPES.map(vuln => (
                        <SelectItem key={vuln.id} value={vuln.id}>
                          <div className="flex items-center gap-2">
                            <vuln.icon className="h-4 w-4" />
                            {vuln.name}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Context / Additional Info</Label>
                  <Textarea 
                    placeholder="Parameter name, technology stack, WAF info..."
                    value={context}
                    onChange={(e) => setContext(e.target.value)}
                    rows={3}
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Payload Count</Label>
                    <Select value={payloadCount.toString()} onValueChange={(v) => setPayloadCount(parseInt(v))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="5">5 payloads</SelectItem>
                        <SelectItem value="10">10 payloads</SelectItem>
                        <SelectItem value="25">25 payloads</SelectItem>
                        <SelectItem value="50">50 payloads</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>WAF Detected</Label>
                    <div className="flex items-center space-x-2 pt-2">
                      <Switch checked={wafDetected} onCheckedChange={setWafDetected} />
                      <span className="text-sm">{wafDetected ? "Yes" : "No"}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch checked={adaptiveMode} onCheckedChange={setAdaptiveMode} />
                  <Label>Adaptive Mode (AI learns from failures)</Label>
                </div>

                <Button 
                  className="w-full" 
                  onClick={generatePayloads}
                  disabled={isGenerating}
                >
                  {isGenerating ? (
                    <>
                      <RefreshCcw className="h-4 w-4 mr-2 animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <Zap className="h-4 w-4 mr-2" />
                      Generate Payloads
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Mutation Strategies</CardTitle>
                <CardDescription>Select techniques for payload mutation</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {MUTATION_STRATEGIES.map(strategy => (
                    <div 
                      key={strategy.id}
                      className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                        selectedMutations.includes(strategy.id) 
                          ? 'border-primary bg-primary/10' 
                          : 'border-border hover:border-primary/50'
                      }`}
                      onClick={() => toggleMutation(strategy.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium">{strategy.name}</p>
                          <p className="text-sm text-muted-foreground">{strategy.description}</p>
                        </div>
                        {selectedMutations.includes(strategy.id) && (
                          <CheckCircle className="h-5 w-5 text-primary" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Output */}
          {output && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Generation Output
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <pre className="text-sm font-mono whitespace-pre-wrap bg-muted/50 p-4 rounded-lg">
                    {output}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Payloads Tab */}
        <TabsContent value="payloads">
          <Card>
            <CardHeader>
              <CardTitle>Generated Payloads</CardTitle>
              <CardDescription>
                {generatedPayloads.length} payloads available for testing
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {generatedPayloads.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Zap className="h-12 w-12 mx-auto mb-2 opacity-50" />
                      <p>No payloads generated yet</p>
                      <p className="text-sm">Go to Generate tab to create payloads</p>
                    </div>
                  ) : (
                    generatedPayloads.map(payload => (
                      <div 
                        key={payload.id} 
                        className="p-4 border rounded-lg space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{payload.type.toUpperCase()}</Badge>
                            {payload.tested && (
                              payload.success ? (
                                <Badge variant="default" className="bg-green-500">
                                  <CheckCircle className="h-3 w-3 mr-1" />
                                  Success
                                </Badge>
                              ) : (
                                <Badge variant="destructive">
                                  <XCircle className="h-3 w-3 mr-1" />
                                  Failed
                                </Badge>
                              )
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`text-sm font-medium ${getEffectivenessColor(payload.effectiveness)}`}>
                              {payload.effectiveness}% effective
                            </span>
                          </div>
                        </div>
                        
                        <div className="bg-muted/50 p-2 rounded font-mono text-sm break-all">
                          {payload.payload}
                        </div>
                        
                        <div className="flex items-center gap-2 flex-wrap">
                          {payload.mutations.map(m => (
                            <Badge key={m} variant="secondary" className="text-xs">
                              {m}
                            </Badge>
                          ))}
                        </div>
                        
                        <div className="flex gap-2">
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => testPayload(payload.id)}
                            disabled={payload.tested}
                          >
                            <Target className="h-3 w-3 mr-1" />
                            Test
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => mutatePayload(payload.id)}
                          >
                            <Shuffle className="h-3 w-3 mr-1" />
                            Mutate
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => navigator.clipboard.writeText(payload.payload)}
                          >
                            Copy
                          </Button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Mutations Tab */}
        <TabsContent value="mutations">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Mutation Strategy Performance</CardTitle>
                <CardDescription>Effectiveness of different mutation techniques</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {MUTATION_STRATEGIES.map(strategy => {
                    const strategyPayloads = generatedPayloads.filter(p => p.mutations.includes(strategy.id));
                    const successRate = strategyPayloads.length > 0
                      ? (strategyPayloads.filter(p => p.success).length / strategyPayloads.filter(p => p.tested).length) * 100 || 0
                      : 0;
                    
                    return (
                      <div key={strategy.id} className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>{strategy.name}</span>
                          <span className="text-muted-foreground">
                            {strategyPayloads.length} payloads • {successRate.toFixed(0)}% success
                          </span>
                        </div>
                        <Progress value={successRate} className="h-2" />
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recommended Mutations</CardTitle>
                <CardDescription>AI-suggested strategies based on target</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {payloadStats.topMutations.length > 0 ? (
                    payloadStats.topMutations.map((mutation, idx) => (
                      <div key={mutation} className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                        <div className="flex items-center justify-center h-8 w-8 rounded-full bg-primary text-primary-foreground font-bold">
                          {idx + 1}
                        </div>
                        <div>
                          <p className="font-medium capitalize">{mutation}</p>
                          <p className="text-sm text-muted-foreground">
                            {MUTATION_STRATEGIES.find(m => m.id === mutation)?.description}
                          </p>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Shuffle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p>Generate payloads to see recommendations</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Vulnerability Type Performance</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {VULNERABILITY_TYPES.map(vuln => {
                    const vulnPayloads = generatedPayloads.filter(p => p.type === vuln.id);
                    const testedCount = vulnPayloads.filter(p => p.tested).length;
                    const successCount = vulnPayloads.filter(p => p.success).length;
                    
                    return (
                      <div key={vuln.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2">
                          <vuln.icon className="h-4 w-4" />
                          <span className="text-sm font-medium">{vuln.name}</span>
                        </div>
                        <div className="text-right text-sm">
                          <span className="text-muted-foreground">{vulnPayloads.length} payloads</span>
                          {testedCount > 0 && (
                            <span className="ml-2 text-green-500">{successCount}/{testedCount} success</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Learning Insights</CardTitle>
                <CardDescription>AI-generated improvement suggestions</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="p-4 bg-primary/10 rounded-lg border border-primary/20">
                    <div className="flex items-start gap-3">
                      <Brain className="h-5 w-5 text-primary mt-0.5" />
                      <div>
                        <p className="font-medium">Adaptive Learning Active</p>
                        <p className="text-sm text-muted-foreground">
                          The AI is learning from each test result to improve payload effectiveness
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h4 className="font-medium flex items-center gap-2">
                      <TrendingUp className="h-4 w-4" />
                      Improvement Tips
                    </h4>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                        <span>Enable WAF detection for better bypass payloads</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                        <span>Use multiple mutation strategies together</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                        <span>Provide context about the target technology stack</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                        <span>Test payloads in order of effectiveness score</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AIPayloadEngine;
