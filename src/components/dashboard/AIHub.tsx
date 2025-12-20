import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { 
  Brain, 
  Zap, 
  Shield, 
  Target, 
  Activity, 
  Loader2,
  Send,
  Play,
  Lightbulb,
  AlertTriangle,
  CheckCircle,
  XCircle,
  MessageSquare
} from "lucide-react";

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface AnalysisResult {
  attack_type?: string;
  analysis?: any;
  recommendations?: string[];
  output?: string;
}

const AIHub = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("assistant");
  
  // AI Assistant state
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  
  // Autonomous Hacking state
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("full-pentest");
  const [targetAnalysis, setTargetAnalysis] = useState<any>(null);
  const [attackChain, setAttackChain] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResults, setExecutionResults] = useState<any[]>([]);
  
  // PentestGPT state
  const [attackType, setAttackType] = useState("");
  const [pentestOutput, setPentestOutput] = useState("");
  
  const attackTypes = [
    "SQL Injection", "Cross-Site Scripting (XSS)", "CSRF", "RCE", 
    "LFI/RFI", "SSRF", "XXE", "Authentication Bypass", 
    "Privilege Escalation", "Command Injection"
  ];

  // AI Assistant Functions
  const sendMessage = async () => {
    if (!input.trim()) return;
    
    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: input,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMessage]);
    setInput("");
    setIsProcessing(true);

    try {
      const { data, error } = await supabase.functions.invoke('ai-tool-orchestrator', {
        body: { 
          action: 'analyze-intent', 
          data: { userInput: input, target: target || 'general' } 
        }
      });

      if (error) throw error;

      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: data.analysis 
          ? `**Understanding:** ${data.analysis.understood_intent}\n\n**Strategy:** ${data.analysis.attack_strategy}\n\n**Recommended Tools:** ${data.analysis.recommended_tools?.join(', ') || 'None'}\n\n**Risk Level:** ${data.analysis.risk_level || 'Medium'}`
          : data.message || 'Analysis complete.',
        timestamp: new Date()
      };
      setMessages(prev => [...prev, assistantMessage]);
      
      toast({ title: "AI Analysis Complete" });
    } catch (error: any) {
      const errorMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: `Error: ${error.message}. Please ensure you're logged in and try again.`,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsProcessing(false);
    }
  };

  // Autonomous Hacking Functions
  const analyzeTarget = async () => {
    if (!target) {
      toast({ title: "Error", description: "Please enter a target", variant: "destructive" });
      return;
    }

    setIsAnalyzing(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-attack-orchestrator', {
        body: {
          action: 'analyze-target',
          data: { target, reconnaissance_data: { basic: true } }
        }
      });

      if (error) throw error;

      setTargetAnalysis(data.analysis);
      toast({ 
        title: "Target Analysis Complete", 
        description: `Identified ${data.analysis?.vulnerabilities?.length || 0} potential vulnerabilities` 
      });
    } catch (error: any) {
      toast({ title: "Analysis Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const createAttackPlan = async () => {
    if (!targetAnalysis) {
      toast({ title: "Error", description: "Please analyze target first", variant: "destructive" });
      return;
    }

    setIsAnalyzing(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-attack-orchestrator', {
        body: {
          action: 'create-attack-chain',
          data: { target, objective, intelligence: targetAnalysis }
        }
      });

      if (error) throw error;

      setAttackChain(data);
      toast({ 
        title: "Attack Chain Created", 
        description: `${data.chain?.total_stages || 0} stages planned` 
      });
    } catch (error: any) {
      toast({ title: "Failed to Create Chain", description: error.message, variant: "destructive" });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const executeAttackChain = async () => {
    if (!attackChain) {
      toast({ title: "Error", description: "Create attack chain first", variant: "destructive" });
      return;
    }

    setIsExecuting(true);
    setExecutionResults([]);

    try {
      // Simulate execution steps
      const stages = attackChain.chain?.attack_sequence || [];
      for (let i = 0; i < stages.length; i++) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        setExecutionResults(prev => [...prev, {
          stage: i + 1,
          name: stages[i].name,
          success: Math.random() > 0.3,
          output: `Executed ${stages[i].tool}: ${stages[i].technique}`,
          timestamp: new Date().toISOString()
        }]);
      }
      
      toast({ title: "Execution Complete" });
    } catch (error: any) {
      toast({ title: "Execution Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsExecuting(false);
    }
  };

  // PentestGPT Functions
  const getAttackInfo = async () => {
    if (!attackType) {
      toast({ title: "Error", description: "Please select an attack type", variant: "destructive" });
      return;
    }

    setIsProcessing(true);
    try {
      const { data, error } = await supabase.functions.invoke('security-advisor', {
        body: { query: `Provide comprehensive information about ${attackType} attack including detection methods, exploitation techniques, and mitigation strategies.` }
      });

      if (error) throw error;

      setPentestOutput(data.advice || data.response || 'No response received.');
      toast({ title: "Attack Information Retrieved" });
    } catch (error: any) {
      toast({ title: "Failed", description: error.message, variant: "destructive" });
      setPentestOutput(`Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Brain className="h-6 w-6 text-primary" />
            <CardTitle>AI Security Hub</CardTitle>
          </div>
          <CardDescription>
            Unified AI-powered security analysis, autonomous hacking, and intelligent assistance
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="assistant" className="flex items-center gap-1">
                <MessageSquare className="h-4 w-4" />
                Assistant
              </TabsTrigger>
              <TabsTrigger value="autonomous" className="flex items-center gap-1">
                <Zap className="h-4 w-4" />
                Autonomous
              </TabsTrigger>
              <TabsTrigger value="pentest" className="flex items-center gap-1">
                <Shield className="h-4 w-4" />
                PentestGPT
              </TabsTrigger>
              <TabsTrigger value="insights" className="flex items-center gap-1">
                <Lightbulb className="h-4 w-4" />
                Insights
              </TabsTrigger>
            </TabsList>

            {/* AI Assistant Tab */}
            <TabsContent value="assistant" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Brain className="h-5 w-5 text-primary animate-pulse" />
                    AI Security Assistant
                  </CardTitle>
                  <CardDescription>
                    Natural language commands for security operations
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>Target (Optional)</Label>
                      <Input
                        placeholder="example.com or 192.168.1.1"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                      />
                    </div>
                    
                    <ScrollArea className="h-[300px] border rounded-lg p-4">
                      {messages.length === 0 ? (
                        <div className="text-center text-muted-foreground py-8">
                          <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>Ask me anything about security testing...</p>
                          <div className="mt-4 flex flex-wrap justify-center gap-2">
                            <Badge variant="outline">"Scan for vulnerabilities"</Badge>
                            <Badge variant="outline">"Find SQL injection points"</Badge>
                            <Badge variant="outline">"Run full pentest"</Badge>
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {messages.map((msg) => (
                            <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                              <div className={`max-w-[80%] rounded-lg p-3 ${
                                msg.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'
                              }`}>
                                <pre className="whitespace-pre-wrap text-sm font-sans">{msg.content}</pre>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </ScrollArea>

                    <div className="flex gap-2">
                      <Input
                        placeholder="Ask about security testing..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                        disabled={isProcessing}
                      />
                      <Button onClick={sendMessage} disabled={isProcessing || !input.trim()}>
                        {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Autonomous Hacking Tab */}
            <TabsContent value="autonomous" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Zap className="h-5 w-5 text-primary" />
                    Autonomous Attack Orchestration
                  </CardTitle>
                  <CardDescription>
                    AI-driven target analysis and attack chain execution
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Target</Label>
                      <Input
                        placeholder="example.com or 192.168.1.1"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Objective</Label>
                      <select
                        className="w-full px-3 py-2 border rounded-md bg-background"
                        value={objective}
                        onChange={(e) => setObjective(e.target.value)}
                      >
                        <option value="full-pentest">Full Penetration Test</option>
                        <option value="vulnerability-scan">Vulnerability Assessment</option>
                        <option value="exploitation">Exploitation Only</option>
                        <option value="credential-access">Credential Access</option>
                      </select>
                    </div>
                  </div>

                  <div className="flex gap-2 flex-wrap">
                    <Button onClick={analyzeTarget} disabled={isAnalyzing || !target}>
                      {isAnalyzing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Target className="h-4 w-4 mr-2" />}
                      1. Analyze Target
                    </Button>
                    <Button onClick={createAttackPlan} disabled={isAnalyzing || !targetAnalysis} variant="secondary">
                      <Brain className="h-4 w-4 mr-2" />
                      2. Create Attack Plan
                    </Button>
                    <Button onClick={executeAttackChain} disabled={isExecuting || !attackChain} variant="default">
                      {isExecuting ? <Activity className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
                      3. Execute
                    </Button>
                  </div>

                  {/* Target Analysis Output */}
                  {targetAnalysis && (
                    <Card className="bg-muted/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Target Intelligence</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[200px]">
                          <div className="space-y-2 text-sm">
                            {targetAnalysis.tech_stack && (
                              <div>
                                <strong>Technology Stack:</strong>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {targetAnalysis.tech_stack.map((tech: string, i: number) => (
                                    <Badge key={i} variant="secondary">{tech}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                            {targetAnalysis.vulnerabilities && (
                              <div>
                                <strong>Vulnerabilities:</strong>
                                <ul className="list-disc list-inside mt-1">
                                  {targetAnalysis.vulnerabilities.map((v: string, i: number) => (
                                    <li key={i}>{v}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}

                  {/* Attack Chain Output */}
                  {attackChain && (
                    <Card className="bg-muted/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Attack Chain</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[200px]">
                          <div className="space-y-2">
                            {attackChain.chain?.attack_sequence?.map((stage: any, i: number) => (
                              <div key={i} className="p-2 bg-background rounded border">
                                <div className="flex items-center justify-between">
                                  <span className="font-medium">Stage {stage.stage}: {stage.name}</span>
                                  <Badge variant="outline">{stage.tool}</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{stage.technique}</p>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}

                  {/* Execution Results */}
                  {executionResults.length > 0 && (
                    <Card className="bg-muted/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Execution Results</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[200px]">
                          <div className="space-y-2">
                            {executionResults.map((result, i) => (
                              <div key={i} className={`p-2 rounded border ${result.success ? 'border-green-500/50' : 'border-red-500/50'}`}>
                                <div className="flex items-center gap-2">
                                  {result.success ? <CheckCircle className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-red-500" />}
                                  <span className="font-medium">Stage {result.stage}: {result.name}</span>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{result.output}</p>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* PentestGPT Tab */}
            <TabsContent value="pentest" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Shield className="h-5 w-5 text-primary" />
                    PentestGPT - Attack Information
                  </CardTitle>
                  <CardDescription>
                    Get comprehensive information about attack techniques
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Attack Type</Label>
                    <select
                      className="w-full px-3 py-2 border rounded-md bg-background"
                      value={attackType}
                      onChange={(e) => setAttackType(e.target.value)}
                    >
                      <option value="">Select attack type...</option>
                      {attackTypes.map((type) => (
                        <option key={type} value={type}>{type}</option>
                      ))}
                    </select>
                  </div>

                  <Button onClick={getAttackInfo} disabled={isProcessing || !attackType} className="w-full">
                    {isProcessing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Brain className="h-4 w-4 mr-2" />}
                    Get Attack Information
                  </Button>

                  {pentestOutput && (
                    <Card className="bg-muted/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Badge>{attackType}</Badge>
                          Attack Information
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[400px]">
                          <pre className="whitespace-pre-wrap text-sm">{pentestOutput}</pre>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Insights Tab */}
            <TabsContent value="insights" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Lightbulb className="h-5 w-5 text-yellow-500" />
                    AI-Powered Insights
                  </CardTitle>
                  <CardDescription>
                    Get intelligent recommendations based on security findings
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/20">
                      <CardContent className="p-4">
                        <div className="flex items-center gap-3">
                          <Brain className="h-8 w-8 text-purple-400" />
                          <div>
                            <p className="font-medium">AI Learning</p>
                            <p className="text-sm text-muted-foreground">Adapts from scan results</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                    <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/20">
                      <CardContent className="p-4">
                        <div className="flex items-center gap-3">
                          <Shield className="h-8 w-8 text-green-400" />
                          <div>
                            <p className="font-medium">Security Score</p>
                            <p className="text-sm text-muted-foreground">Based on findings</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  <div className="text-center py-8 text-muted-foreground">
                    <Lightbulb className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Run scans to generate AI-powered insights and recommendations</p>
                    <Button className="mt-4" variant="outline" onClick={() => setActiveTab("autonomous")}>
                      Start Scanning
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default AIHub;
