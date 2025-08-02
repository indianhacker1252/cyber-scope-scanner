import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { 
  Settings, 
  Download, 
  Play, 
  Pause,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  Terminal,
  Key,
  Zap
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import OpenAIService from "@/utils/openaiService";

const ToolManagement = () => {
  const [tools, setTools] = useState([
    { name: "Nmap", version: "7.94", status: "active", category: "Network" },
    { name: "Nikto", version: "2.5.0", status: "active", category: "Web" },
    { name: "SQLMap", version: "1.7.2", status: "active", category: "Database" },
    { name: "Gobuster", version: "3.6", status: "inactive", category: "Discovery" },
    { name: "Burp Suite", version: "2023.10", status: "active", category: "Web" },
    { name: "OWASP ZAP", version: "2.14.0", status: "active", category: "Web" },
  ]);
  const [apiKey, setApiKey] = useState(OpenAIService.getApiKey() || '');
  const [vulnerabilityType, setVulnerabilityType] = useState('');
  const [payloadTarget, setPayloadTarget] = useState('');
  const [generatedPayloads, setGeneratedPayloads] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const { toast } = useToast();

  const getStatusIcon = (status: string) => {
    return status === "active" ? CheckCircle : AlertCircle;
  };

  const getStatusColor = (status: string) => {
    return status === "active" ? "text-success" : "text-warning";
  };

  const handleToolToggle = (index: number) => {
    setTools(prev => prev.map((tool, i) => 
      i === index 
        ? { ...tool, status: tool.status === "active" ? "inactive" : "active" }
        : tool
    ));
    
    const tool = tools[index];
    toast({
      title: `${tool.name} ${tool.status === "active" ? "Stopped" : "Started"}`,
      description: `Tool status updated successfully`
    });
  };

  const handleToolConfigure = (toolName: string) => {
    toast({
      title: "Configuration",
      description: `Opening configuration for ${toolName}...`
    });
  };

  const handleApiKeyUpdate = () => {
    if (!apiKey.trim()) {
      toast({
        title: "Error",
        description: "Please enter a valid API key",
        variant: "destructive"
      });
      return;
    }
    
    OpenAIService.setApiKey(apiKey);
    toast({
      title: "API Key Updated",
      description: "ChatGPT integration is now configured"
    });
  };

  const generatePayloads = async () => {
    if (!OpenAIService.hasApiKey()) {
      toast({
        title: "API Key Required",
        description: "Please configure your OpenAI API key first",
        variant: "destructive"
      });
      return;
    }

    if (!vulnerabilityType.trim() || !payloadTarget.trim()) {
      toast({
        title: "Missing Information",
        description: "Please specify vulnerability type and target",
        variant: "destructive"
      });
      return;
    }

    setIsGenerating(true);
    try {
      const payloads = await OpenAIService.generatePayloads(vulnerabilityType, payloadTarget);
      setGeneratedPayloads(payloads);
      toast({
        title: "Payloads Generated",
        description: "Latest payloads have been generated successfully"
      });
    } catch (error: any) {
      toast({
        title: "Generation Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Settings className="h-5 w-5 mr-2 text-primary" />
            Security Tool Management
          </CardTitle>
          <CardDescription>
            Manage and configure security testing tools and frameworks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="tools" className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="tools">Installed Tools</TabsTrigger>
              <TabsTrigger value="chatgpt">ChatGPT AI</TabsTrigger>
              <TabsTrigger value="marketplace">Marketplace</TabsTrigger>
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="updates">Updates</TabsTrigger>
            </TabsList>

            <TabsContent value="tools" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {tools.map((tool, index) => {
                  const StatusIcon = getStatusIcon(tool.status);
                  return (
                    <Card key={index}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <Terminal className="h-6 w-6 text-primary" />
                            <div>
                              <h4 className="font-medium">{tool.name}</h4>
                              <p className="text-sm text-muted-foreground">Version {tool.version}</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3">
                            <Badge variant="outline">{tool.category}</Badge>
                            <StatusIcon className={`h-5 w-5 ${getStatusColor(tool.status)}`} />
                            <div className="space-x-2">
                              {tool.status === "active" ? (
                                <Button 
                                  size="sm" 
                                  variant="outline"
                                  onClick={() => handleToolToggle(index)}
                                >
                                  <Pause className="h-4 w-4 mr-1" />
                                  Stop
                                </Button>
                              ) : (
                                <Button 
                                  size="sm"
                                  onClick={() => handleToolToggle(index)}
                                >
                                  <Play className="h-4 w-4 mr-1" />
                                  Start
                                </Button>
                              )}
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => handleToolConfigure(tool.name)}
                              >
                                <Settings className="h-4 w-4 mr-1" />
                                Configure
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="chatgpt" className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* API Configuration */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Key className="h-5 w-5 mr-2" />
                      API Configuration
                    </CardTitle>
                    <CardDescription>
                      Configure your OpenAI API key for AI-powered analysis
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <Label htmlFor="apiKey">OpenAI API Key</Label>
                      <Input
                        id="apiKey"
                        type="password"
                        placeholder="sk-..."
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                      />
                    </div>
                    <Button onClick={handleApiKeyUpdate} className="w-full">
                      <Key className="h-4 w-4 mr-2" />
                      Update API Key
                    </Button>
                    {OpenAIService.hasApiKey() && (
                      <div className="text-sm text-green-600 flex items-center">
                        <CheckCircle className="h-4 w-4 mr-1" />
                        API Key Configured
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Payload Generator */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Zap className="h-5 w-5 mr-2" />
                      Latest Payload Generator
                    </CardTitle>
                    <CardDescription>
                      Generate cutting-edge payloads for vulnerability testing
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <Label htmlFor="vulnType">Vulnerability Type</Label>
                      <Input
                        id="vulnType"
                        placeholder="e.g., SQL Injection, XSS, RCE"
                        value={vulnerabilityType}
                        onChange={(e) => setVulnerabilityType(e.target.value)}
                      />
                    </div>
                    <div>
                      <Label htmlFor="target">Target</Label>
                      <Input
                        id="target"
                        placeholder="e.g., http://example.com/login.php"
                        value={payloadTarget}
                        onChange={(e) => setPayloadTarget(e.target.value)}
                      />
                    </div>
                    <Button 
                      onClick={generatePayloads} 
                      className="w-full"
                      disabled={isGenerating}
                    >
                      {isGenerating ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Zap className="h-4 w-4 mr-2" />
                      )}
                      Generate Payloads
                    </Button>
                  </CardContent>
                </Card>
              </div>

              {/* Generated Payloads Display */}
              {generatedPayloads && (
                <Card>
                  <CardHeader>
                    <CardTitle>Generated Payloads</CardTitle>
                    <CardDescription>
                      Latest AI-generated payloads for testing
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Textarea
                      value={generatedPayloads}
                      readOnly
                      className="min-h-[300px] font-mono text-sm"
                      placeholder="Generated payloads will appear here..."
                    />
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="marketplace" className="space-y-4">
              <div className="text-center p-8">
                <Download className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Tool Marketplace</p>
                <p className="text-muted-foreground">
                  Browse and install additional security testing tools
                </p>
              </div>
            </TabsContent>

            <TabsContent value="config" className="space-y-4">
              <div className="text-center p-8">
                <Settings className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Global Configuration</p>
                <p className="text-muted-foreground">
                  Configure global settings for all security tools
                </p>
              </div>
            </TabsContent>

            <TabsContent value="updates" className="space-y-4">
              <div className="text-center p-8">
                <RefreshCw className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Tool Updates</p>
                <p className="text-muted-foreground">
                  Check for and install tool updates and security patches
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ToolManagement;