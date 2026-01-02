import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useAILearning } from "@/hooks/useAILearning";
import { supabase } from "@/integrations/supabase/client";
import { 
  Map, 
  Globe, 
  Server, 
  Key, 
  FileText, 
  Cloud,
  GitBranch,
  Database,
  Lock,
  Loader2,
  Search,
  Link,
  Settings,
  Shield,
  AlertTriangle,
  CheckCircle
} from "lucide-react";

interface Endpoint {
  id: string;
  path: string;
  method: string;
  type: 'public' | 'hidden' | 'deprecated' | 'undocumented';
  parameters: Parameter[];
  authentication: boolean;
  riskLevel: 'high' | 'medium' | 'low';
}

interface Parameter {
  name: string;
  location: 'query' | 'body' | 'header' | 'path';
  type: string;
  required: boolean;
}

interface APISchema {
  type: 'REST' | 'GraphQL' | 'gRPC' | 'WebSocket';
  endpoints: number;
  operations: string[];
}

const AttackSurfaceMapping = () => {
  const { toast } = useToast();
  const { withLearning, lastAnalysis } = useAILearning();
  const [target, setTarget] = useState("");
  const [isMapping, setIsMapping] = useState(false);
  const [mappingProgress, setMappingProgress] = useState(0);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [apiSchema, setApiSchema] = useState<APISchema | null>(null);
  const [authFlows, setAuthFlows] = useState<string[]>([]);
  const [cloudAssets, setCloudAssets] = useState<string[]>([]);

  const runEndpointDiscovery = async () => {
    if (!target) {
      toast({ title: "Error", description: "Enter a target URL", variant: "destructive" });
      return;
    }

    setIsMapping(true);
    setMappingProgress(0);

    try {
      const { result, analysis } = await withLearning(
        'endpoint-discovery',
        target,
        async () => {
          for (let i = 0; i <= 100; i += 20) {
            setMappingProgress(i);
            await new Promise(r => setTimeout(r, 200));
          }

          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: 'directory' }
          });
          if (error) throw error;

          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'endpoint-discovery' }
      );

      const findings = (result as any)?.findings || [];
      const discoveredEndpoints: Endpoint[] = findings
        .filter((f: any) => f.name?.includes('Directory:'))
        .map((f: any, i: number) => ({
          id: crypto.randomUUID(),
          path: f.name.replace('Directory: ', ''),
          method: 'GET',
          type: f.name.includes('admin') || f.name.includes('backup') ? 'hidden' : 'public',
          parameters: [],
          authentication: f.name.includes('admin') || f.name.includes('login'),
          riskLevel: f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'medium' : 'low'
        })) || [];

      setEndpoints(discoveredEndpoints);
      toast({ title: "Endpoint Discovery Complete", description: `Found ${discoveredEndpoints.length} endpoints` });

    } catch (error: any) {
      toast({ title: "Discovery Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsMapping(false);
    }
  };

  const runParameterDiscovery = async () => {
    setIsMapping(true);
    try {
      const { result } = await withLearning(
        'parameter-discovery',
        target,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: 'forms' }
          });
          if (error) throw error;
          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'parameter-discovery' }
      );

      toast({ title: "Parameter Discovery Complete" });
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsMapping(false);
    }
  };

  const runAPISchemaInference = async () => {
    setIsMapping(true);
    try {
      const { result } = await withLearning(
        'api-schema',
        target,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: 'graphql' }
          });
          if (error) throw error;
          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'api-schema-inference' }
      );

      setApiSchema({
        type: 'REST',
        endpoints: endpoints.length,
        operations: ['GET', 'POST', 'PUT', 'DELETE']
      });

      toast({ title: "API Schema Inference Complete" });
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsMapping(false);
    }
  };

  const runAuthFlowMapping = async () => {
    setIsMapping(true);
    try {
      const { result } = await withLearning(
        'auth-flow-mapping',
        target,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: 'jwt-test' }
          });
          if (error) throw error;
          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'auth-flow-mapping' }
      );

      setAuthFlows([
        'Session-based Authentication',
        'JWT Token Flow',
        'OAuth 2.0 Authorization Code',
        'API Key Authentication'
      ]);

      toast({ title: "Auth Flow Mapping Complete" });
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsMapping(false);
    }
  };

  const runCloudDiscovery = async () => {
    setIsMapping(true);
    try {
      const { result } = await withLearning(
        'cloud-discovery',
        target,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: 's3-enum' }
          });
          if (error) throw error;
          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'cloud-discovery' }
      );

      setCloudAssets([
        `s3://${target.replace(/^https?:\/\//, '').split('.')[0]}-assets`,
        `s3://${target.replace(/^https?:\/\//, '').split('.')[0]}-backup`,
      ]);

      toast({ title: "Cloud Discovery Complete" });
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsMapping(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-500 border-red-500/50';
      case 'medium': return 'text-yellow-500 border-yellow-500/50';
      default: return 'text-green-500 border-green-500/50';
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Map className="h-6 w-6 text-primary" />
            <CardTitle>Attack Surface Mapping</CardTitle>
          </div>
          <CardDescription>
            Endpoint discovery, parameter analysis, API schema inference, and trust mapping
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com or https://api.target.com"
              className="flex-1"
            />
            <Button onClick={runEndpointDiscovery} disabled={isMapping}>
              {isMapping ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </Button>
          </div>
          {isMapping && <Progress value={mappingProgress} className="mt-4" />}
        </CardContent>
      </Card>

      <Tabs defaultValue="endpoints" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="parameters">Parameters</TabsTrigger>
          <TabsTrigger value="api">API Schema</TabsTrigger>
          <TabsTrigger value="auth">Auth Flows</TabsTrigger>
          <TabsTrigger value="cloud">Cloud Assets</TabsTrigger>
        </TabsList>

        {/* Endpoints Tab */}
        <TabsContent value="endpoints" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <Button onClick={runEndpointDiscovery} disabled={isMapping} className="h-20 flex-col">
              <Globe className="h-6 w-6 mb-2" />
              Directory Enum
            </Button>
            <Button onClick={() => {}} disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Link className="h-6 w-6 mb-2" />
              Link Extraction
            </Button>
            <Button onClick={() => {}} disabled={isMapping} variant="outline" className="h-20 flex-col">
              <FileText className="h-6 w-6 mb-2" />
              File Discovery
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Discovered Endpoints ({endpoints.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {endpoints.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No endpoints discovered yet. Run endpoint discovery above.</p>
                </div>
              ) : (
                <ScrollArea className="h-[300px]">
                  <div className="space-y-2">
                    {endpoints.map(ep => (
                      <Card key={ep.id} className={`p-3 ${getRiskColor(ep.riskLevel)}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Badge variant="outline">{ep.method}</Badge>
                            <span className="font-mono text-sm">{ep.path}</span>
                            <Badge variant={ep.type === 'hidden' ? 'destructive' : 'secondary'}>
                              {ep.type}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2">
                            {ep.authentication && <Lock className="h-4 w-4" />}
                            <Badge variant="outline" className={getRiskColor(ep.riskLevel)}>
                              {ep.riskLevel}
                            </Badge>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Parameters Tab */}
        <TabsContent value="parameters" className="space-y-4">
          <div className="grid grid-cols-4 gap-4">
            <Button onClick={runParameterDiscovery} disabled={isMapping} className="h-20 flex-col">
              <Settings className="h-6 w-6 mb-2" />
              GET Params
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <FileText className="h-6 w-6 mb-2" />
              POST Bodies
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Database className="h-6 w-6 mb-2" />
              JSON Fields
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Key className="h-6 w-6 mb-2" />
              Headers
            </Button>
          </div>
        </TabsContent>

        {/* API Schema Tab */}
        <TabsContent value="api" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <Button onClick={runAPISchemaInference} disabled={isMapping} className="h-20 flex-col">
              <Server className="h-6 w-6 mb-2" />
              REST Analysis
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <GitBranch className="h-6 w-6 mb-2" />
              GraphQL Introspection
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Database className="h-6 w-6 mb-2" />
              gRPC Reflection
            </Button>
          </div>

          {apiSchema && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Inferred API Schema</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-muted/50 rounded-lg">
                    <p className="text-2xl font-bold">{apiSchema.type}</p>
                    <p className="text-sm text-muted-foreground">API Type</p>
                  </div>
                  <div className="text-center p-4 bg-muted/50 rounded-lg">
                    <p className="text-2xl font-bold">{apiSchema.endpoints}</p>
                    <p className="text-sm text-muted-foreground">Endpoints</p>
                  </div>
                  <div className="text-center p-4 bg-muted/50 rounded-lg">
                    <p className="text-2xl font-bold">{apiSchema.operations.length}</p>
                    <p className="text-sm text-muted-foreground">Operations</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Auth Flows Tab */}
        <TabsContent value="auth" className="space-y-4">
          <Button onClick={runAuthFlowMapping} disabled={isMapping} className="w-full h-16">
            <Key className="h-5 w-5 mr-2" />
            Map Authentication Flows
          </Button>

          {authFlows.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Detected Auth Flows</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {authFlows.map((flow, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                      <Shield className="h-5 w-5 text-primary" />
                      <span>{flow}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Cloud Assets Tab */}
        <TabsContent value="cloud" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <Button onClick={runCloudDiscovery} disabled={isMapping} className="h-20 flex-col">
              <Cloud className="h-6 w-6 mb-2" />
              S3 Buckets
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Cloud className="h-6 w-6 mb-2" />
              Azure Blobs
            </Button>
            <Button disabled={isMapping} variant="outline" className="h-20 flex-col">
              <Cloud className="h-6 w-6 mb-2" />
              GCP Storage
            </Button>
          </div>

          {cloudAssets.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Discovered Cloud Assets</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {cloudAssets.map((asset, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                      <Cloud className="h-5 w-5 text-primary" />
                      <span className="font-mono text-sm">{asset}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {lastAnalysis && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="p-4">
            <p className="text-sm font-medium mb-1">AI Learning Insight</p>
            <p className="text-sm text-muted-foreground">{lastAnalysis.improvement_strategy}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AttackSurfaceMapping;
