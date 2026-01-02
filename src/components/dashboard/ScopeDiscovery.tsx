import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { useAILearning } from "@/hooks/useAILearning";
import { supabase } from "@/integrations/supabase/client";
import { 
  Target, 
  Globe, 
  Search, 
  Server, 
  Cloud, 
  Smartphone,
  Shield,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Plus,
  Trash2,
  RefreshCw,
  Database,
  Lock,
  GitBranch,
  Layers
} from "lucide-react";

interface ScopeAsset {
  id: string;
  type: 'domain' | 'ip' | 'wildcard' | 'cidr' | 'app';
  value: string;
  classification: 'web' | 'api' | 'mobile' | 'cloud' | 'infrastructure';
  status: 'in-scope' | 'out-of-scope' | 'pending';
  techStack?: string[];
  thirdParty?: boolean;
  environment?: 'prod' | 'staging' | 'dev';
  discoveredAt?: Date;
}

interface DiscoveryResult {
  subdomains: string[];
  technologies: string[];
  cloudAssets: string[];
  thirdPartyDeps: string[];
}

const ScopeDiscovery = () => {
  const { toast } = useToast();
  const { withLearning, lastAnalysis } = useAILearning();
  const [assets, setAssets] = useState<ScopeAsset[]>([]);
  const [newAsset, setNewAsset] = useState("");
  const [assetType, setAssetType] = useState<'domain' | 'ip' | 'wildcard' | 'cidr'>('domain');
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryProgress, setDiscoveryProgress] = useState(0);
  const [discoveryResults, setDiscoveryResults] = useState<DiscoveryResult | null>(null);
  const [autoExpand, setAutoExpand] = useState(true);
  const [scopeEnforcement, setScopeEnforcement] = useState(true);

  const addAsset = () => {
    if (!newAsset.trim()) {
      toast({ title: "Error", description: "Please enter an asset", variant: "destructive" });
      return;
    }

    const asset: ScopeAsset = {
      id: crypto.randomUUID(),
      type: assetType,
      value: newAsset.trim(),
      classification: 'web',
      status: 'in-scope',
      discoveredAt: new Date()
    };

    setAssets(prev => [...prev, asset]);
    setNewAsset("");
    toast({ title: "Asset Added", description: `${newAsset} added to scope` });
  };

  const removeAsset = (id: string) => {
    setAssets(prev => prev.filter(a => a.id !== id));
  };

  const toggleAssetStatus = (id: string) => {
    setAssets(prev => prev.map(a => 
      a.id === id 
        ? { ...a, status: a.status === 'in-scope' ? 'out-of-scope' : 'in-scope' }
        : a
    ));
  };

  const runScopeDiscovery = async () => {
    if (assets.length === 0) {
      toast({ title: "Error", description: "Add at least one asset to discover", variant: "destructive" });
      return;
    }

    setIsDiscovering(true);
    setDiscoveryProgress(0);

    const inScopeAssets = assets.filter(a => a.status === 'in-scope');

    try {
      const { result, analysis } = await withLearning(
        'scope-discovery',
        inScopeAssets[0]?.value || 'unknown',
        async () => {
          // Simulate discovery progress
          for (let i = 0; i <= 100; i += 10) {
            setDiscoveryProgress(i);
            await new Promise(r => setTimeout(r, 300));
          }

          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { 
              target: inScopeAssets.map(a => a.value).join(','),
              scanType: 'subdomain',
              options: { enumAll: true }
            }
          });

          if (error) throw error;

          const results: DiscoveryResult = {
            subdomains: data.findings?.filter((f: any) => f.name?.includes('Subdomain'))
              .map((f: any) => f.name.replace('Subdomain: ', '')) || [],
            technologies: data.findings?.filter((f: any) => f.name?.includes('Technology'))
              .map((f: any) => f.name.replace('Technology: ', '')) || [],
            cloudAssets: [],
            thirdPartyDeps: []
          };

          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { assetCount: inScopeAssets.length }
      );

      // Create discovered assets
      const newAssets: ScopeAsset[] = [];
      const findings = (result as any)?.findings || [];
      findings.forEach((f: any) => {
        if (f.name?.includes('Subdomain:')) {
          const subdomain = f.name.replace('Subdomain: ', '');
          newAssets.push({
            id: crypto.randomUUID(),
            type: 'domain',
            value: subdomain,
            classification: 'web',
            status: autoExpand ? 'in-scope' : 'pending',
            discoveredAt: new Date(),
            thirdParty: false
          });
        }
      });

      if (newAssets.length > 0) {
        setAssets(prev => [...prev, ...newAssets]);
      }

      toast({ 
        title: "Discovery Complete", 
        description: `Found ${newAssets.length} new assets` 
      });

    } catch (error: any) {
      toast({ title: "Discovery Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsDiscovering(false);
    }
  };

  const runTechFingerprinting = async () => {
    const inScopeAssets = assets.filter(a => a.status === 'in-scope');
    if (inScopeAssets.length === 0) return;

    setIsDiscovering(true);
    
    try {
      const { result } = await withLearning(
        'tech-fingerprint',
        inScopeAssets[0]?.value,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { 
              target: inScopeAssets[0]?.value,
              scanType: 'tech'
            }
          });
          if (error) throw error;
          return {
            findings: data.findings || [],
            output: data.output || '',
            success: true
          };
        },
        { type: 'fingerprinting' }
      );

      // Update assets with tech stack
      const findings = (result as any)?.findings || [];
      if (findings.length > 0) {
        const techs = findings
          .filter((f: any) => f.name?.includes('Technology:'))
          .map((f: any) => f.name.replace('Technology: ', ''));
        
        if (techs.length > 0) {
          setAssets(prev => prev.map(a => 
            a.id === inScopeAssets[0]?.id
              ? { ...a, techStack: techs }
              : a
          ));
        }
      }

      toast({ title: "Fingerprinting Complete" });
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setIsDiscovering(false);
    }
  };

  const getClassificationIcon = (c: string) => {
    switch(c) {
      case 'web': return <Globe className="h-4 w-4" />;
      case 'api': return <Server className="h-4 w-4" />;
      case 'mobile': return <Smartphone className="h-4 w-4" />;
      case 'cloud': return <Cloud className="h-4 w-4" />;
      default: return <Database className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Target className="h-6 w-6 text-primary" />
            <CardTitle>Autonomous Scope Discovery & Management</CardTitle>
          </div>
          <CardDescription>
            Target ingestion, automated enumeration, asset classification, and scope boundary enforcement
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs defaultValue="ingestion" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="ingestion">Target Ingestion</TabsTrigger>
          <TabsTrigger value="discovery">Auto Discovery</TabsTrigger>
          <TabsTrigger value="classification">Classification</TabsTrigger>
          <TabsTrigger value="guardrails">Guardrails</TabsTrigger>
        </TabsList>

        {/* Target Ingestion */}
        <TabsContent value="ingestion" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Add Target Assets</CardTitle>
              <CardDescription>Add domains, IPs, wildcards, or CIDR ranges</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <select 
                  value={assetType} 
                  onChange={(e) => setAssetType(e.target.value as any)}
                  className="w-32 p-2 border rounded-md bg-background"
                >
                  <option value="domain">Domain</option>
                  <option value="ip">IP Address</option>
                  <option value="wildcard">Wildcard</option>
                  <option value="cidr">CIDR Range</option>
                </select>
                <Input 
                  value={newAsset}
                  onChange={(e) => setNewAsset(e.target.value)}
                  placeholder={assetType === 'domain' ? 'example.com' : assetType === 'ip' ? '192.168.1.1' : assetType === 'wildcard' ? '*.example.com' : '10.0.0.0/24'}
                  className="flex-1"
                />
                <Button onClick={addAsset}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add
                </Button>
              </div>

              <div className="border-t pt-4">
                <Label className="mb-2 block">Bulk Import</Label>
                <Textarea 
                  placeholder="Paste multiple targets (one per line)&#10;example.com&#10;*.subdomain.com&#10;192.168.1.0/24"
                  rows={4}
                />
                <Button variant="outline" size="sm" className="mt-2">
                  Import Targets
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Scope Assets ({assets.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {assets.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No assets added yet. Add targets above to begin.</p>
                </div>
              ) : (
                <ScrollArea className="h-[300px]">
                  <div className="space-y-2">
                    {assets.map(asset => (
                      <Card key={asset.id} className={`p-3 ${
                        asset.status === 'in-scope' ? 'border-green-500/50' :
                        asset.status === 'out-of-scope' ? 'border-red-500/50' : 'border-yellow-500/50'
                      }`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {getClassificationIcon(asset.classification)}
                            <div>
                              <p className="font-medium">{asset.value}</p>
                              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                <Badge variant="outline" className="text-xs">{asset.type}</Badge>
                                {asset.techStack?.slice(0, 2).map(t => (
                                  <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                                ))}
                                {asset.environment && (
                                  <Badge variant="outline" className="text-xs">{asset.environment}</Badge>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleAssetStatus(asset.id)}
                            >
                              {asset.status === 'in-scope' ? (
                                <CheckCircle className="h-4 w-4 text-green-500" />
                              ) : (
                                <AlertTriangle className="h-4 w-4 text-red-500" />
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeAsset(asset.id)}
                            >
                              <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
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

        {/* Auto Discovery */}
        <TabsContent value="discovery" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Search className="h-5 w-5" />
                Automated Discovery
              </CardTitle>
              <CardDescription>
                Subdomain enumeration, technology fingerprinting, and asset expansion
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Switch checked={autoExpand} onCheckedChange={setAutoExpand} />
                  <Label>Auto-expand discovered assets to scope</Label>
                </div>
              </div>

              {isDiscovering && (
                <div className="space-y-2">
                  <Progress value={discoveryProgress} />
                  <p className="text-sm text-muted-foreground text-center">
                    Discovering assets... {discoveryProgress}%
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <Button onClick={runScopeDiscovery} disabled={isDiscovering || assets.length === 0}>
                  {isDiscovering ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
                  Subdomain Enum
                </Button>
                <Button onClick={runTechFingerprinting} disabled={isDiscovering || assets.length === 0} variant="outline">
                  <Layers className="h-4 w-4 mr-2" />
                  Tech Fingerprint
                </Button>
                <Button disabled={isDiscovering} variant="outline">
                  <Cloud className="h-4 w-4 mr-2" />
                  Cloud Discovery
                </Button>
                <Button disabled={isDiscovering} variant="outline">
                  <GitBranch className="h-4 w-4 mr-2" />
                  Third-Party Deps
                </Button>
              </div>

              {lastAnalysis && (
                <Card className="bg-primary/5 border-primary/20">
                  <CardContent className="p-4">
                    <p className="text-sm font-medium mb-1">AI Insight</p>
                    <p className="text-sm text-muted-foreground">{lastAnalysis.improvement_strategy}</p>
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Classification */}
        <TabsContent value="classification" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Asset Classification</CardTitle>
              <CardDescription>Categorize assets by type, environment, and risk</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card className="p-4 text-center">
                  <Globe className="h-8 w-8 mx-auto mb-2 text-blue-500" />
                  <p className="font-bold text-2xl">{assets.filter(a => a.classification === 'web').length}</p>
                  <p className="text-sm text-muted-foreground">Web Apps</p>
                </Card>
                <Card className="p-4 text-center">
                  <Server className="h-8 w-8 mx-auto mb-2 text-green-500" />
                  <p className="font-bold text-2xl">{assets.filter(a => a.classification === 'api').length}</p>
                  <p className="text-sm text-muted-foreground">APIs</p>
                </Card>
                <Card className="p-4 text-center">
                  <Cloud className="h-8 w-8 mx-auto mb-2 text-purple-500" />
                  <p className="font-bold text-2xl">{assets.filter(a => a.classification === 'cloud').length}</p>
                  <p className="text-sm text-muted-foreground">Cloud</p>
                </Card>
                <Card className="p-4 text-center">
                  <Smartphone className="h-8 w-8 mx-auto mb-2 text-orange-500" />
                  <p className="font-bold text-2xl">{assets.filter(a => a.classification === 'mobile').length}</p>
                  <p className="text-sm text-muted-foreground">Mobile</p>
                </Card>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Guardrails */}
        <TabsContent value="guardrails" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Scope Boundary Enforcement
              </CardTitle>
              <CardDescription>
                Prevent out-of-scope testing with automated guardrails
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-muted/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <Lock className="h-5 w-5 text-primary" />
                  <div>
                    <p className="font-medium">Scope Enforcement</p>
                    <p className="text-sm text-muted-foreground">Block operations on out-of-scope targets</p>
                  </div>
                </div>
                <Switch checked={scopeEnforcement} onCheckedChange={setScopeEnforcement} />
              </div>

              <div className="grid grid-cols-3 gap-4">
                <Card className="p-4 text-center border-green-500/50">
                  <CheckCircle className="h-6 w-6 mx-auto mb-2 text-green-500" />
                  <p className="text-2xl font-bold">{assets.filter(a => a.status === 'in-scope').length}</p>
                  <p className="text-sm text-muted-foreground">In Scope</p>
                </Card>
                <Card className="p-4 text-center border-red-500/50">
                  <AlertTriangle className="h-6 w-6 mx-auto mb-2 text-red-500" />
                  <p className="text-2xl font-bold">{assets.filter(a => a.status === 'out-of-scope').length}</p>
                  <p className="text-sm text-muted-foreground">Out of Scope</p>
                </Card>
                <Card className="p-4 text-center border-yellow-500/50">
                  <RefreshCw className="h-6 w-6 mx-auto mb-2 text-yellow-500" />
                  <p className="text-2xl font-bold">{assets.filter(a => a.status === 'pending').length}</p>
                  <p className="text-sm text-muted-foreground">Pending Review</p>
                </Card>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ScopeDiscovery;
