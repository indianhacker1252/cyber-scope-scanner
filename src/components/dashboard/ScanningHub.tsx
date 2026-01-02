import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAILearning } from "@/hooks/useAILearning";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { 
  Search, 
  Network, 
  Globe, 
  Shield,
  Server,
  Wifi,
  FileText,
  Loader2,
  CheckCircle,
  XCircle,
  Play,
  Database,
  Lock,
  AlertTriangle
} from "lucide-react";

interface ScanResult {
  id: string;
  type: string;
  status: 'running' | 'completed' | 'failed';
  output: string;
  findings: any[];
  timestamp: Date;
}

const ScanningHub = () => {
  const { toast } = useToast();
  const { withLearning, getRecommendations, lastAnalysis } = useAILearning();
  const [activeTab, setActiveTab] = useState("recon");
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("basic");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [currentOutput, setCurrentOutput] = useState("");
  const [aiRecommendation, setAiRecommendation] = useState<string>("");

  const runScan = async (scanName: string, scanAction: string) => {
    if (!target) {
      toast({ title: "Error", description: "Please enter a target", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setCurrentOutput(`Starting ${scanName} on ${target}...\n`);

    const newResult: ScanResult = {
      id: crypto.randomUUID(),
      type: scanName,
      status: 'running',
      output: '',
      findings: [],
      timestamp: new Date()
    };
    setScanResults(prev => [newResult, ...prev]);

    try {
      // Use AI learning wrapper for automatic learning
      const { result, analysis } = await withLearning<{ findings: any[]; output: string; success: boolean }>(
        scanAction,
        target,
        async () => {
          const { data, error } = await supabase.functions.invoke('security-scan', {
            body: { target, scanType: scanAction, options: { intensity: scanType } }
          });
          if (error) throw error;
          return {
            findings: data.findings || data.vulnerabilities || [],
            output: data.output || data.results || JSON.stringify(data, null, 2),
            success: true
          };
        },
        { scanType, intensity: scanType }
      );

      if (result) {
        const scanOutput = result.output || '';
        const scanFindings = result.findings || [];
        
        setCurrentOutput(prev => prev + `\n${scanOutput}\n\n✅ Scan completed. AI Learning recorded.`);
        if (analysis?.improvement_strategy) {
          setCurrentOutput(prev => prev + `\n🤖 AI Insight: ${analysis.improvement_strategy}`);
        }
        
        setScanResults(prev => prev.map(r => 
          r.id === newResult.id 
            ? { ...r, status: 'completed', output: scanOutput, findings: scanFindings }
            : r
        ));

        toast({ title: `${scanName} Complete`, description: `Found ${scanFindings.length} items` });
      }
    } catch (error: any) {
      setCurrentOutput(prev => prev + `\nError: ${error.message}`);
      
      setScanResults(prev => prev.map(r => 
        r.id === newResult.id 
          ? { ...r, status: 'failed', output: error.message }
          : r
      ));

      toast({ title: "Scan Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsScanning(false);
    }
  };

  const ScanCard = ({ 
    title, 
    description, 
    icon: Icon, 
    scanAction,
    disabled = false 
  }: { 
    title: string; 
    description: string; 
    icon: any; 
    scanAction: string;
    disabled?: boolean;
  }) => (
    <Card 
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${disabled ? 'opacity-50' : ''}`}
      onClick={() => !disabled && runScan(title, scanAction)}
    >
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          {isScanning ? (
            <Loader2 className="h-5 w-5 text-primary animate-spin" />
          ) : (
            <Icon className="h-5 w-5 text-primary" />
          )}
          <div>
            <p className="font-medium">{title}</p>
            <p className="text-sm text-muted-foreground">{description}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Search className="h-6 w-6 text-primary" />
            <CardTitle>Security Scanning Hub</CardTitle>
          </div>
          <CardDescription>
            Comprehensive scanning suite for reconnaissance, network, and web security testing
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Target Input */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="md:col-span-2 space-y-2">
              <Label>Target</Label>
              <Input
                placeholder="example.com, 192.168.1.1, or 10.0.0.0/24"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Scan Intensity</Label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="basic">Basic (Fast)</SelectItem>
                  <SelectItem value="standard">Standard</SelectItem>
                  <SelectItem value="aggressive">Aggressive (Slow)</SelectItem>
                  <SelectItem value="stealth">Stealth Mode</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="recon" className="flex items-center gap-1">
                <Search className="h-4 w-4" />
                Recon
              </TabsTrigger>
              <TabsTrigger value="network" className="flex items-center gap-1">
                <Network className="h-4 w-4" />
                Network
              </TabsTrigger>
              <TabsTrigger value="web" className="flex items-center gap-1">
                <Globe className="h-4 w-4" />
                Web
              </TabsTrigger>
              <TabsTrigger value="vuln" className="flex items-center gap-1">
                <Shield className="h-4 w-4" />
                Vulns
              </TabsTrigger>
              <TabsTrigger value="results" className="flex items-center gap-1">
                <FileText className="h-4 w-4" />
                Results
              </TabsTrigger>
            </TabsList>

            {/* Reconnaissance Tab */}
            <TabsContent value="recon" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <ScanCard 
                  title="DNS Lookup" 
                  description="A, AAAA, MX, TXT, NS records" 
                  icon={Server} 
                  scanAction="dns"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="WHOIS Info" 
                  description="Domain registration details" 
                  icon={Globe} 
                  scanAction="whois"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="SSL Certificate" 
                  description="Certificate transparency" 
                  icon={Lock} 
                  scanAction="ssl"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Subdomain Enum" 
                  description="Find subdomains" 
                  icon={Search} 
                  scanAction="subdomain"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Technology Stack" 
                  description="Identify technologies" 
                  icon={Database} 
                  scanAction="tech"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Email Harvesting" 
                  description="Public email addresses" 
                  icon={FileText} 
                  scanAction="email"
                  disabled={isScanning}
                />
              </div>
            </TabsContent>

            {/* Network Tab */}
            <TabsContent value="network" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <ScanCard 
                  title="Port Scan" 
                  description="TCP/UDP port discovery" 
                  icon={Network} 
                  scanAction="port"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Host Discovery" 
                  description="Find active hosts" 
                  icon={Server} 
                  scanAction="host"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Service Enum" 
                  description="Identify running services" 
                  icon={Shield} 
                  scanAction="service"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="OS Detection" 
                  description="Operating system fingerprint" 
                  icon={Wifi} 
                  scanAction="os"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Traceroute" 
                  description="Network path analysis" 
                  icon={Network} 
                  scanAction="traceroute"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Banner Grab" 
                  description="Service banners" 
                  icon={FileText} 
                  scanAction="banner"
                  disabled={isScanning}
                />
              </div>
            </TabsContent>

            {/* Web Tab */}
            <TabsContent value="web" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <ScanCard 
                  title="Directory Enum" 
                  description="Find hidden directories" 
                  icon={FileText} 
                  scanAction="directory"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Web Crawl" 
                  description="Crawl and map site" 
                  icon={Globe} 
                  scanAction="crawl"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Header Analysis" 
                  description="Security headers check" 
                  icon={Shield} 
                  scanAction="headers"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Cookie Analysis" 
                  description="Check cookie security" 
                  icon={Lock} 
                  scanAction="cookies"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Form Analysis" 
                  description="Find and analyze forms" 
                  icon={Database} 
                  scanAction="forms"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Link Extraction" 
                  description="Extract all links" 
                  icon={Search} 
                  scanAction="links"
                  disabled={isScanning}
                />
              </div>
            </TabsContent>

            {/* Vulnerability Tab */}
            <TabsContent value="vuln" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <ScanCard 
                  title="SQL Injection" 
                  description="Test for SQLi vulnerabilities" 
                  icon={Database} 
                  scanAction="sqli"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="XSS Detection" 
                  description="Cross-site scripting tests" 
                  icon={AlertTriangle} 
                  scanAction="xss"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="CSRF Check" 
                  description="CSRF protection analysis" 
                  icon={Shield} 
                  scanAction="csrf"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="LFI/RFI Test" 
                  description="File inclusion tests" 
                  icon={FileText} 
                  scanAction="lfi"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="SSRF Detection" 
                  description="Server-side request forgery" 
                  icon={Server} 
                  scanAction="ssrf"
                  disabled={isScanning}
                />
                <ScanCard 
                  title="Full Vuln Scan" 
                  description="Comprehensive vulnerability scan" 
                  icon={Shield} 
                  scanAction="full"
                  disabled={isScanning}
                />
              </div>
            </TabsContent>

            {/* Results Tab */}
            <TabsContent value="results" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Scan Output</CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px] border rounded-lg p-4 bg-muted/30 font-mono text-sm">
                    <pre className="whitespace-pre-wrap">
                      {currentOutput || 'No scan output yet. Run a scan to see results here.'}
                    </pre>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Scan History</CardTitle>
                </CardHeader>
                <CardContent>
                  {scanResults.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No scans yet. Start by running a scan above.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[300px]">
                      <div className="space-y-2">
                        {scanResults.map((result) => (
                          <Card key={result.id} className={`p-3 ${
                            result.status === 'completed' ? 'border-green-500/50' :
                            result.status === 'failed' ? 'border-red-500/50' : 'border-yellow-500/50'
                          }`}>
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {result.status === 'completed' && <CheckCircle className="h-4 w-4 text-green-500" />}
                                {result.status === 'failed' && <XCircle className="h-4 w-4 text-red-500" />}
                                {result.status === 'running' && <Loader2 className="h-4 w-4 text-yellow-500 animate-spin" />}
                                <span className="font-medium">{result.type}</span>
                                <Badge variant="outline">{target}</Badge>
                              </div>
                              <span className="text-xs text-muted-foreground">
                                {result.timestamp.toLocaleTimeString()}
                              </span>
                            </div>
                            {result.findings.length > 0 && (
                              <p className="text-sm text-muted-foreground mt-1">
                                {result.findings.length} findings
                              </p>
                            )}
                          </Card>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ScanningHub;
