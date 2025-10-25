import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { 
  Search, 
  Globe, 
  Server, 
  FileText,
  Users,
  Mail,
  Loader2,
  CheckCircle,
  XCircle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import { RealKaliToolsManager } from "@/utils/realKaliTools";

interface ReconnaissanceProps {
  onNavigateToResults?: () => void;
}

interface ScanState {
  isRunning: boolean;
  output: string;
  findings: any[];
  status: 'idle' | 'running' | 'completed' | 'failed';
}

const Reconnaissance = ({ onNavigateToResults }: ReconnaissanceProps) => {
  const [domain, setDomain] = useState("");
  const { toast } = useToast();
  const toolsManager = RealKaliToolsManager.getInstance();

  const [dnsState, setDnsState] = useState<ScanState>({
    isRunning: false,
    output: '',
    findings: [],
    status: 'idle'
  });

  const [whoisState, setWhoisState] = useState<ScanState>({
    isRunning: false,
    output: '',
    findings: [],
    status: 'idle'
  });

  const [sslState, setSslState] = useState<ScanState>({
    isRunning: false,
    output: '',
    findings: [],
    status: 'idle'
  });

  const [subdomainState, setSubdomainState] = useState<ScanState>({
    isRunning: false,
    output: '',
    findings: [],
    status: 'idle'
  });

  const handleDNSLookup = async () => {
    if (!domain) {
      toast({
        title: "Error",
        description: "Please enter a domain",
        variant: "destructive"
      });
      return;
    }

    setDnsState({ isRunning: true, output: '', findings: [], status: 'running' });

    try {
      await toolsManager.runDNSLookup(domain, {
        onOutput: (data) => {
          setDnsState(prev => ({ ...prev, output: prev.output + data }));
        },
        onComplete: (result) => {
          setDnsState({
            isRunning: false,
            output: result.output || '',
            findings: result.findings || [],
            status: 'completed'
          });
          toast({
            title: "DNS Lookup Complete",
            description: `Found ${result.findings?.length || 0} DNS records`
          });
        },
        onError: (error) => {
          setDnsState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
          toast({
            title: "DNS Lookup Failed",
            description: error,
            variant: "destructive"
          });
        }
      });
    } catch (error: any) {
      setDnsState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleWhoisLookup = async () => {
    if (!domain) {
      toast({
        title: "Error",
        description: "Please enter a domain",
        variant: "destructive"
      });
      return;
    }

    setWhoisState({ isRunning: true, output: '', findings: [], status: 'running' });

    try {
      await toolsManager.runWhoisLookup(domain, {
        onOutput: (data) => {
          setWhoisState(prev => ({ ...prev, output: prev.output + data }));
        },
        onComplete: (result) => {
          setWhoisState({
            isRunning: false,
            output: result.output || '',
            findings: result.findings || [],
            status: 'completed'
          });
          toast({
            title: "WHOIS Lookup Complete",
            description: "Registration details retrieved"
          });
        },
        onError: (error) => {
          setWhoisState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
          toast({
            title: "WHOIS Lookup Failed",
            description: error,
            variant: "destructive"
          });
        }
      });
    } catch (error: any) {
      setWhoisState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleSSLAnalysis = async () => {
    if (!domain) {
      toast({
        title: "Error",
        description: "Please enter a domain",
        variant: "destructive"
      });
      return;
    }

    setSslState({ isRunning: true, output: '', findings: [], status: 'running' });

    try {
      await toolsManager.runSSLAnalysis(domain, {
        onOutput: (data) => {
          setSslState(prev => ({ ...prev, output: prev.output + data }));
        },
        onComplete: (result) => {
          setSslState({
            isRunning: false,
            output: result.output || '',
            findings: result.findings || [],
            status: 'completed'
          });
          toast({
            title: "SSL Analysis Complete",
            description: `Found ${result.findings?.length || 0} certificate details`
          });
        },
        onError: (error) => {
          setSslState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
          toast({
            title: "SSL Analysis Failed",
            description: error,
            variant: "destructive"
          });
        }
      });
    } catch (error: any) {
      setSslState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleSubdomainEnum = async () => {
    if (!domain) {
      toast({
        title: "Error",
        description: "Please enter a domain",
        variant: "destructive"
      });
      return;
    }

    setSubdomainState({ isRunning: true, output: '', findings: [], status: 'running' });

    try {
      await toolsManager.runAmassEnum(domain, {
        onOutput: (data) => {
          setSubdomainState(prev => ({ ...prev, output: prev.output + data }));
        },
        onComplete: (result) => {
          setSubdomainState({
            isRunning: false,
            output: result.output || '',
            findings: result.findings || [],
            status: 'completed'
          });
          toast({
            title: "Subdomain Enumeration Complete",
            description: `Found ${result.findings?.length || 0} subdomains`
          });
          if (onNavigateToResults) {
            setTimeout(() => onNavigateToResults(), 1000);
          }
        },
        onError: (error) => {
          setSubdomainState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
          toast({
            title: "Subdomain Enumeration Failed",
            description: error,
            variant: "destructive"
          });
        }
      });
    } catch (error: any) {
      setSubdomainState(prev => ({ ...prev, isRunning: false, status: 'failed' }));
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const renderResults = (state: ScanState) => {
    if (state.status === 'idle') {
      return null;
    }

    return (
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center text-sm">
            {state.status === 'running' && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {state.status === 'completed' && <CheckCircle className="h-4 w-4 mr-2 text-success" />}
            {state.status === 'failed' && <XCircle className="h-4 w-4 mr-2 text-destructive" />}
            Results {state.isRunning ? '(Running...)' : ''}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {state.findings.length > 0 && (
            <div className="space-y-2 mb-4">
              <h4 className="text-sm font-medium">Findings ({state.findings.length})</h4>
              <div className="space-y-1">
                {state.findings.map((finding, idx) => (
                  <div key={idx} className="flex items-start text-sm p-2 bg-muted/50 rounded">
                    <Badge className="mr-2" variant="outline">{finding.type}</Badge>
                    <span className="flex-1">{finding.description || finding.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <ScrollArea className="h-48 border rounded p-2 bg-muted/30 font-mono text-xs">
            <pre className="whitespace-pre-wrap">{state.output || 'No output yet...'}</pre>
          </ScrollArea>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Search className="h-5 w-5 mr-2 text-primary" />
            Reconnaissance & OSINT
          </CardTitle>
          <CardDescription>
            Gather intelligence about targets using open source intelligence
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="domain" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="domain">Domain Intel</TabsTrigger>
              <TabsTrigger value="subdomain">Subdomains</TabsTrigger>
              <TabsTrigger value="social">Social Media</TabsTrigger>
              <TabsTrigger value="metadata">Metadata</TabsTrigger>
            </TabsList>

            <TabsContent value="domain" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="domain-input">Target Domain</Label>
                  <div className="flex space-x-2">
                    <Input
                      id="domain-input"
                      placeholder="example.com"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={handleDNSLookup}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        {dnsState.isRunning ? (
                          <Loader2 className="h-5 w-5 text-primary animate-spin" />
                        ) : (
                          <Server className="h-5 w-5 text-primary" />
                        )}
                        <div>
                          <p className="font-medium">DNS Records</p>
                          <p className="text-sm text-muted-foreground">A, AAAA, MX, TXT, NS</p>
                          {dnsState.status === 'completed' && (
                            <Badge className="mt-1" variant="outline">{dnsState.findings.length} records</Badge>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={handleWhoisLookup}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        {whoisState.isRunning ? (
                          <Loader2 className="h-5 w-5 text-primary animate-spin" />
                        ) : (
                          <Globe className="h-5 w-5 text-primary" />
                        )}
                        <div>
                          <p className="font-medium">WHOIS Info</p>
                          <p className="text-sm text-muted-foreground">Registration details</p>
                          {whoisState.status === 'completed' && (
                            <Badge className="mt-1" variant="outline">Complete</Badge>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={handleSSLAnalysis}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        {sslState.isRunning ? (
                          <Loader2 className="h-5 w-5 text-primary animate-spin" />
                        ) : (
                          <FileText className="h-5 w-5 text-primary" />
                        )}
                        <div>
                          <p className="font-medium">SSL Certificate</p>
                          <p className="text-sm text-muted-foreground">Certificate transparency</p>
                          {sslState.status === 'completed' && (
                            <Badge className="mt-1" variant="outline">{sslState.findings.length} details</Badge>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {renderResults(dnsState)}
                {renderResults(whoisState)}
                {renderResults(sslState)}
              </div>
            </TabsContent>

            <TabsContent value="subdomain" className="space-y-4">
              <div className="space-y-4">
                <div className="text-center p-8">
                  <Search className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">Subdomain Enumeration</p>
                  <p className="text-muted-foreground mb-4">
                    Discover subdomains using passive and active techniques
                  </p>
                  <Button onClick={handleSubdomainEnum} disabled={subdomainState.isRunning}>
                    {subdomainState.isRunning ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4 mr-2" />
                    )}
                    {subdomainState.isRunning ? 'Scanning...' : 'Start Subdomain Scan'}
                  </Button>
                </div>

                {renderResults(subdomainState)}
              </div>
            </TabsContent>

            <TabsContent value="social" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                  toast({
                    title: "Social Media Intelligence",
                    description: "This feature requires manual OSINT gathering",
                  });
                }}>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Users className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Employee Search</p>
                        <p className="text-sm text-muted-foreground">LinkedIn, GitHub profiles</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                  toast({
                    title: "Email Harvesting",
                    description: "This feature requires theHarvester tool",
                  });
                }}>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Mail className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Email Harvesting</p>
                        <p className="text-sm text-muted-foreground">Public email addresses</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="metadata" className="space-y-4">
              <div className="text-center p-8">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Metadata Analysis</p>
                <p className="text-muted-foreground mb-4">
                  Extract metadata from documents and files
                </p>
                <Button onClick={() => {
                  toast({
                    title: "Metadata Extraction",
                    description: "This feature requires exiftool",
                  });
                }}>
                  <FileText className="h-4 w-4 mr-2" />
                  Analyze Metadata
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default Reconnaissance;