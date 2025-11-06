import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { RealKaliToolsManager } from "@/utils/realKaliTools";
import { 
  Globe, Search, Link, Shield, FileSearch, Zap, 
  GitBranch, Key, Lock, Target, Database, Network,
  AlertCircle, CheckCircle2, Loader2
} from "lucide-react";

export function WebHackersWeapons() {
  const { toast } = useToast();
  const toolsManager = RealKaliToolsManager.getInstance();

  // Tool states
  const [subfinderDomain, setSubfinderDomain] = useState('');
  const [httpxTarget, setHttpxTarget] = useState('');
  const [katanaUrl, setKatanaUrl] = useState('');
  const [dalfoxUrl, setDalfoxUrl] = useState('');
  const [gauDomain, setGauDomain] = useState('');
  const [ffufUrl, setFfufUrl] = useState('');
  const [arjunUrl, setArjunUrl] = useState('');
  const [paramspiderDomain, setParamspiderDomain] = useState('');
  const [waybackDomain, setWaybackDomain] = useState('');
  const [hakrawlerUrl, setHakrawlerUrl] = useState('');
  const [assetfinderDomain, setAssetfinderDomain] = useState('');
  const [linkfinderUrl, setLinkfinderUrl] = useState('');
  const [secretfinderUrl, setSecretfinderUrl] = useState('');
  const [gitleaksRepo, setGitleaksRepo] = useState('');
  const [rustscanTarget, setRustscanTarget] = useState('');

  const [output, setOutput] = useState('');
  const [isRunning, setIsRunning] = useState(false);

  const handleToolRun = async (
    toolName: string,
    toolFunction: () => Promise<any>,
    successMessage: string
  ) => {
    setIsRunning(true);
    setOutput('');
    
    try {
      const result = await toolFunction();
      setOutput(result);
      toast({
        title: "Success",
        description: successMessage,
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
      setOutput(`Error: ${error.message}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-6 w-6" />
              WebHackersWeapons Arsenal
            </CardTitle>
            <CardDescription>
              Modern pentesting tools from the WebHackersWeapons collection
            </CardDescription>
          </div>
          <Badge variant="outline" className="text-lg px-4 py-2">
            15 Tools
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="recon" className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="recon">Reconnaissance</TabsTrigger>
            <TabsTrigger value="crawling">Crawling</TabsTrigger>
            <TabsTrigger value="fuzzing">Fuzzing</TabsTrigger>
            <TabsTrigger value="scanning">Scanning</TabsTrigger>
            <TabsTrigger value="secrets">Secrets</TabsTrigger>
          </TabsList>

          {/* Reconnaissance Tools */}
          <TabsContent value="recon" className="space-y-4">
            {/* Subfinder */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Subfinder - Fast Subdomain Enumeration
                </CardTitle>
                <CardDescription>
                  Passive subdomain discovery using multiple sources
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="subfinder-domain">Target Domain</Label>
                  <Input
                    id="subfinder-domain"
                    placeholder="example.com"
                    value={subfinderDomain}
                    onChange={(e) => setSubfinderDomain(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'subfinder',
                    () => toolsManager.runSubfinderScan(subfinderDomain),
                    'Subfinder scan completed'
                  )}
                  disabled={isRunning || !subfinderDomain}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                  Enumerate Subdomains
                </Button>
              </CardContent>
            </Card>

            {/* Assetfinder */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Assetfinder - Asset Discovery
                </CardTitle>
                <CardDescription>
                  Find domains and subdomains related to a target
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="assetfinder-domain">Target Domain</Label>
                  <Input
                    id="assetfinder-domain"
                    placeholder="example.com"
                    value={assetfinderDomain}
                    onChange={(e) => setAssetfinderDomain(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'assetfinder',
                    () => toolsManager.runAssetfinderScan(assetfinderDomain),
                    'Asset discovery completed'
                  )}
                  disabled={isRunning || !assetfinderDomain}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Database className="mr-2 h-4 w-4" />}
                  Discover Assets
                </Button>
              </CardContent>
            </Card>

            {/* GAU - GetAllUrls */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Link className="h-5 w-5" />
                  GAU - Get All URLs
                </CardTitle>
                <CardDescription>
                  Fetch URLs from AlienVault OTX, Wayback Machine, Common Crawl
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="gau-domain">Target Domain</Label>
                  <Input
                    id="gau-domain"
                    placeholder="example.com"
                    value={gauDomain}
                    onChange={(e) => setGauDomain(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'gau',
                    () => toolsManager.runGauScan(gauDomain),
                    'URL collection completed'
                  )}
                  disabled={isRunning || !gauDomain}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Link className="mr-2 h-4 w-4" />}
                  Fetch URLs
                </Button>
              </CardContent>
            </Card>

            {/* Waybackurls */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Waybackurls - Wayback Machine URLs
                </CardTitle>
                <CardDescription>
                  Extract archived URLs from Wayback Machine
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="wayback-domain">Target Domain</Label>
                  <Input
                    id="wayback-domain"
                    placeholder="example.com"
                    value={waybackDomain}
                    onChange={(e) => setWaybackDomain(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'waybackurls',
                    () => toolsManager.runWaybackurlsScan(waybackDomain),
                    'Wayback URL extraction completed'
                  )}
                  disabled={isRunning || !waybackDomain}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Globe className="mr-2 h-4 w-4" />}
                  Extract Archived URLs
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Crawling Tools */}
          <TabsContent value="crawling" className="space-y-4">
            {/* Katana */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Katana - Modern Web Crawler
                </CardTitle>
                <CardDescription>
                  Next-generation crawling and spidering framework
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="katana-url">Target URL</Label>
                  <Input
                    id="katana-url"
                    placeholder="https://example.com"
                    value={katanaUrl}
                    onChange={(e) => setKatanaUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'katana',
                    () => toolsManager.runKatanaScan(katanaUrl),
                    'Katana crawl completed'
                  )}
                  disabled={isRunning || !katanaUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Network className="mr-2 h-4 w-4" />}
                  Start Crawling
                </Button>
              </CardContent>
            </Card>

            {/* Hakrawler */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Hakrawler - Simple Fast Crawler
                </CardTitle>
                <CardDescription>
                  Quickly discover endpoints and paths
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="hakrawler-url">Target URL</Label>
                  <Input
                    id="hakrawler-url"
                    placeholder="https://example.com"
                    value={hakrawlerUrl}
                    onChange={(e) => setHakrawlerUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'hakrawler',
                    () => toolsManager.runHakrawlerScan(hakrawlerUrl),
                    'Hakrawler scan completed'
                  )}
                  disabled={isRunning || !hakrawlerUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                  Crawl Website
                </Button>
              </CardContent>
            </Card>

            {/* httpx */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  httpx - HTTP Probing Toolkit
                </CardTitle>
                <CardDescription>
                  Fast HTTP probing with technology detection
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="httpx-target">Target URL/Domain</Label>
                  <Input
                    id="httpx-target"
                    placeholder="example.com or https://example.com"
                    value={httpxTarget}
                    onChange={(e) => setHttpxTarget(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'httpx',
                    () => toolsManager.runHttpxScan(httpxTarget),
                    'HTTP probe completed'
                  )}
                  disabled={isRunning || !httpxTarget}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Target className="mr-2 h-4 w-4" />}
                  Probe Target
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Fuzzing Tools */}
          <TabsContent value="fuzzing" className="space-y-4">
            {/* FFUF */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  FFUF - Fast Web Fuzzer
                </CardTitle>
                <CardDescription>
                  Lightning-fast web fuzzing tool written in Go
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="ffuf-url">Target URL</Label>
                  <Input
                    id="ffuf-url"
                    placeholder="https://example.com"
                    value={ffufUrl}
                    onChange={(e) => setFfufUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'ffuf',
                    () => toolsManager.runFfufScan(ffufUrl),
                    'FFUF fuzzing completed'
                  )}
                  disabled={isRunning || !ffufUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4" />}
                  Start Fuzzing
                </Button>
              </CardContent>
            </Card>

            {/* Arjun */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileSearch className="h-5 w-5" />
                  Arjun - Parameter Discovery
                </CardTitle>
                <CardDescription>
                  HTTP parameter discovery suite for finding hidden parameters
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="arjun-url">Target URL</Label>
                  <Input
                    id="arjun-url"
                    placeholder="https://example.com/page"
                    value={arjunUrl}
                    onChange={(e) => setArjunUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'arjun',
                    () => toolsManager.runArjunScan(arjunUrl),
                    'Parameter discovery completed'
                  )}
                  disabled={isRunning || !arjunUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileSearch className="mr-2 h-4 w-4" />}
                  Discover Parameters
                </Button>
              </CardContent>
            </Card>

            {/* ParamSpider */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  ParamSpider - Parameter Mining
                </CardTitle>
                <CardDescription>
                  Mine parameters from dark corners of web archives
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="paramspider-domain">Target Domain</Label>
                  <Input
                    id="paramspider-domain"
                    placeholder="example.com"
                    value={paramspiderDomain}
                    onChange={(e) => setParamspiderDomain(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'paramspider',
                    () => toolsManager.runParamspiderScan(paramspiderDomain),
                    'Parameter mining completed'
                  )}
                  disabled={isRunning || !paramspiderDomain}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                  Mine Parameters
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Scanning Tools */}
          <TabsContent value="scanning" className="space-y-4">
            {/* Dalfox */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertCircle className="h-5 w-5" />
                  Dalfox - XSS Scanner
                </CardTitle>
                <CardDescription>
                  Powerful XSS scanning and parameter analysis tool
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="dalfox-url">Target URL</Label>
                  <Input
                    id="dalfox-url"
                    placeholder="https://example.com/page?param="
                    value={dalfoxUrl}
                    onChange={(e) => setDalfoxUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'dalfox',
                    () => toolsManager.runDalfoxScan(dalfoxUrl),
                    'XSS scan completed'
                  )}
                  disabled={isRunning || !dalfoxUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <AlertCircle className="mr-2 h-4 w-4" />}
                  Scan for XSS
                </Button>
              </CardContent>
            </Card>

            {/* RustScan */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  RustScan - Ultra-Fast Port Scanner
                </CardTitle>
                <CardDescription>
                  Blazing fast port scanner that feeds results to Nmap
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="rustscan-target">Target IP/Domain</Label>
                  <Input
                    id="rustscan-target"
                    placeholder="192.168.1.1 or example.com"
                    value={rustscanTarget}
                    onChange={(e) => setRustscanTarget(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'rustscan',
                    () => toolsManager.runRustscanScan(rustscanTarget),
                    'RustScan completed'
                  )}
                  disabled={isRunning || !rustscanTarget}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Shield className="mr-2 h-4 w-4" />}
                  Fast Scan
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Secrets & Analysis Tools */}
          <TabsContent value="secrets" className="space-y-4">
            {/* LinkFinder */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Link className="h-5 w-5" />
                  LinkFinder - JS Endpoint Discovery
                </CardTitle>
                <CardDescription>
                  Discover endpoints in JavaScript files
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="linkfinder-url">Target URL or JS File</Label>
                  <Input
                    id="linkfinder-url"
                    placeholder="https://example.com/app.js"
                    value={linkfinderUrl}
                    onChange={(e) => setLinkfinderUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'linkfinder',
                    () => toolsManager.runLinkfinderScan(linkfinderUrl),
                    'LinkFinder scan completed'
                  )}
                  disabled={isRunning || !linkfinderUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Link className="mr-2 h-4 w-4" />}
                  Find Endpoints
                </Button>
              </CardContent>
            </Card>

            {/* SecretFinder */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  SecretFinder - JS Secret Scanner
                </CardTitle>
                <CardDescription>
                  Find API keys, tokens, and sensitive data in JavaScript
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="secretfinder-url">Target URL or JS File</Label>
                  <Input
                    id="secretfinder-url"
                    placeholder="https://example.com/app.js"
                    value={secretfinderUrl}
                    onChange={(e) => setSecretfinderUrl(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'secretfinder',
                    () => toolsManager.runSecretfinderScan(secretfinderUrl),
                    'Secret search completed'
                  )}
                  disabled={isRunning || !secretfinderUrl}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Key className="mr-2 h-4 w-4" />}
                  Find Secrets
                </Button>
              </CardContent>
            </Card>

            {/* Gitleaks */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <GitBranch className="h-5 w-5" />
                  Gitleaks - Git Secret Scanner
                </CardTitle>
                <CardDescription>
                  Scan git repositories for hardcoded secrets
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="gitleaks-repo">Repository Path or URL</Label>
                  <Input
                    id="gitleaks-repo"
                    placeholder="/path/to/repo or https://github.com/user/repo"
                    value={gitleaksRepo}
                    onChange={(e) => setGitleaksRepo(e.target.value)}
                  />
                </div>
                <Button 
                  onClick={() => handleToolRun(
                    'gitleaks',
                    () => toolsManager.runGitleaksScan(gitleaksRepo),
                    'Gitleaks scan completed'
                  )}
                  disabled={isRunning || !gitleaksRepo}
                >
                  {isRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <GitBranch className="mr-2 h-4 w-4" />}
                  Scan Repository
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Output Display */}
        {output && (
          <Card className="mt-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {isRunning ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                )}
                Scan Output
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px] w-full rounded-md border p-4">
                <pre className="text-sm whitespace-pre-wrap font-mono">
                  {output}
                </pre>
              </ScrollArea>
            </CardContent>
          </Card>
        )}
      </CardContent>
    </Card>
  );
}
