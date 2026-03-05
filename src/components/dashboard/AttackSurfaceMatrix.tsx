/**
 * AttackSurfaceMatrix.tsx — Offensive C2 Dashboard
 * Maps discovered technologies → CVEs → Nuclei verification → Weaponization Queue
 */

import { useState, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  Target, Shield, Crosshair, Cpu, AlertTriangle, CheckCircle2,
  Globe, Search, Zap, Bug, Lock, RefreshCw, Play, Code2,
  Database, Layers, Activity, Eye, XCircle, ExternalLink,
} from 'lucide-react';
import { fingerprintFromScanResults, type TargetAsset, type TechProfile } from '@/services/TechFingerprinter';
import { correlateAllTechnologies, type CVECorrelationResult, type CVERecord } from '@/services/CVEIntelFetcher';
import { batchVerifyCVEs, type NucleiVerificationResult, type WeaponizationEntry } from '@/services/NucleiOrchestrator';

type Phase = 'idle' | 'fingerprinting' | 'cve-lookup' | 'verifying' | 'complete';

const AttackSurfaceMatrix = () => {
  const { toast } = useToast();
  const [target, setTarget] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [progress, setProgress] = useState(0);
  const [log, setLog] = useState<string[]>([]);

  // Data
  const [asset, setAsset] = useState<TargetAsset | null>(null);
  const [cveResults, setCveResults] = useState<CVECorrelationResult[]>([]);
  const [verificationResults, setVerificationResults] = useState<NucleiVerificationResult[]>([]);
  const [weaponizationQueue, setWeaponizationQueue] = useState<WeaponizationEntry[]>([]);
  const [activeTab, setActiveTab] = useState('matrix');

  const addLog = useCallback((msg: string) => {
    setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  }, []);

  // ===== FULL PIPELINE =====
  const runPipeline = async () => {
    if (!target) {
      toast({ title: 'Target Required', variant: 'destructive' });
      return;
    }

    setPhase('fingerprinting');
    setProgress(5);
    setLog([]);
    setCveResults([]);
    setVerificationResults([]);
    setWeaponizationQueue([]);
    addLog(`🎯 Starting attack surface analysis on ${target}`);

    // Phase 1: Fingerprint
    addLog('📡 Phase 1: Deep technology fingerprinting...');
    let fingerprint: TargetAsset;
    try {
      // Run recon scans for fingerprinting data
      const [headersRes, techRes, sslRes] = await Promise.all([
        supabase.functions.invoke('security-scan', { body: { scanType: 'headers', target } }),
        supabase.functions.invoke('security-scan', { body: { scanType: 'tech', target } }),
        supabase.functions.invoke('security-scan', { body: { scanType: 'ssl', target } }),
      ]);

      const headers: Record<string, string> = {};
      const technologies: string[] = [];

      // Extract headers
      const headerFindings = headersRes.data?.findings || headersRes.data?.vulnerabilities || [];
      for (const f of headerFindings) {
        const name = f.name || f.title || '';
        if (name.includes(':')) {
          const [k, ...v] = name.split(':');
          headers[k.trim()] = v.join(':').trim();
        }
        if (f.description) {
          const headerMatch = f.description.match(/([A-Za-z-]+):\s*(.+)/);
          if (headerMatch) headers[headerMatch[1]] = headerMatch[2];
        }
      }

      // Extract technologies
      const techFindings = techRes.data?.findings || techRes.data?.vulnerabilities || [];
      for (const f of techFindings) {
        const name = (f.name || f.title || '').replace(/^Technology:\s*/i, '').trim();
        if (name) technologies.push(name);
      }

      // SSL info
      const sslFindings = sslRes.data?.findings || sslRes.data?.vulnerabilities || [];
      for (const f of sslFindings) {
        const name = (f.name || f.title || '').trim();
        if (name) technologies.push(name);
      }

      fingerprint = fingerprintFromScanResults(target, { headers, technologies });
      setAsset(fingerprint);
      setProgress(30);
      addLog(`✅ Fingerprinted ${fingerprint.technologies.length} technologies`);
      fingerprint.technologies.forEach(t =>
        addLog(`  ⚙️ ${t.name}${t.version ? ` v${t.version}` : ''} [${t.category}] (${Math.round(t.confidence * 100)}%)`)
      );
    } catch (err: any) {
      addLog(`❌ Fingerprinting error: ${err.message}`);
      setPhase('idle');
      return;
    }

    // Phase 2: CVE Intelligence
    setPhase('cve-lookup');
    setProgress(40);
    addLog('🔍 Phase 2: CVE intelligence correlation...');
    try {
      const correlations = await correlateAllTechnologies(fingerprint.technologies);
      setCveResults(correlations);
      setProgress(60);
      const totalCVEs = correlations.reduce((s, c) => s + c.cves.length, 0);
      addLog(`✅ Found ${totalCVEs} High/Critical CVEs across ${correlations.length} technologies`);
      correlations.forEach(c =>
        addLog(`  🐛 ${c.technology.name}: ${c.cves.length} CVEs (highest CVSS: ${c.highestCVSS})`)
      );
    } catch (err: any) {
      addLog(`❌ CVE lookup error: ${err.message}`);
    }

    // Phase 3: Nuclei Verification
    setPhase('verifying');
    setProgress(70);
    addLog('🔬 Phase 3: Safe CVE verification via Nuclei templates...');
    try {
      const allCVEsToVerify = cveResults.length > 0
        ? cveResults.flatMap(c => c.cves.map(cve => ({ cve, technology: c.technology.name, version: c.technology.version })))
        : [];

      // Use latest cveResults from state — need to recalculate since state might not be updated yet
      const freshCorrelations = await correlateAllTechnologies(fingerprint.technologies);
      const cvesToVerify = freshCorrelations.flatMap(c =>
        c.cves.slice(0, 3).map(cve => ({ cve, technology: c.technology.name, version: c.technology.version }))
      );

      if (cvesToVerify.length > 0) {
        const { results, weaponized } = await batchVerifyCVEs(target, cvesToVerify);
        setVerificationResults(results);
        setWeaponizationQueue(weaponized);
        setProgress(95);
        addLog(`✅ Verified ${results.length} CVEs: ${weaponized.length} CONFIRMED vulnerable`);
        weaponized.forEach(w =>
          addLog(`  💀 ${w.cveId} (CVSS ${w.cvssScore}) — ${w.vulnerabilityType} on ${w.technology}`)
        );
      } else {
        addLog('ℹ️ No CVEs available for verification');
      }
    } catch (err: any) {
      addLog(`❌ Verification error: ${err.message}`);
    }

    setPhase('complete');
    setProgress(100);
    addLog('🏁 Attack surface analysis complete');
    toast({ title: 'Analysis Complete', description: `${weaponizationQueue.length} verified vulnerabilities ready for reporting` });
  };

  const getSevColor = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'text-red-400 bg-red-500/15 border-red-500/30';
    if (s === 'high') return 'text-orange-400 bg-orange-500/15 border-orange-500/30';
    if (s === 'medium') return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30';
    return 'text-blue-400 bg-blue-500/15 border-blue-500/30';
  };

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case 'server': return <Globe className="h-3 w-3" />;
      case 'framework': return <Layers className="h-3 w-3" />;
      case 'language': return <Code2 className="h-3 w-3" />;
      case 'cms': return <Database className="h-3 w-3" />;
      case 'waf': return <Shield className="h-3 w-3" />;
      case 'cdn': return <Zap className="h-3 w-3" />;
      default: return <Cpu className="h-3 w-3" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-xl border border-red-500/30">
            <Crosshair className="h-8 w-8 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Attack Surface Matrix</h1>
            <p className="text-muted-foreground text-sm">Tech Fingerprint → CVE Intel → Nuclei Verify → Weaponization Queue</p>
          </div>
        </div>
        <Badge variant={phase === 'complete' ? 'default' : 'secondary'} className="gap-1">
          <Activity className={`h-3 w-3 ${phase !== 'idle' && phase !== 'complete' ? 'animate-pulse' : ''}`} />
          {phase}
        </Badge>
      </div>

      {/* Target + Launch */}
      <Card>
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com"
              disabled={phase !== 'idle' && phase !== 'complete'}
              className="flex-1"
            />
            <Button
              onClick={runPipeline}
              disabled={!target || (phase !== 'idle' && phase !== 'complete')}
              className="gap-2"
            >
              {phase !== 'idle' && phase !== 'complete' ? (
                <><RefreshCw className="h-4 w-4 animate-spin" />Analyzing...</>
              ) : (
                <><Play className="h-4 w-4" />Launch Analysis</>
              )}
            </Button>
          </div>
          {phase !== 'idle' && <Progress value={progress} className="mt-3 h-2" />}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-5 w-full text-xs">
              <TabsTrigger value="matrix"><Crosshair className="h-3 w-3 mr-1" />Matrix</TabsTrigger>
              <TabsTrigger value="cves"><Bug className="h-3 w-3 mr-1" />CVEs{cveResults.length > 0 && <Badge className="ml-1 text-xs h-4 px-1">{cveResults.reduce((s, c) => s + c.cves.length, 0)}</Badge>}</TabsTrigger>
              <TabsTrigger value="verify"><CheckCircle2 className="h-3 w-3 mr-1" />Verify</TabsTrigger>
              <TabsTrigger value="weaponize"><Zap className="h-3 w-3 mr-1" />Weaponize{weaponizationQueue.length > 0 && <Badge className="ml-1 text-xs h-4 px-1 bg-red-500/20 text-red-400">{weaponizationQueue.length}</Badge>}</TabsTrigger>
              <TabsTrigger value="log"><Activity className="h-3 w-3 mr-1" />Log</TabsTrigger>
            </TabsList>

            {/* MATRIX TAB */}
            <TabsContent value="matrix" className="space-y-4">
              {!asset ? (
                <Card>
                  <CardContent className="py-12 text-center text-muted-foreground">
                    <Crosshair className="h-12 w-12 mx-auto mb-3 opacity-30" />
                    <p>Enter a target and launch analysis to map the attack surface.</p>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardHeader className="py-3">
                    <CardTitle className="text-sm">Technology → CVE Attack Matrix</CardTitle>
                    <CardDescription className="text-xs">Each row maps a detected technology to its known CVEs</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-3">
                        {asset.technologies.map((tech, idx) => {
                          const corr = cveResults.find(c => c.technology.name === tech.name);
                          const verified = verificationResults.filter(v => corr?.cves.some(c => c.cveId === v.cveId));
                          const confirmedCount = verified.filter(v => v.verified).length;

                          return (
                            <div key={idx} className="p-3 border border-border rounded-lg bg-card/50 hover:bg-card/80 transition-colors">
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  {getCategoryIcon(tech.category)}
                                  <span className="font-mono font-medium text-sm">{tech.name}</span>
                                  {tech.version && <Badge variant="outline" className="text-xs font-mono">v{tech.version}</Badge>}
                                  <Badge variant="secondary" className="text-xs">{tech.category}</Badge>
                                </div>
                                <div className="flex items-center gap-1">
                                  <Badge variant="outline" className="text-xs">{Math.round(tech.confidence * 100)}%</Badge>
                                  {corr && (
                                    <Badge className={`text-xs ${corr.highestCVSS >= 9 ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                                      {corr.totalCVEs} CVEs
                                    </Badge>
                                  )}
                                  {confirmedCount > 0 && (
                                    <Badge className="text-xs bg-red-600/20 text-red-300 border-red-500/40">
                                      💀 {confirmedCount} confirmed
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              {corr && corr.cves.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {corr.cves.slice(0, 5).map(cve => {
                                    const isVerified = verified.find(v => v.cveId === cve.cveId);
                                    return (
                                      <Badge
                                        key={cve.cveId}
                                        variant="outline"
                                        className={`text-xs font-mono ${
                                          isVerified?.verified ? 'border-red-500/50 text-red-400 bg-red-500/10' :
                                          isVerified ? 'border-green-500/50 text-green-400' :
                                          getSevColor(cve.severity)
                                        }`}
                                      >
                                        {isVerified?.verified && '💀 '}{cve.cveId} ({cve.cvssScore})
                                      </Badge>
                                    );
                                  })}
                                </div>
                              )}
                              <p className="text-xs text-muted-foreground mt-1">Source: {tech.source}</p>
                            </div>
                          );
                        })}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            {/* CVEs TAB */}
            <TabsContent value="cves">
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2"><Bug className="h-4 w-4" />CVE Intelligence Feed</CardTitle>
                </CardHeader>
                <CardContent>
                  {cveResults.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No CVEs fetched yet.</div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-2">
                        {cveResults.flatMap(c => c.cves.map(cve => ({ ...cve, tech: c.technology.name }))).map((cve, i) => (
                          <div key={i} className="p-3 border border-border rounded-lg bg-card/50">
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className="text-xs font-mono">{cve.cveId}</Badge>
                                  <Badge className={`text-xs ${getSevColor(cve.severity)}`}>
                                    CVSS {cve.cvssScore} — {cve.severity}
                                  </Badge>
                                  <Badge variant="secondary" className="text-xs">{cve.tech}</Badge>
                                  {cve.exploitAvailable && <Badge className="text-xs bg-red-500/20 text-red-400">Exploit Available</Badge>}
                                </div>
                                <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{cve.description}</p>
                                <p className="text-xs mt-1"><span className="text-muted-foreground">Type:</span> {cve.vulnerabilityType} | <span className="text-muted-foreground">Affected:</span> {cve.affectedVersions}</p>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* VERIFY TAB */}
            <TabsContent value="verify">
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2"><CheckCircle2 className="h-4 w-4" />Nuclei Verification Results</CardTitle>
                  <CardDescription className="text-xs">Safe, template-based verification — no destructive exploitation</CardDescription>
                </CardHeader>
                <CardContent>
                  {verificationResults.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">No verification results yet.</div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-2">
                        {verificationResults.map((r, i) => (
                          <div key={i} className={`p-3 border rounded-lg ${r.verified ? 'border-red-500/40 bg-red-500/5' : 'border-border bg-card/50'}`}>
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {r.verified ? <AlertTriangle className="h-4 w-4 text-red-400" /> : r.matcherStatus === 'not-vulnerable' ? <CheckCircle2 className="h-4 w-4 text-green-400" /> : <XCircle className="h-4 w-4 text-muted-foreground" />}
                                <Badge variant="outline" className="text-xs font-mono">{r.cveId}</Badge>
                                <Badge className={`text-xs ${r.verified ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                                  {r.matcherStatus}
                                </Badge>
                              </div>
                              <span className="text-xs text-muted-foreground">{new Date(r.timestamp).toLocaleTimeString()}</span>
                            </div>
                            {r.nucleiOutput && (
                              <pre className="mt-2 p-2 bg-black/40 rounded text-xs font-mono text-muted-foreground overflow-x-auto max-h-20">{r.nucleiOutput}</pre>
                            )}
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* WEAPONIZE TAB */}
            <TabsContent value="weaponize">
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2 text-red-400"><Zap className="h-4 w-4" />Weaponization Queue</CardTitle>
                  <CardDescription className="text-xs">Nuclei-confirmed CVEs ready for PoC crafting and bounty reporting</CardDescription>
                </CardHeader>
                <CardContent>
                  {weaponizationQueue.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Zap className="h-12 w-12 mx-auto mb-2 opacity-30" />
                      <p>Verified CVEs will appear here for manual PoC development.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-3">
                        {weaponizationQueue.map((w) => (
                          <div key={w.id} className="p-4 border border-red-500/30 rounded-lg bg-red-500/5">
                            <div className="flex items-start justify-between gap-2 mb-2">
                              <div>
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className="font-mono text-xs">{w.cveId}</Badge>
                                  <Badge className={`text-xs ${getSevColor(w.severity)}`}>CVSS {w.cvssScore}</Badge>
                                  <Badge variant="secondary" className="text-xs">{w.technology}{w.version ? ` v${w.version}` : ''}</Badge>
                                  {w.exploitReady && <Badge className="text-xs bg-red-600/20 text-red-300">Exploit Ready</Badge>}
                                </div>
                                <p className="text-sm font-medium mt-1">{w.vulnerabilityType}</p>
                                <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{w.description}</p>
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-xs mt-2">
                              <div className="p-2 bg-muted/30 rounded">
                                <span className="text-muted-foreground">Endpoint: </span>
                                <span className="font-mono">{w.verifiedEndpoint}</span>
                              </div>
                              <div className="p-2 bg-muted/30 rounded">
                                <span className="text-muted-foreground">Template: </span>
                                <span className="font-mono">{w.nucleiTemplateId}</span>
                              </div>
                            </div>
                            {w.pocPayload && (
                              <pre className="mt-2 p-2 bg-black/50 rounded text-xs font-mono text-green-300 overflow-x-auto">{w.pocPayload}</pre>
                            )}
                            <p className="text-xs text-muted-foreground mt-2">Verified: {new Date(w.verifiedAt).toLocaleString()}</p>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* LOG TAB */}
            <TabsContent value="log">
              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-sm flex items-center gap-2"><Activity className="h-4 w-4" />Operation Log</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[500px]">
                    <div className="p-4 font-mono text-xs space-y-1 bg-black/50 rounded-b-lg">
                      {log.length === 0 ? (
                        <div className="text-muted-foreground text-center py-4">Awaiting operation...</div>
                      ) : log.map((line, i) => (
                        <div key={i} className={
                          line.includes('✅') ? 'text-green-400' :
                          line.includes('❌') ? 'text-red-400' :
                          line.includes('💀') ? 'text-red-300 font-bold' :
                          line.includes('🐛') ? 'text-orange-400' :
                          line.includes('⚙️') ? 'text-cyan-400' :
                          'text-muted-foreground'
                        }>{line}</div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Sidebar Stats */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm flex items-center gap-2"><Target className="h-4 w-4" />Summary</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {[
                { label: 'Technologies', value: asset?.technologies.length || 0, color: 'text-cyan-400' },
                { label: 'Total CVEs', value: cveResults.reduce((s, c) => s + c.cves.length, 0), color: 'text-orange-400' },
                { label: 'Critical CVEs', value: cveResults.reduce((s, c) => s + c.cves.filter(x => x.severity === 'CRITICAL').length, 0), color: 'text-red-400' },
                { label: 'Verified', value: verificationResults.filter(v => v.verified).length, color: 'text-red-300' },
                { label: 'Not Vuln', value: verificationResults.filter(v => v.matcherStatus === 'not-vulnerable').length, color: 'text-green-400' },
                { label: 'Weaponized', value: weaponizationQueue.length, color: 'text-red-400' },
                { label: 'Exploit Ready', value: weaponizationQueue.filter(w => w.exploitReady).length, color: 'text-red-300' },
              ].map(s => (
                <div key={s.label} className="flex justify-between">
                  <span className="text-muted-foreground text-sm">{s.label}</span>
                  <span className={`font-mono ${s.color}`}>{s.value}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          {asset && asset.serverInfo.server && (
            <Card>
              <CardHeader className="py-3"><CardTitle className="text-sm">🖥️ Server</CardTitle></CardHeader>
              <CardContent>
                <p className="text-sm font-mono">{asset.serverInfo.server}</p>
                {asset.serverInfo.poweredBy && <p className="text-xs text-muted-foreground mt-1">Powered by: {asset.serverInfo.poweredBy}</p>}
              </CardContent>
            </Card>
          )}

          {cveResults.length > 0 && (
            <Card>
              <CardHeader className="py-3"><CardTitle className="text-sm">🏆 Highest CVSS</CardTitle></CardHeader>
              <CardContent>
                {cveResults
                  .sort((a, b) => b.highestCVSS - a.highestCVSS)
                  .slice(0, 5)
                  .map((c, i) => (
                    <div key={i} className="flex justify-between items-center py-1">
                      <span className="text-sm">{c.technology.name}</span>
                      <Badge className={`text-xs ${c.highestCVSS >= 9 ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                        {c.highestCVSS}
                      </Badge>
                    </div>
                  ))}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackSurfaceMatrix;
