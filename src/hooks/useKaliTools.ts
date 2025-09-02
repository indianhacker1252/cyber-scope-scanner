import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';
import { RealKaliToolsManager } from '@/utils/realKaliTools';
import { ScanResult, ToolConfig, AutomatedScanConfig } from '@/utils/kaliTools';
import { DEMO_OUTPUTS } from '@/config/apiConfig';

export const useKaliTools = () => {
  const [isKaliEnvironment, setIsKaliEnvironment] = useState(false);
  const [installedTools, setInstalledTools] = useState<ToolConfig[]>([]);
  const [activeSessions, setActiveSessions] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const { toast } = useToast();

  const toolsManager = RealKaliToolsManager.getInstance();

  // Check if running in Kali Linux
  useEffect(() => {
    const checkEnvironment = async () => {
      try {
        const isKali = await toolsManager.isKaliLinux();
        setIsKaliEnvironment(isKali);
        
        if (!isKali) {
          setIsDemoMode(true);
          toast({
            title: "Demo Mode Active",
            description: "Backend not available. Running in demonstration mode with simulated results.",
            variant: "default"
          });
        } else {
          toast({
            title: "Kali Linux Detected",
            description: "Full tool functionality available",
          });
        }
        
        const tools = await toolsManager.getInstalledTools();
        setInstalledTools(tools);
      } catch (error) {
        console.error('Failed to check environment:', error);
        setIsDemoMode(true);
        toast({
          title: "Demo Mode Active",
          description: "Backend connection failed. Running in demonstration mode.",
          variant: "default"
        });
      } finally {
        setIsLoading(false);
      }
    };

    checkEnvironment();
  }, [toast]);

  // Simulate demo scan with realistic output
  const simulateDemoScan = (tool: string, target: string): Promise<string> => {
    return new Promise((resolve) => {
      setTimeout(() => {
        const demoOutput = DEMO_OUTPUTS[tool as keyof typeof DEMO_OUTPUTS] || [`Demo ${tool} scan output for ${target}`];
        resolve(demoOutput.join('\n'));
      }, 2000 + Math.random() * 3000); // Random delay between 2-5 seconds
    });
  };

  // Run network scan
  const runNetworkScan = useCallback(async (target: string, scanType: string = 'basic') => {
    const sessionId = `nmap-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'nmap',
      target,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "Network Scan Started",
        description: `Running ${scanType} scan on ${target}${isDemoMode ? ' (Demo Mode)' : ''}`
      });

      let output: string;
      if (isDemoMode) {
        output = await simulateDemoScan('nmap', target);
      } else {
        output = await toolsManager.runNmapScan(target, scanType);
      }
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseNmapOutput(output)
            }
          : session
      ));

      toast({
        title: "Network Scan Completed",
        description: `Scan completed for ${target}${isDemoMode ? ' (Demo)' : ''}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      if (!isDemoMode) {
        toast({
          title: "Network Scan Failed",
          description: error.message,
          variant: "destructive"
        });
      }

      throw error;
    }
  }, [toast, isDemoMode]);

  // Run web vulnerability scan
  const runWebScan = useCallback(async (target: string) => {
    const sessionId = `nikto-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'nikto',
      target,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "Web Scan Started",
        description: `Running Nikto scan on ${target}${isDemoMode ? ' (Demo Mode)' : ''}`
      });

      let output: string;
      if (isDemoMode) {
        output = await simulateDemoScan('nikto', target);
      } else {
        output = await toolsManager.runNiktoScan(target);
      }
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseNiktoOutput(output)
            }
          : session
      ));

      toast({
        title: "Web Scan Completed",
        description: `Nikto scan completed for ${target}${isDemoMode ? ' (Demo)' : ''}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      if (!isDemoMode) {
        toast({
          title: "Web Scan Failed",
          description: error.message,
          variant: "destructive"
        });
      }

      throw error;
    }
  }, [toast, isDemoMode]);

  // Run SQL injection test
  const runSQLInjectionTest = useCallback(async (target: string, options?: string) => {
    const sessionId = `sqlmap-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'sqlmap',
      target,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "SQL Injection Test Started",
        description: `Running SQLMap on ${target}`
      });

      const output = await toolsManager.runSQLMapScan(target, options);
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseSQLMapOutput(output)
            }
          : session
      ));

      toast({
        title: "SQL Injection Test Completed",
        description: `SQLMap test completed for ${target}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      toast({
        title: "SQL Injection Test Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

  // Run directory enumeration
  const runDirectoryEnum = useCallback(async (target: string, wordlist?: string) => {
    const sessionId = `gobuster-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'gobuster',
      target,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "Directory Enumeration Started",
        description: `Running Gobuster on ${target}`
      });

      const output = await toolsManager.runGobusterScan(target, wordlist);
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseGobusterOutput(output)
            }
          : session
      ));

      toast({
        title: "Directory Enumeration Completed",
        description: `Gobuster scan completed for ${target}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      toast({
        title: "Directory Enumeration Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

  // Run subdomain enumeration
  const runSubdomainEnum = useCallback(async (domain: string) => {
    const sessionId = `amass-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'amass',
      target: domain,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "Subdomain Enumeration Started",
        description: `Running Amass on ${domain}`
      });

      const output = await toolsManager.runAmassEnum(domain);
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseAmassOutput(output)
            }
          : session
      ));

      toast({
        title: "Subdomain Enumeration Completed",
        description: `Amass enumeration completed for ${domain}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      toast({
        title: "Subdomain Enumeration Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

  // Run vulnerability scan with Nuclei
  const runVulnerabilityScan = useCallback(async (target: string, templates?: string) => {
    const sessionId = `nuclei-${Date.now()}`;
    const newSession: ScanResult = {
      id: sessionId,
      tool: 'nuclei',
      target,
      status: 'running',
      progress: 0,
      findings: [],
      output: '',
      startTime: new Date()
    };

    setActiveSessions(prev => [...prev, newSession]);
    
    try {
      toast({
        title: "Vulnerability Scan Started",
        description: `Running Nuclei on ${target}`
      });

      const output = await toolsManager.runNucleiScan(target, templates);
      
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'completed', 
              progress: 100, 
              output,
              endTime: new Date(),
              findings: parseNucleiOutput(output)
            }
          : session
      ));

      toast({
        title: "Vulnerability Scan Completed",
        description: `Nuclei scan completed for ${target}`
      });

      return output;
    } catch (error: any) {
      setActiveSessions(prev => prev.map(session => 
        session.id === sessionId 
          ? { 
              ...session, 
              status: 'failed', 
              output: error.message,
              endTime: new Date()
            }
          : session
      ));

      toast({
        title: "Vulnerability Scan Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

  // Generate comprehensive report
  const generateReport = useCallback(async () => {
    const completedSessions = activeSessions.filter(s => s.status === 'completed');
    return await toolsManager.generateReport(completedSessions);
  }, [activeSessions]);

  // Clear session history
  const clearSessions = useCallback(() => {
    setActiveSessions([]);
  }, []);

  // Stop all running scans
  const stopAllScans = useCallback(() => {
    toolsManager.stopAllScans();
    setActiveSessions(prev => prev.map(session => ({
      ...session,
      status: session.status === 'running' ? 'failed' : session.status,
      endTime: session.status === 'running' ? new Date() : session.endTime
    })));
    
    toast({
      title: "Scans Stopped",
      description: "All running scans have been terminated"
    });
  }, [toast]);

  // Run automated comprehensive scan
  const runAutomatedScan = useCallback(async (target: string, scanTypes?: string[]) => {
    // Pre-create sessions for all tools that will run
    const toolsToRun = scanTypes && scanTypes.length > 0 ? scanTypes : ['nmap', 'whatweb', 'wafw00f', 'gobuster', 'nikto', 'nuclei', 'sqlmap'];
    const preSessions: ScanResult[] = [];
    
    toolsToRun.forEach(tool => {
      const sessionId = `${tool}-auto-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      preSessions.push({
        id: sessionId,
        tool,
        target,
        status: 'running',
        progress: 0,
        findings: [],
        output: '',
        startTime: new Date()
      });
    });

    // Add all pre-sessions to state immediately
    setActiveSessions(prev => [...prev, ...preSessions]);

    const config: AutomatedScanConfig = {
      target,
      scanTypes: toolsToRun,
      onProgress: (progress: number, currentTool: string) => {
        toast({
          title: "Automated Scan Progress",
          description: `${progress}% - Running ${currentTool}`,
        });
      },
      onToolComplete: (result: ScanResult) => {
        setActiveSessions(prev => {
          const existingIndex = prev.findIndex(s => s.tool === result.tool && s.target === result.target && s.status === 'running');
          if (existingIndex >= 0) {
            const updated = [...prev];
            updated[existingIndex] = {
              ...updated[existingIndex],
              status: result.status,
              progress: 100,
              output: result.output,
              endTime: result.endTime,
              findings: result.findings
            };
            return updated;
          }
          return prev;
        });

        toast({
          title: `${result.tool.toUpperCase()} ${result.status === 'completed' ? 'Completed' : 'Failed'}`,
          description: `Found ${result.findings.length} findings for ${result.target}`,
          variant: result.status === 'failed' ? 'destructive' : 'default'
        });
      }
    };

    try {
      toast({
        title: "Automated Scan Started",
        description: `Running ${toolsToRun.length} security tools on ${target}`,
      });

      await toolsManager.runAutomatedScan(config);
      
      toast({
        title: "Automated Scan Completed",
        description: `All tools completed for ${target}`,
      });

      return activeSessions;
    } catch (error: any) {
      toast({
        title: "Automated Scan Failed",
        description: error.message,
        variant: "destructive"
      });
      throw error;
    }
  }, [toast]);

  // Stop a specific scan
  const stopScan = useCallback((scanId: string) => {
    setActiveSessions(prev => prev.map(session => 
      session.id === scanId && session.status === 'running'
        ? { ...session, status: 'failed', output: 'Scan stopped by user', endTime: new Date() }
        : session
    ));
    
    toast({
      title: "Scan Stopped",
      description: "The selected scan has been terminated"
    });
  }, [toast]);

  return {
    isKaliEnvironment,
    isDemoMode,
    installedTools,
    activeSessions,
    isLoading,
    runNetworkScan,
    runWebScan,
    runSQLInjectionTest,
    runDirectoryEnum,
    runSubdomainEnum,
    runVulnerabilityScan,
    runAutomatedScan,
    generateReport,
    clearSessions,
    stopAllScans,
    stopScan
  };
};

// Output parsers
function parseNmapOutput(output: string): any[] {
  const findings = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('open')) {
      const parts = line.split(/\s+/);
      findings.push({
        type: 'open_port',
        port: parts[0],
        service: parts[2] || 'unknown',
        version: parts[3] || 'unknown'
      });
    }
  }
  
  return findings;
}

function parseNiktoOutput(output: string): any[] {
  const findings = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('OSVDB') || line.includes('CVE')) {
      findings.push({
        type: 'vulnerability',
        description: line.trim(),
        severity: 'medium'
      });
    }
  }
  
  return findings;
}

function parseSQLMapOutput(output: string): any[] {
  const findings = [];
  
  if (output.includes('injectable')) {
    findings.push({
      type: 'sql_injection',
      description: 'SQL injection vulnerability detected',
      severity: 'high'
    });
  }
  
  return findings;
}

function parseGobusterOutput(output: string): any[] {
  const findings = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('Status: 200') || line.includes('Status: 301') || line.includes('Status: 302')) {
      findings.push({
        type: 'directory',
        path: line.split(' ')[0],
        status: line.includes('Status: 200') ? '200' : line.includes('Status: 301') ? '301' : '302'
      });
    }
  }
  
  return findings;
}

function parseAmassOutput(output: string): any[] {
  const findings = [];
  const lines = output.split('\n').filter(line => line.trim());
  
  for (const line of lines) {
    if (line.includes('.')) {
      findings.push({
        type: 'subdomain',
        domain: line.trim()
      });
    }
  }
  
  return findings;
}

function parseNucleiOutput(output: string): any[] {
  const findings = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('[') && (line.includes('critical') || line.includes('high') || line.includes('medium'))) {
      findings.push({
        type: 'vulnerability',
        description: line.trim(),
        severity: line.includes('critical') ? 'critical' : line.includes('high') ? 'high' : 'medium'
      });
    }
  }
  
  return findings;
}