import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';
import KaliToolsManager, { ScanResult, ToolConfig, AutomatedScanConfig } from '@/utils/kaliTools';

export const useKaliTools = () => {
  const [isKaliEnvironment, setIsKaliEnvironment] = useState(false);
  const [installedTools, setInstalledTools] = useState<ToolConfig[]>([]);
  const [activeSessions, setActiveSessions] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  const toolsManager = KaliToolsManager.getInstance();

  // Check if running in Kali Linux
  useEffect(() => {
    const checkEnvironment = async () => {
      try {
        const isKali = await toolsManager.isKaliLinux();
        setIsKaliEnvironment(isKali);
        
        if (!isKali) {
          toast({
            title: "Environment Warning",
            description: "This tool is optimized for Kali Linux. Some features may not work correctly.",
            variant: "destructive"
          });
        }
        
        const tools = await toolsManager.getInstalledTools();
        setInstalledTools(tools);
      } catch (error) {
        console.error('Failed to check environment:', error);
        toast({
          title: "Error",
          description: "Failed to check system environment",
          variant: "destructive"
        });
      } finally {
        setIsLoading(false);
      }
    };

    checkEnvironment();
  }, [toast]);

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
        description: `Running ${scanType} scan on ${target}`
      });

      const output = await toolsManager.runNmapScan(target, scanType);
      
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
        description: `Scan completed for ${target}`
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
        title: "Network Scan Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

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
        description: `Running Nikto scan on ${target}`
      });

      const output = await toolsManager.runNiktoScan(target);
      
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
        description: `Nikto scan completed for ${target}`
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
        title: "Web Scan Failed",
        description: error.message,
        variant: "destructive"
      });

      throw error;
    }
  }, [toast]);

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
  const generateReport = useCallback(() => {
    const completedSessions = activeSessions.filter(s => s.status === 'completed');
    return toolsManager.generateReport(completedSessions);
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
    const config: AutomatedScanConfig = {
      target,
      scanTypes: scanTypes || [],
      onProgress: (progress: number, currentTool: string) => {
        toast({
          title: "Automated Scan Progress",
          description: `${progress}% - Running ${currentTool}`,
        });
      },
      onToolComplete: (result: ScanResult) => {
        setActiveSessions(prev => {
          const existingIndex = prev.findIndex(s => s.id === result.id);
          if (existingIndex >= 0) {
            const updated = [...prev];
            updated[existingIndex] = result;
            return updated;
          }
          return [...prev, result];
        });

        toast({
          title: `${result.tool.toUpperCase()} ${result.status === 'completed' ? 'Completed' : 'Failed'}`,
          description: `Scan ${result.status} for ${result.target}`,
          variant: result.status === 'failed' ? 'destructive' : 'default'
        });
      }
    };

    try {
      toast({
        title: "Automated Scan Started",
        description: `Running comprehensive security assessment on ${target}`,
      });

      const results = await toolsManager.runAutomatedScan(config);
      
      toast({
        title: "Automated Scan Completed",
        description: `Assessment completed for ${target}. Check the results below.`,
      });

      return results;
    } catch (error: any) {
      toast({
        title: "Automated Scan Failed",
        description: error.message,
        variant: "destructive"
      });
      throw error;
    }
  }, [toast]);

  return {
    isKaliEnvironment,
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
    stopAllScans
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