import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { 
  Download, 
  Key, 
  Monitor, 
  Trash2, 
  RefreshCw, 
  ExternalLink,
  Shield,
  Smartphone,
  Laptop,
  Computer,
  Copy,
  Plus
} from "lucide-react";

interface Agent {
  id: string;
  name: string;
  platform: 'windows' | 'macos' | 'android';
  apiKey: string;
  status: 'online' | 'offline' | 'scanning';
  lastSeen: Date;
  version: string;
  ipAddress: string;
  osVersion: string;
}

interface AgentFile {
  platform: 'windows' | 'macos' | 'android';
  filename: string;
  description: string;
  icon: typeof Computer;
}

const AgentManagement = () => {
  const { toast } = useToast();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [apiKeys, setApiKeys] = useState<string[]>([]);
  const [newApiKeyName, setNewApiKeyName] = useState("");

  const agentFiles: AgentFile[] = [
    {
      platform: 'windows',
      filename: 'CyberScope-Agent-Windows.exe',
      description: 'Windows endpoint security agent with full system access',
      icon: Computer
    },
    {
      platform: 'macos',
      filename: 'CyberScope-Agent-macOS.dmg',
      description: 'macOS endpoint security agent with system-level permissions',
      icon: Laptop
    },
    {
      platform: 'android',
      filename: 'CyberScope-Agent-Android.apk',
      description: 'Android security agent with root access capabilities',
      icon: Smartphone
    }
  ];

  useEffect(() => {
    // Load existing agents and API keys from localStorage
    const savedAgents = localStorage.getItem('cyberscope_agents');
    const savedApiKeys = localStorage.getItem('cyberscope_api_keys');
    
    if (savedAgents) {
      setAgents(JSON.parse(savedAgents));
    }
    if (savedApiKeys) {
      setApiKeys(JSON.parse(savedApiKeys));
    }
  }, []);

  const generateApiKey = () => {
    if (!newApiKeyName.trim()) {
      toast({
        title: "Error",
        description: "Please enter a name for the API key",
        variant: "destructive"
      });
      return;
    }

    const newKey = `cs_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
    const newApiKeys = [...apiKeys, newKey];
    setApiKeys(newApiKeys);
    localStorage.setItem('cyberscope_api_keys', JSON.stringify(newApiKeys));
    setNewApiKeyName("");
    
    toast({
      title: "API Key Generated",
      description: "New API key has been generated and saved"
    });
  };

  const downloadAgent = (agentFile: AgentFile) => {
    // Create a mock agent file download
    const agentContent = `#!/usr/bin/env python3
# CyberScope Endpoint Security Agent - ${agentFile.platform.toUpperCase()}
# This agent provides comprehensive endpoint security scanning and vulnerability assessment

import os
import sys
import json
import requests
import platform
import subprocess
from datetime import datetime

class CyberScopeAgent:
    def __init__(self, api_key):
        self.api_key = api_key
        self.server_url = "https://your-cyberscope-server.com"
        self.agent_version = "1.0.0"
        self.platform = "${agentFile.platform}"
        
    def register_agent(self):
        """Register this agent with the CyberScope server"""
        payload = {
            "platform": self.platform,
            "version": self.agent_version,
            "os_version": platform.platform(),
            "hostname": platform.node(),
            "timestamp": datetime.now().isoformat()
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/agents/register", 
                                   json=payload, headers=headers)
            return response.json()
        except Exception as e:
            print(f"Registration failed: {e}")
            return None
    
    def perform_vulnerability_scan(self):
        """Perform comprehensive vulnerability scanning"""
        scan_results = {
            "scan_id": f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "platform": self.platform,
            "vulnerabilities": [],
            "system_info": self.get_system_info(),
            "network_info": self.get_network_info(),
            "processes": self.get_running_processes(),
            "services": self.get_services(),
            "file_permissions": self.check_file_permissions(),
            "registry_analysis": self.analyze_registry() if self.platform == "windows" else None
        }
        
        # Add platform-specific scanning
        if self.platform == "windows":
            scan_results["windows_specific"] = self.windows_security_scan()
        elif self.platform == "macos":
            scan_results["macos_specific"] = self.macos_security_scan()
        elif self.platform == "android":
            scan_results["android_specific"] = self.android_security_scan()
            
        return scan_results
    
    def get_system_info(self):
        """Get detailed system information"""
        return {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "architecture": platform.architecture(),
            "python_version": platform.python_version()
        }
    
    def get_network_info(self):
        """Get network configuration and open ports"""
        # Implementation would include network scanning
        return {"interfaces": [], "open_ports": [], "connections": []}
    
    def get_running_processes(self):
        """Get list of running processes"""
        # Implementation would include process enumeration
        return []
    
    def get_services(self):
        """Get system services information"""
        # Implementation would include service enumeration
        return []
    
    def check_file_permissions(self):
        """Check critical file permissions"""
        # Implementation would include permission analysis
        return {}
    
    def analyze_registry(self):
        """Windows registry analysis"""
        # Windows-specific registry scanning
        return {}
    
    def windows_security_scan(self):
        """Windows-specific security scanning"""
        return {
            "windows_defender": "enabled",
            "firewall_status": "enabled",
            "uac_level": "default",
            "installed_patches": [],
            "vulnerable_services": []
        }
    
    def macos_security_scan(self):
        """macOS-specific security scanning"""
        return {
            "sip_status": "enabled",
            "gatekeeper": "enabled",
            "xprotect": "enabled",
            "firewall": "enabled",
            "installed_updates": []
        }
    
    def android_security_scan(self):
        """Android-specific security scanning"""
        return {
            "security_patch_level": "",
            "root_detection": False,
            "play_protect": "enabled",
            "unknown_sources": False,
            "installed_apps": []
        }
    
    def send_results(self, scan_results):
        """Send scan results to CyberScope server"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/scans/submit",
                                   json=scan_results, headers=headers)
            return response.json()
        except Exception as e:
            print(f"Failed to send results: {e}")
            return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent.py <API_KEY>")
        sys.exit(1)
        
    api_key = sys.argv[1]
    agent = CyberScopeAgent(api_key)
    
    # Register agent
    registration = agent.register_agent()
    if registration:
        print("Agent registered successfully")
        
        # Perform vulnerability scan
        print("Starting vulnerability scan...")
        results = agent.perform_vulnerability_scan()
        
        # Send results
        response = agent.send_results(results)
        if response:
            print("Scan results sent successfully")
        else:
            print("Failed to send scan results")
    else:
        print("Agent registration failed")
`;

    const blob = new Blob([agentContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = agentFile.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Agent Downloaded",
      description: `${agentFile.filename} has been downloaded`
    });
  };

  const copyApiKey = (apiKey: string) => {
    navigator.clipboard.writeText(apiKey);
    toast({
      title: "Copied",
      description: "API key copied to clipboard"
    });
  };

  const deleteApiKey = (apiKeyToDelete: string) => {
    const updatedKeys = apiKeys.filter(key => key !== apiKeyToDelete);
    setApiKeys(updatedKeys);
    localStorage.setItem('cyberscope_api_keys', JSON.stringify(updatedKeys));
    
    toast({
      title: "API Key Deleted",
      description: "API key has been removed"
    });
  };

  const remoteAccess = (agent: Agent) => {
    toast({
      title: "Remote Access",
      description: `Initiating remote access to ${agent.name}...`
    });
  };

  const updateAgent = (agent: Agent) => {
    toast({
      title: "Agent Update",
      description: `Update command sent to ${agent.name}`
    });
  };

  const deleteAgent = (agentId: string) => {
    const updatedAgents = agents.filter(agent => agent.id !== agentId);
    setAgents(updatedAgents);
    localStorage.setItem('cyberscope_agents', JSON.stringify(updatedAgents));
    
    toast({
      title: "Agent Deleted",
      description: "Agent has been removed from monitoring"
    });
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'online': return 'bg-green-500';
      case 'offline': return 'bg-red-500';
      case 'scanning': return 'bg-yellow-500';
      default: return 'bg-gray-500';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'windows': return Computer;
      case 'macos': return Laptop;
      case 'android': return Smartphone;
      default: return Monitor;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Agent Management</h2>
        <Dialog>
          <DialogTrigger asChild>
            <Button>
              <Download className="h-4 w-4 mr-2" />
              Download Agents
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Download Security Agents</DialogTitle>
            </DialogHeader>
            <div className="grid gap-4">
              {agentFiles.map((agentFile) => {
                const Icon = agentFile.icon;
                return (
                  <Card key={agentFile.platform} className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <Icon className="h-8 w-8 text-primary" />
                        <div>
                          <h3 className="font-semibold">{agentFile.filename}</h3>
                          <p className="text-sm text-muted-foreground">
                            {agentFile.description}
                          </p>
                        </div>
                      </div>
                      <Button onClick={() => downloadAgent(agentFile)}>
                        <Download className="h-4 w-4 mr-2" />
                        Download
                      </Button>
                    </div>
                  </Card>
                );
              })}
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="endpoints" className="space-y-4">
        <TabsList>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="api-keys">API Keys</TabsTrigger>
        </TabsList>

        <TabsContent value="endpoints" className="space-y-4">
          {agents.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No Agents Connected</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Download and deploy agents to start monitoring endpoints
                </p>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button>Download Agents</Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-2xl">
                    <DialogHeader>
                      <DialogTitle>Download Security Agents</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-4">
                      {agentFiles.map((agentFile) => {
                        const Icon = agentFile.icon;
                        return (
                          <Card key={agentFile.platform} className="p-4">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-3">
                                <Icon className="h-8 w-8 text-primary" />
                                <div>
                                  <h3 className="font-semibold">{agentFile.filename}</h3>
                                  <p className="text-sm text-muted-foreground">
                                    {agentFile.description}
                                  </p>
                                </div>
                              </div>
                              <Button onClick={() => downloadAgent(agentFile)}>
                                <Download className="h-4 w-4 mr-2" />
                                Download
                              </Button>
                            </div>
                          </Card>
                        );
                      })}
                    </div>
                  </DialogContent>
                </Dialog>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {agents.map((agent) => {
                const PlatformIcon = getPlatformIcon(agent.platform);
                return (
                  <Card key={agent.id}>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <PlatformIcon className="h-6 w-6" />
                          <div>
                            <CardTitle className="text-lg">{agent.name}</CardTitle>
                            <p className="text-sm text-muted-foreground">
                              {agent.ipAddress} • {agent.osVersion}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline" className="capitalize">
                            {agent.platform}
                          </Badge>
                          <div className={`w-3 h-3 rounded-full ${getStatusColor(agent.status)}`} />
                          <Badge variant={agent.status === 'online' ? 'default' : 'secondary'}>
                            {agent.status}
                          </Badge>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center justify-between">
                        <div className="text-sm text-muted-foreground">
                          Last seen: {agent.lastSeen.toLocaleString()} • Version: {agent.version}
                        </div>
                        <div className="flex space-x-2">
                          <Button size="sm" variant="outline" onClick={() => remoteAccess(agent)}>
                            <ExternalLink className="h-4 w-4 mr-1" />
                            Remote Access
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => updateAgent(agent)}>
                            <RefreshCw className="h-4 w-4 mr-1" />
                            Update
                          </Button>
                          <Button 
                            size="sm" 
                            variant="destructive" 
                            onClick={() => deleteAgent(agent.id)}
                          >
                            <Trash2 className="h-4 w-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="api-keys" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Generate New API Key</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex space-x-2">
                <Input
                  placeholder="Enter API key name"
                  value={newApiKeyName}
                  onChange={(e) => setNewApiKeyName(e.target.value)}
                />
                <Button onClick={generateApiKey}>
                  <Plus className="h-4 w-4 mr-2" />
                  Generate
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-4">
            {apiKeys.map((apiKey, index) => (
              <Card key={index}>
                <CardContent className="flex items-center justify-between p-4">
                  <div className="flex items-center space-x-3">
                    <Key className="h-5 w-5 text-primary" />
                    <code className="bg-muted px-2 py-1 rounded text-sm">
                      {apiKey.substring(0, 8)}...{apiKey.substring(apiKey.length - 8)}
                    </code>
                  </div>
                  <div className="flex space-x-2">
                    <Button size="sm" variant="outline" onClick={() => copyApiKey(apiKey)}>
                      <Copy className="h-4 w-4 mr-1" />
                      Copy
                    </Button>
                    <Button 
                      size="sm" 
                      variant="destructive" 
                      onClick={() => deleteApiKey(apiKey)}
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      Delete
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {apiKeys.length === 0 && (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Key className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No API Keys</h3>
                <p className="text-muted-foreground">
                  Generate API keys to connect your security agents
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AgentManagement;