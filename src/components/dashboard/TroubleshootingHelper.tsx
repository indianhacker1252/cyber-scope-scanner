import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { 
  AlertCircle, 
  CheckCircle2, 
  Terminal, 
  Settings, 
  Wifi,
  RefreshCw,
  ExternalLink
} from "lucide-react";
import { useState } from "react";

interface TroubleshootingHelperProps {
  errorType?: 'connection' | 'timeout' | 'privilege' | 'tool-missing' | 'scan-failed';
  toolName?: string;
}

const TroubleshootingHelper = ({ errorType = 'connection', toolName }: TroubleshootingHelperProps) => {
  const [expandedSteps, setExpandedSteps] = useState<number[]>([0]);

  const troubleshootingGuides = {
    'connection': {
      title: "Backend Connection Failed",
      description: "Unable to connect to the Kali Linux backend",
      severity: "critical",
      steps: [
        {
          title: "Check Backend is Running",
          commands: ["cd server", "node index.js"],
          description: "Ensure the Node.js backend server is started and listening on port 8080",
          validation: "You should see: 'Backend server running on http://localhost:8080'"
        },
        {
          title: "Verify Port Availability",
          commands: ["lsof -i :8080", "netstat -an | grep 8080"],
          description: "Check if port 8080 is available and not blocked by firewall",
          validation: "Port 8080 should show as LISTEN state"
        },
        {
          title: "Configure API Settings",
          commands: [],
          description: "Open Settings → API Configuration and set Backend URL to 'http://localhost:8080' and WebSocket URL to 'ws://localhost:8080'",
          validation: "Click 'Test Connection' to verify"
        },
        {
          title: "Run Diagnostics",
          commands: [],
          description: "Click the 'Diagnostics' button in the header to test connectivity",
          validation: "All checks should show green/pass status"
        }
      ]
    },
    'timeout': {
      title: "Scan Timeout",
      description: "The scan took too long and was automatically stopped",
      severity: "warning",
      steps: [
        {
          title: "Use Faster Scan Options",
          commands: [],
          description: "Choose 'Basic' or 'Quick' scan modes instead of 'Aggressive' or 'Full' for faster results",
          validation: "Scans should complete within 2-3 minutes"
        },
        {
          title: "Reduce Target Scope",
          commands: [],
          description: "Scan fewer ports or a smaller IP range to avoid timeouts",
          validation: "Try scanning top 100 ports first"
        },
        {
          title: "Check Network Connectivity",
          commands: ["ping 8.8.8.8", "traceroute target-ip"],
          description: "Ensure stable network connection to target",
          validation: "Low latency (<100ms) and no packet loss"
        },
        {
          title: "Increase Timeout Settings",
          commands: [],
          description: "In Advanced Settings, increase scan timeout to 15-20 minutes for large scans",
          validation: "Timeout extended in configuration"
        }
      ]
    },
    'privilege': {
      title: "Insufficient Privileges",
      description: "Some scan techniques require elevated privileges",
      severity: "warning",
      steps: [
        {
          title: "Use Basic Scan Mode",
          commands: [],
          description: "Switch to 'Basic' scan mode which doesn't require root privileges",
          validation: "Basic scans work without sudo"
        },
        {
          title: "Run Backend with Sudo (Advanced)",
          commands: ["sudo node server/index.js"],
          description: "Start the backend server with elevated privileges to enable advanced scanning",
          validation: "SYN scans and OS detection will work"
        },
        {
          title: "Configure Tool Capabilities",
          commands: ["sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap"],
          description: "Grant specific capabilities to tools instead of running as root",
          validation: "Tools can perform privileged operations"
        }
      ]
    },
    'tool-missing': {
      title: "Required Tool Not Found",
      description: `The tool '${toolName}' is not installed or not in PATH`,
      severity: "critical",
      steps: [
        {
          title: "Install Kali Linux Tools",
          commands: ["sudo apt update", "sudo apt install -y kali-linux-default"],
          description: "Install the complete Kali Linux toolset",
          validation: "Tool is accessible in terminal"
        },
        {
          title: "Install Specific Tool",
          commands: [`sudo apt install -y ${toolName?.toLowerCase() || 'tool-name'}`],
          description: `Install only the ${toolName} package`,
          validation: `Run '${toolName?.toLowerCase()} --version' to verify`
        },
        {
          title: "Run Installation Script",
          commands: ["chmod +x install-kali-tools.sh", "./install-kali-tools.sh"],
          description: "Use the provided installation script to set up all required tools",
          validation: "Script should complete without errors"
        },
        {
          title: "Verify PATH Configuration",
          commands: ["echo $PATH", "which nmap"],
          description: "Ensure tools directory is in system PATH",
          validation: "Tool executable should be found"
        }
      ]
    },
    'scan-failed': {
      title: "Scan Failed to Complete",
      description: "The scan encountered errors during execution",
      severity: "error",
      steps: [
        {
          title: "Check Target Accessibility",
          commands: ["ping target-host", "nmap -Pn target-host"],
          description: "Verify the target is reachable and responding",
          validation: "Target responds to ping or TCP probes"
        },
        {
          title: "Review Scan Output",
          commands: [],
          description: "Check the 'Live Output' tab for specific error messages",
          validation: "Identify the exact error from tool output"
        },
        {
          title: "Enable Verbose Mode",
          commands: [],
          description: "Turn on 'Verbose Output' in scan options for detailed debugging",
          validation: "More detailed error information available"
        },
        {
          title: "Try Alternative Tools",
          commands: [],
          description: "If one tool fails, try an alternative (e.g., use masscan instead of nmap)",
          validation: "Alternative tool completes successfully"
        },
        {
          title: "Check Backend Logs",
          commands: ["tail -f /var/log/vapt-backend.log"],
          description: "Review backend server logs for error details",
          validation: "Error cause identified in logs"
        }
      ]
    }
  };

  const guide = troubleshootingGuides[errorType];

  const toggleStep = (index: number) => {
    setExpandedSteps(prev => 
      prev.includes(index) 
        ? prev.filter(i => i !== index)
        : [...prev, index]
    );
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-destructive';
      case 'error': return 'text-destructive';
      case 'warning': return 'text-warning';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <Card className="border-l-4 border-l-warning">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-3">
            <AlertCircle className={`h-6 w-6 mt-1 ${getSeverityColor(guide.severity)}`} />
            <div>
              <CardTitle>{guide.title}</CardTitle>
              <CardDescription className="mt-1">{guide.description}</CardDescription>
            </div>
          </div>
          <Badge variant={guide.severity === 'critical' ? 'destructive' : 'default'}>
            {guide.severity}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Alert>
          <Settings className="h-4 w-4" />
          <AlertTitle>Quick Fix Steps</AlertTitle>
          <AlertDescription>
            Follow these steps in order to resolve the issue. Most problems can be fixed in 2-3 minutes.
          </AlertDescription>
        </Alert>

        <div className="space-y-3">
          {guide.steps.map((step, index) => (
            <Card 
              key={index}
              className={`cursor-pointer transition-all ${expandedSteps.includes(index) ? 'bg-muted/30' : ''}`}
              onClick={() => toggleStep(index)}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3 flex-1">
                    <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/10 text-primary text-sm font-medium mt-0.5">
                      {index + 1}
                    </div>
                    <div className="flex-1">
                      <h4 className="font-medium mb-1">{step.title}</h4>
                      {expandedSteps.includes(index) && (
                        <div className="space-y-3 mt-3">
                          <p className="text-sm text-muted-foreground">{step.description}</p>
                          
                          {step.commands.length > 0 && (
                            <div className="space-y-2">
                              <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                                <Terminal className="h-3 w-3" />
                                <span>Commands to run:</span>
                              </div>
                              <div className="bg-black/90 text-green-400 p-3 rounded font-mono text-xs space-y-1">
                                {step.commands.map((cmd, cmdIndex) => (
                                  <div key={cmdIndex} className="flex items-center justify-between group">
                                    <span>$ {cmd}</span>
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      className="h-6 px-2 opacity-0 group-hover:opacity-100 transition-opacity"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        navigator.clipboard.writeText(cmd);
                                      }}
                                    >
                                      Copy
                                    </Button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          <div className="flex items-start space-x-2 bg-success/10 text-success p-2 rounded text-xs">
                            <CheckCircle2 className="h-4 w-4 mt-0.5 flex-shrink-0" />
                            <span><strong>Validation:</strong> {step.validation}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="flex items-center justify-between pt-4 border-t">
          <Button variant="outline" size="sm">
            <ExternalLink className="h-4 w-4 mr-2" />
            View Full Documentation
          </Button>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <RefreshCw className="h-4 w-4 mr-2" />
              Re-test
            </Button>
            <Button size="sm">
              Mark as Resolved
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default TroubleshootingHelper;
