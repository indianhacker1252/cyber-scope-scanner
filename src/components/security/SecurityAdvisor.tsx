import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Brain, Shield, Cloud, Code, Lock, FileSearch, Users, Settings, AlertTriangle, Database, GitBranch, User } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

export const SecurityAdvisor = () => {
  const [domain, setDomain] = useState("network-security");
  const [task, setTask] = useState("");
  const [advice, setAdvice] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const domains = [
    { value: "network-security", label: "Network Security", icon: Shield },
    { value: "incident-response", label: "Incident Response", icon: AlertTriangle },
    { value: "cloud-security", label: "Cloud Security", icon: Cloud },
    { value: "application-security", label: "Application Security", icon: Code },
    { value: "cryptography", label: "Cryptography", icon: Lock },
    { value: "compliance", label: "Compliance & Regulation", icon: FileSearch },
    { value: "threat-intelligence", label: "Threat Intelligence", icon: Brain },
    { value: "forensics", label: "Digital Forensics", icon: Database },
    { value: "iam", label: "IAM", icon: User },
    { value: "devsecops", label: "DevSecOps", icon: GitBranch },
    { value: "social-engineering", label: "Social Engineering", icon: Users },
    { value: "siem", label: "SIEM & Log Analysis", icon: Settings },
    { value: "risk-management", label: "Risk Management", icon: AlertTriangle },
  ];

  const getAdvice = async () => {
    if (!task.trim()) {
      toast({ title: "Input required", description: "Please describe your security challenge", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('security-advisor', {
        body: { domain, task }
      });

      if (error) throw error;
      setAdvice(data.advice);
      toast({ title: "Advice generated", description: "Expert guidance ready" });
    } catch (error: any) {
      console.error('Security advisor error:', error);
      toast({ 
        title: "Advice generation failed", 
        description: error.message,
        variant: "destructive" 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const selectedDomain = domains.find(d => d.value === domain);
  const DomainIcon = selectedDomain?.icon || Shield;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Brain className="w-6 h-6 text-primary" />
            <div>
              <CardTitle>AI Security Advisor</CardTitle>
              <CardDescription>Expert guidance across all security domains</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Security Domain</label>
            <Select value={domain} onValueChange={setDomain}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {domains.map(({ value, label, icon: Icon }) => (
                  <SelectItem key={value} value={value}>
                    <div className="flex items-center gap-2">
                      <Icon className="w-4 h-4" />
                      {label}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Your Question or Challenge</label>
            <Textarea
              placeholder="Describe your security challenge, question, or scenario..."
              value={task}
              onChange={(e) => setTask(e.target.value)}
              rows={6}
            />
          </div>

          <Button onClick={getAdvice} disabled={isLoading} className="w-full">
            <DomainIcon className="w-4 h-4 mr-2" />
            {isLoading ? "Generating Advice..." : "Get Expert Advice"}
          </Button>

          {advice && (
            <div className="mt-4 p-4 bg-muted rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <DomainIcon className="w-5 h-5 text-primary" />
                <h3 className="font-semibold">{selectedDomain?.label} Guidance</h3>
              </div>
              <div className="whitespace-pre-wrap text-sm leading-relaxed">{advice}</div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Expert Certifications</CardTitle>
          <CardDescription>This AI advisor has knowledge equivalent to:</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
            {[
              "CISSP", "OSCP", "CISM", "CEH", "CCSP", "GCIH",
              "GCFA", "GCFE", "GPEN", "GWAPT", "OSWE", "OSED",
              "CRISC", "CISA", "CompTIA Security+", "CySA+"
            ].map(cert => (
              <div key={cert} className="flex items-center gap-2 p-2 bg-muted rounded">
                <Shield className="w-4 h-4 text-primary" />
                <span>{cert}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
