import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Shield, Search, AlertTriangle, Activity } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

export const ThreatIntelligence = () => {
  const [query, setQuery] = useState("");
  const [analysisType, setAnalysisType] = useState("ioc-analysis");
  const [analysis, setAnalysis] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const analyzeIntelligence = async () => {
    if (!query.trim()) {
      toast({ title: "Input required", description: "Please enter data to analyze", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('threat-intelligence', {
        body: { query, type: analysisType }
      });

      if (error) throw error;
      setAnalysis(data.analysis);
      toast({ title: "Analysis complete", description: "Threat intelligence generated" });
    } catch (error: any) {
      console.error('Threat intelligence error:', error);
      toast({ 
        title: "Analysis failed", 
        description: error.message,
        variant: "destructive" 
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary" />
            <div>
              <CardTitle>Threat Intelligence Platform</CardTitle>
              <CardDescription>AI-powered threat analysis and intelligence</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Analysis Type</label>
            <Select value={analysisType} onValueChange={setAnalysisType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ioc-analysis">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    IOC Analysis
                  </div>
                </SelectItem>
                <SelectItem value="malware-analysis">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4" />
                    Malware Analysis
                  </div>
                </SelectItem>
                <SelectItem value="threat-hunting">
                  <div className="flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Threat Hunting
                  </div>
                </SelectItem>
                <SelectItem value="vulnerability-intel">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Vulnerability Intelligence
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Input Data</label>
            <Textarea
              placeholder="Enter IOC, malware hash, CVE ID, or threat description..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              rows={6}
              className="font-mono"
            />
          </div>

          <Button onClick={analyzeIntelligence} disabled={isLoading} className="w-full">
            {isLoading ? "Analyzing..." : "Analyze Threat Intelligence"}
          </Button>

          {analysis && (
            <div className="mt-4 p-4 bg-muted rounded-lg">
              <h3 className="font-semibold mb-2">Analysis Results</h3>
              <div className="whitespace-pre-wrap text-sm">{analysis}</div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
