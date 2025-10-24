import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Lightbulb, ExternalLink, Loader2, Settings } from "lucide-react";
import exaService from "@/utils/exaService";
import { useToast } from "@/hooks/use-toast";

interface ExaInsightsProps {
  scanData?: {
    target: string;
    tool: string;
    findings: any[];
    output: string;
  };
}

export const ExaInsights = ({ scanData }: ExaInsightsProps) => {
  const { toast } = useToast();
  const [apiKey, setApiKey] = useState(exaService.getApiKey() || "");
  const [recommendations, setRecommendations] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showApiKeyInput, setShowApiKeyInput] = useState(!exaService.hasApiKey());

  const handleSetApiKey = () => {
    if (!apiKey) {
      toast({
        title: "API Key Required",
        description: "Please enter your Exa.ai API key",
        variant: "destructive"
      });
      return;
    }
    exaService.setApiKey(apiKey);
    setShowApiKeyInput(false);
    toast({
      title: "API Key Saved",
      description: "Exa.ai integration is now active"
    });
  };

  const handleAnalyze = async () => {
    if (!exaService.hasApiKey()) {
      setShowApiKeyInput(true);
      toast({
        title: "API Key Required",
        description: "Please configure your Exa.ai API key first",
        variant: "destructive"
      });
      return;
    }

    if (!scanData) {
      toast({
        title: "No Scan Data",
        description: "Please perform a scan first",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    try {
      const result = await exaService.analyzeScanResults(scanData);
      setRecommendations(result);
      toast({
        title: "Analysis Complete",
        description: "Exa.ai has generated recommendations for your scan"
      });
    } catch (error: any) {
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (showApiKeyInput) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lightbulb className="h-5 w-5 text-yellow-500" />
            Exa.ai Integration Setup
          </CardTitle>
          <CardDescription>
            Configure Exa.ai to get AI-powered recommendations for better vulnerability assessments
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Exa.ai API Key</label>
            <Input
              type="password"
              placeholder="Enter your Exa.ai API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Get your API key from{" "}
              <a
                href="https://exa.ai"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                exa.ai
              </a>
            </p>
          </div>
          <div className="flex gap-2">
            <Button onClick={handleSetApiKey}>Save API Key</Button>
            <Button variant="outline" onClick={() => setShowApiKeyInput(false)}>
              Cancel
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-yellow-500" />
              Exa.ai Insights
            </CardTitle>
            <CardDescription>
              AI-powered recommendations for better VAPT
            </CardDescription>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowApiKeyInput(true)}
          >
            <Settings className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {!scanData ? (
          <div className="text-center text-muted-foreground py-8">
            <Lightbulb className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>Perform a scan to get AI-powered recommendations</p>
          </div>
        ) : !recommendations ? (
          <Button onClick={handleAnalyze} disabled={isLoading} className="w-full">
            {isLoading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Lightbulb className="h-4 w-4 mr-2" />
                Generate Recommendations
              </>
            )}
          </Button>
        ) : (
          <ScrollArea className="h-[400px]">
            <div className="space-y-4">
              {/* Immediate Actions */}
              {recommendations.immediate_actions?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold flex items-center gap-2">
                    <Badge variant="destructive">Urgent</Badge>
                    Immediate Actions
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    {recommendations.immediate_actions.map((action: string, idx: number) => (
                      <li key={idx}>{action}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Best Practices */}
              {recommendations.best_practices?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold flex items-center gap-2">
                    <Badge>Best Practices</Badge>
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    {recommendations.best_practices.map((practice: string, idx: number) => (
                      <li key={idx}>{practice}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Remediation Steps */}
              {recommendations.remediation_steps?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold flex items-center gap-2">
                    <Badge variant="secondary">Remediation</Badge>
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    {recommendations.remediation_steps.map((step: string, idx: number) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* References */}
              {recommendations.references?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold">References</h4>
                  <div className="space-y-2">
                    {recommendations.references.map((ref: any, idx: number) => (
                      <a
                        key={idx}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block p-3 border rounded-lg hover:bg-accent transition-colors"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <p className="font-medium text-sm">{ref.title}</p>
                            <p className="text-xs text-muted-foreground mt-1">
                              {ref.snippet}
                            </p>
                          </div>
                          <ExternalLink className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                        </div>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              <Button
                variant="outline"
                onClick={handleAnalyze}
                disabled={isLoading}
                className="w-full mt-4"
              >
                Refresh Analysis
              </Button>
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
};
