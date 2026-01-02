import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAILearning } from "@/hooks/useAILearning";
import { useToast } from "@/hooks/use-toast";
import { 
  Brain, 
  TrendingUp, 
  Target, 
  CheckCircle, 
  XCircle,
  Lightbulb,
  BarChart3,
  Clock,
  Zap,
  RefreshCw,
  AlertTriangle,
  Shield,
  Activity
} from "lucide-react";

interface LearningSummary {
  total_learnings: number;
  tools_used: number;
  overall_success_rate: number;
  by_tool: Array<{
    tool: string;
    success_rate: number;
    total_scans: number;
    total_findings: number;
  }>;
  recent_improvements: string[];
  last_scan: string | null;
}

const AILearningDashboard = () => {
  const { toast } = useToast();
  const { getLearningSummary, analyzeImprovement, lastAnalysis } = useAILearning();
  const [summary, setSummary] = useState<LearningSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [toolAnalysis, setToolAnalysis] = useState<any>(null);

  const loadSummary = async () => {
    setIsLoading(true);
    try {
      const data = await getLearningSummary();
      setSummary(data);
    } catch (error) {
      console.error('Failed to load learning summary:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, []);

  const handleToolAnalysis = async (tool: string) => {
    setSelectedTool(tool);
    try {
      const analysis = await analyzeImprovement(tool);
      setToolAnalysis(analysis);
    } catch (error) {
      console.error('Failed to analyze tool:', error);
    }
  };

  const getSuccessRateColor = (rate: number) => {
    if (rate >= 80) return "text-green-500";
    if (rate >= 60) return "text-yellow-500";
    if (rate >= 40) return "text-orange-500";
    return "text-red-500";
  };

  const getSuccessRateBg = (rate: number) => {
    if (rate >= 80) return "bg-green-500/20";
    if (rate >= 60) return "bg-yellow-500/20";
    if (rate >= 40) return "bg-orange-500/20";
    return "bg-red-500/20";
  };

  const stats = summary ? [
    { label: "Total Learnings", value: summary.total_learnings, icon: Brain, color: "text-primary" },
    { label: "Tools Used", value: summary.tools_used, icon: Target, color: "text-blue-500" },
    { label: "Success Rate", value: `${summary.overall_success_rate.toFixed(1)}%`, icon: TrendingUp, color: getSuccessRateColor(summary.overall_success_rate) },
    { label: "Improvements", value: summary.recent_improvements.length, icon: Lightbulb, color: "text-yellow-500" },
  ] : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Brain className="h-6 w-6 text-primary animate-pulse" />
              <CardTitle>AI Learning Dashboard</CardTitle>
            </div>
            <Button variant="outline" size="sm" onClick={loadSummary} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
          <CardDescription>
            Monitor AI learning progress, success rates, and improvement strategies across all security modules
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Stats Overview */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <Card key={index} className="bg-gradient-to-br from-card to-muted/50">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{stat.label}</p>
                      <p className="text-3xl font-bold">{stat.value}</p>
                    </div>
                    <Icon className={`h-8 w-8 ${stat.color}`} />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview" className="flex items-center gap-1">
            <BarChart3 className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="tools" className="flex items-center gap-1">
            <Target className="h-4 w-4" />
            By Tool
          </TabsTrigger>
          <TabsTrigger value="improvements" className="flex items-center gap-1">
            <Lightbulb className="h-4 w-4" />
            Improvements
          </TabsTrigger>
          <TabsTrigger value="insights" className="flex items-center gap-1">
            <Zap className="h-4 w-4" />
            AI Insights
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Success Rate Gauge */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-primary" />
                  Overall Success Rate
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col items-center justify-center py-8">
                  <div className={`text-6xl font-bold ${getSuccessRateColor(summary?.overall_success_rate || 0)}`}>
                    {summary?.overall_success_rate.toFixed(1) || 0}%
                  </div>
                  <Progress 
                    value={summary?.overall_success_rate || 0} 
                    className="w-full h-3 mt-4"
                  />
                  <p className="text-sm text-muted-foreground mt-2">
                    Based on {summary?.total_learnings || 0} learning entries
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Clock className="h-5 w-5 text-primary" />
                  Learning Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {summary?.last_scan ? (
                    <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                      <Activity className="h-5 w-5 text-primary animate-pulse" />
                      <div>
                        <p className="font-medium">Last Learning Recorded</p>
                        <p className="text-sm text-muted-foreground">
                          {new Date(summary.last_scan).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No learning data yet. Run some scans to start learning!</p>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                    <div className="text-center">
                      <p className="text-2xl font-bold text-green-500">
                        {summary?.by_tool.reduce((sum, t) => sum + (t.success_rate >= 50 ? 1 : 0), 0) || 0}
                      </p>
                      <p className="text-xs text-muted-foreground">High-performing tools</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-orange-500">
                        {summary?.by_tool.reduce((sum, t) => sum + (t.success_rate < 50 ? 1 : 0), 0) || 0}
                      </p>
                      <p className="text-xs text-muted-foreground">Need improvement</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* By Tool Tab */}
        <TabsContent value="tools" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Tool Performance</CardTitle>
              <CardDescription>Success rates and findings by security tool</CardDescription>
            </CardHeader>
            <CardContent>
              {summary?.by_tool.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No tool data yet. Start scanning to build the knowledge base.</p>
                </div>
              ) : (
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {summary?.by_tool.map((tool, index) => (
                      <Card 
                        key={index} 
                        className={`p-4 cursor-pointer hover:bg-muted/50 transition-colors ${
                          selectedTool === tool.tool ? 'border-primary' : ''
                        }`}
                        onClick={() => handleToolAnalysis(tool.tool)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className={`p-2 rounded-full ${getSuccessRateBg(tool.success_rate)}`}>
                              {tool.success_rate >= 50 ? (
                                <CheckCircle className={`h-5 w-5 ${getSuccessRateColor(tool.success_rate)}`} />
                              ) : (
                                <AlertTriangle className={`h-5 w-5 ${getSuccessRateColor(tool.success_rate)}`} />
                              )}
                            </div>
                            <div>
                              <p className="font-medium uppercase">{tool.tool}</p>
                              <p className="text-sm text-muted-foreground">
                                {tool.total_scans} scans • {tool.total_findings} findings
                              </p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className={`text-2xl font-bold ${getSuccessRateColor(tool.success_rate)}`}>
                              {tool.success_rate.toFixed(0)}%
                            </p>
                            <Progress value={tool.success_rate} className="w-24 h-2" />
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>

          {/* Tool Analysis Panel */}
          {selectedTool && toolAnalysis && (
            <Card className="border-primary/30">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Zap className="h-5 w-5 text-primary" />
                  Analysis: {selectedTool.toUpperCase()}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {toolAnalysis.insights && (
                    <div className="p-4 bg-primary/10 rounded-lg">
                      <p className="text-sm">{toolAnalysis.insights}</p>
                    </div>
                  )}
                  {toolAnalysis.metrics && (
                    <div className="grid grid-cols-3 gap-4">
                      <div className="text-center">
                        <p className="text-xl font-bold">{toolAnalysis.metrics.success_rate?.toFixed(1) || 0}%</p>
                        <p className="text-xs text-muted-foreground">Success Rate</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold">{toolAnalysis.metrics.trend || 'stable'}</p>
                        <p className="text-xs text-muted-foreground">Trend</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold">{toolAnalysis.metrics.avg_findings || 0}</p>
                        <p className="text-xs text-muted-foreground">Avg Findings</p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Improvements Tab */}
        <TabsContent value="improvements" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Lightbulb className="h-5 w-5 text-yellow-500" />
                Recent Improvement Strategies
              </CardTitle>
              <CardDescription>AI-generated strategies to enhance scan effectiveness</CardDescription>
            </CardHeader>
            <CardContent>
              {summary?.recent_improvements.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Lightbulb className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No improvement strategies yet. Keep scanning to generate insights!</p>
                </div>
              ) : (
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {summary?.recent_improvements.map((improvement, index) => (
                      <Card key={index} className="p-4 bg-yellow-500/5 border-yellow-500/20">
                        <div className="flex gap-3">
                          <Lightbulb className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                          <p className="text-sm">{improvement}</p>
                        </div>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Insights Tab */}
        <TabsContent value="insights" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Last Analysis */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Brain className="h-5 w-5 text-primary" />
                  Latest AI Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                {lastAnalysis ? (
                  <div className="space-y-4">
                    <div className="p-4 bg-muted/50 rounded-lg">
                      <p className="text-sm font-medium mb-2">Analysis</p>
                      <p className="text-sm text-muted-foreground">{lastAnalysis.analysis}</p>
                    </div>
                    <div className="p-4 bg-primary/10 rounded-lg">
                      <p className="text-sm font-medium mb-2">Improvement Strategy</p>
                      <p className="text-sm">{lastAnalysis.improvement_strategy}</p>
                    </div>
                    <div className="flex items-center justify-between pt-4 border-t">
                      <span className="text-sm text-muted-foreground">Success Rate</span>
                      <span className={`text-lg font-bold ${getSuccessRateColor(lastAnalysis.success_rate)}`}>
                        {lastAnalysis.success_rate.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No recent analysis. Run a scan to get AI insights.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Learning Tips */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  Learning Tips
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                    <div>
                      <p className="font-medium text-sm">Run diverse scan types</p>
                      <p className="text-xs text-muted-foreground">Use different tools to build comprehensive knowledge</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                    <div>
                      <p className="font-medium text-sm">Scan multiple targets</p>
                      <p className="text-xs text-muted-foreground">Different targets help AI learn patterns</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                    <div>
                      <p className="font-medium text-sm">Review AI recommendations</p>
                      <p className="text-xs text-muted-foreground">Apply suggested strategies for better results</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                    <div>
                      <p className="font-medium text-sm">Use full vulnerability scans</p>
                      <p className="text-xs text-muted-foreground">Complete scans provide richer learning data</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* Loading State */}
      {isLoading && !summary && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <span className="ml-3 text-muted-foreground">Loading learning data...</span>
        </div>
      )}
    </div>
  );
};

export default AILearningDashboard;
