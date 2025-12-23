import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface LearningEntry {
  tool_used: string;
  target: string;
  findings: any;
  success: boolean;
  execution_time: number;
  context?: any;
}

interface LearningAnalysis {
  analysis: string;
  improvement_strategy: string;
  success_rate: number;
}

interface Recommendations {
  confidence_level: number;
  suggested_approach: string;
  common_findings: string[];
  avoid_patterns: string[];
  estimated_duration: number;
  tips: string[];
}

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

export function useAILearning() {
  const { toast } = useToast();
  const [isRecording, setIsRecording] = useState(false);
  const [lastAnalysis, setLastAnalysis] = useState<LearningAnalysis | null>(null);

  const recordLearning = useCallback(async (entry: LearningEntry): Promise<LearningAnalysis | null> => {
    setIsRecording(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-learning', {
        body: {
          action: 'record-learning',
          data: entry
        }
      });

      if (error) throw error;

      const analysis = data.analysis as LearningAnalysis;
      setLastAnalysis(analysis);

      // Show improvement suggestion if available
      if (analysis?.improvement_strategy && !analysis.improvement_strategy.includes('not available')) {
        toast({
          title: "AI Learning Recorded",
          description: analysis.improvement_strategy.substring(0, 100) + '...',
        });
      }

      return analysis;
    } catch (error: any) {
      console.error('Error recording learning:', error);
      // Don't show error toast - AI learning is secondary functionality
      return null;
    } finally {
      setIsRecording(false);
    }
  }, [toast]);

  const getRecommendations = useCallback(async (
    tool: string, 
    target: string, 
    context?: any
  ): Promise<Recommendations | null> => {
    try {
      const { data, error } = await supabase.functions.invoke('ai-learning', {
        body: {
          action: 'get-recommendations',
          data: { tool, target, context }
        }
      });

      if (error) throw error;
      return data.recommendations as Recommendations;
    } catch (error: any) {
      console.error('Error getting recommendations:', error);
      return null;
    }
  }, []);

  const getLearningSummary = useCallback(async (): Promise<LearningSummary | null> => {
    try {
      const { data, error } = await supabase.functions.invoke('ai-learning', {
        body: {
          action: 'get-learning-summary',
          data: {}
        }
      });

      if (error) throw error;
      return data.summary as LearningSummary;
    } catch (error: any) {
      console.error('Error getting learning summary:', error);
      return null;
    }
  }, []);

  const analyzeImprovement = useCallback(async (tool: string, target?: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('ai-learning', {
        body: {
          action: 'analyze-improvement',
          data: { tool, target }
        }
      });

      if (error) throw error;
      return data;
    } catch (error: any) {
      console.error('Error analyzing improvement:', error);
      return null;
    }
  }, []);

  // Helper function to wrap scan execution with learning
  const withLearning = useCallback(async <T>(
    tool: string,
    target: string,
    scanFn: () => Promise<{ findings: any[]; output: string; success?: boolean }>,
    context?: any
  ): Promise<{ result: T | null; analysis: LearningAnalysis | null }> => {
    const startTime = Date.now();
    
    try {
      const result = await scanFn();
      const executionTime = Date.now() - startTime;
      
      // Record the learning in background
      const analysis = await recordLearning({
        tool_used: tool,
        target,
        findings: result.findings || [],
        success: result.success ?? (result.findings?.length >= 0),
        execution_time: executionTime,
        context
      });

      return { result: result as unknown as T, analysis };
    } catch (error: any) {
      const executionTime = Date.now() - startTime;
      
      // Record failure
      const analysis = await recordLearning({
        tool_used: tool,
        target,
        findings: [],
        success: false,
        execution_time: executionTime,
        context: { ...context, error: error.message }
      });

      return { result: null, analysis };
    }
  }, [recordLearning]);

  return {
    recordLearning,
    getRecommendations,
    getLearningSummary,
    analyzeImprovement,
    withLearning,
    isRecording,
    lastAnalysis
  };
}
