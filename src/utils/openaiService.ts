import { supabase } from '@/integrations/supabase/client';

class OpenAIService {
  async analyzeVulnerabilities(scanResults: any[]) {
    const { data, error } = await supabase.functions.invoke('openai-proxy', {
      body: {
        action: 'analyze-vulnerabilities',
        data: { scanResults }
      }
    });

    if (error) {
      console.error('OpenAI proxy error:', error);
      throw new Error('Failed to analyze vulnerabilities');
    }

    return data.result;
  }

  async generatePayloads(vulnerabilityType: string, target: string, context?: string) {
    const { data, error } = await supabase.functions.invoke('openai-proxy', {
      body: {
        action: 'generate-payloads',
        data: { vulnerabilityType, target, context }
      }
    });

    if (error) {
      console.error('OpenAI proxy error:', error);
      throw new Error('Failed to generate payloads');
    }

    return data.result;
  }

  async generateTechnicalReport(analysisData: any, scanResults: any[]) {
    const { data, error } = await supabase.functions.invoke('openai-proxy', {
      body: {
        action: 'generate-report',
        data: { analysisData, scanResults }
      }
    });

    if (error) {
      console.error('OpenAI proxy error:', error);
      throw new Error('Failed to generate report');
    }

    return data.result;
  }

  async generateCompletion(prompt: string, options?: { maxTokens?: number; temperature?: number }) {
    // This method provides backward compatibility for components that need direct chat completion
    const { data, error } = await supabase.functions.invoke('openai-proxy', {
      body: {
        action: 'custom-completion',
        data: { 
          prompt,
          maxTokens: options?.maxTokens || 3000,
          temperature: options?.temperature || 0.3
        }
      }
    });

    if (error) {
      console.error('OpenAI proxy error:', error);
      throw new Error('Failed to generate completion');
    }

    return data.result;
  }

  // Legacy methods for backward compatibility - now throw errors directing to secure implementation
  hasApiKey() {
    return false;
  }

  getApiKey() {
    return null;
  }

  setApiKey(apiKey: string) {
    throw new Error('API keys are now securely managed on the backend. This method is deprecated.');
  }

  clearApiKey() {
    // No-op for backward compatibility
  }

  getClient() {
    // Return a proxy object that mimics the OpenAI client interface
    return {
      chat: {
        completions: {
          create: async (params: any) => {
            const prompt = params.messages?.map((m: any) => m.content).join('\n') || '';
            const result = await this.generateCompletion(prompt, {
              maxTokens: params.max_tokens,
              temperature: params.temperature
            });
            
            return {
              choices: [{
                message: {
                  content: result
                }
              }]
            };
          }
        }
      }
    };
  }
}

export default new OpenAIService();
