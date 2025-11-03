import { supabase } from '@/integrations/supabase/client';

export default class ExaService {
  async analyzeScanResults(scanData: {
    target: string;
    tool: string;
    findings: any[];
    output: string;
  }) {
    const { data, error } = await supabase.functions.invoke('exa-proxy', {
      body: {
        action: 'analyze-scan',
        data: scanData
      }
    });

    if (error) {
      console.error('Exa proxy error:', error);
      throw new Error('Failed to analyze scan results');
    }

    return data.result;
  }

  async getExploitTechniques(vulnerabilityType: string, target: string) {
    const { data, error } = await supabase.functions.invoke('exa-proxy', {
      body: {
        action: 'get-exploits',
        data: { vulnerabilityType, target }
      }
    });

    if (error) {
      console.error('Exa proxy error:', error);
      throw new Error('Failed to get exploit techniques');
    }

    return data.result;
  }

  async getScanStrategy(targetInfo: { target: string; scanType: string; scope: string }) {
    const { data, error } = await supabase.functions.invoke('exa-proxy', {
      body: {
        action: 'get-strategy',
        data: targetInfo
      }
    });

    if (error) {
      console.error('Exa proxy error:', error);
      throw new Error('Failed to get scan strategy');
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
}
