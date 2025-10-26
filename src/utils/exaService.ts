import Exa from "exa-js";

export default class ExaService {
  private client: Exa | null = null;
  private apiKey: string | null = null;

  constructor() {
    this.apiKey = localStorage.getItem('exa_api_key');
    if (this.apiKey) {
      this.initializeClient();
    }
  }

  private initializeClient() {
    if (this.apiKey) {
      this.client = new Exa(this.apiKey);
    }
  }

  setApiKey(apiKey: string) {
    this.apiKey = apiKey;
    localStorage.setItem('exa_api_key', apiKey);
    this.initializeClient();
  }

  getApiKey() {
    return this.apiKey;
  }

  hasApiKey() {
    return !!this.apiKey;
  }

  clearApiKey() {
    this.apiKey = null;
    localStorage.removeItem('exa_api_key');
    this.client = null;
  }

  async analyzeScanResults(scanData: {
    target: string;
    tool: string;
    findings: any[];
    output: string;
  }) {
    if (!this.client) {
      throw new Error('Exa API key not configured');
    }

    const query = `vulnerability assessment ${scanData.tool} ${scanData.target} security best practices remediation`;
    
    const searchResults = await this.client.searchAndContents(query, {
      type: "neural",
      useAutoprompt: true,
      numResults: 5,
      text: true
    });

    return this.generateRecommendations(scanData, searchResults);
  }

  private generateRecommendations(scanData: any, searchResults: any) {
    const recommendations = {
      immediate_actions: [] as string[],
      best_practices: [] as string[],
      remediation_steps: [] as string[],
      references: [] as { title: string; url: string; snippet: string }[]
    };

    // Extract relevant information from search results
    searchResults.results.forEach((result: any) => {
      recommendations.references.push({
        title: result.title,
        url: result.url,
        snippet: result.text?.substring(0, 200) || ''
      });
    });

    // Analyze findings and generate recommendations
    scanData.findings.forEach((finding: any) => {
      if (finding.severity === 'critical' || finding.severity === 'high') {
        recommendations.immediate_actions.push(
          `Address ${finding.type || 'vulnerability'} on ${scanData.target} immediately`
        );
      }
      
      recommendations.remediation_steps.push(
        `Review and patch ${finding.type || 'issue'} identified by ${scanData.tool}`
      );
    });

    return recommendations;
  }

  async getExploitTechniques(vulnerabilityType: string, target: string) {
    if (!this.client) {
      throw new Error('Exa API key not configured');
    }

    const query = `${vulnerabilityType} exploitation techniques ${target} penetration testing methodology`;
    
    const searchResults = await this.client.searchAndContents(query, {
      type: "neural",
      useAutoprompt: true,
      numResults: 3,
      text: true
    });

    return searchResults.results.map((result: any) => ({
      title: result.title,
      url: result.url,
      technique: result.text?.substring(0, 500) || '',
      score: result.score
    }));
  }

  async getScanStrategy(targetInfo: { target: string; scanType: string; scope: string }) {
    if (!this.client) {
      throw new Error('Exa API key not configured');
    }

    const query = `${targetInfo.scanType} vulnerability assessment strategy ${targetInfo.target} ${targetInfo.scope} best practices`;
    
    const searchResults = await this.client.searchAndContents(query, {
      type: "neural",
      useAutoprompt: true,
      numResults: 5,
      text: true
    });

    return {
      recommended_tools: this.extractTools(searchResults),
      scan_sequence: this.generateScanSequence(targetInfo),
      expected_duration: this.estimateDuration(targetInfo.scanType),
      references: searchResults.results.map((r: any) => ({
        title: r.title,
        url: r.url
      }))
    };
  }

  private extractTools(searchResults: any): string[] {
    const commonTools = ['nmap', 'nikto', 'sqlmap', 'gobuster', 'nuclei', 'metasploit', 'burpsuite'];
    const tools: string[] = [];
    
    searchResults.results.forEach((result: any) => {
      const text = result.text?.toLowerCase() || '';
      commonTools.forEach(tool => {
        if (text.includes(tool) && !tools.includes(tool)) {
          tools.push(tool);
        }
      });
    });
    
    return tools.slice(0, 5);
  }

  private generateScanSequence(targetInfo: any): string[] {
    const sequences: Record<string, string[]> = {
      'network': ['Port Scanning', 'Service Detection', 'Vulnerability Assessment', 'Exploit Testing'],
      'web': ['Technology Detection', 'Directory Enumeration', 'SQL Injection Testing', 'XSS Testing'],
      'database': ['Port Detection', 'Version Detection', 'Authentication Testing', 'SQL Injection'],
      'comprehensive': ['Reconnaissance', 'Network Scanning', 'Web Testing', 'Database Testing', 'Reporting']
    };
    
    return sequences[targetInfo.scanType] || sequences['comprehensive'];
  }

  private estimateDuration(scanType: string): string {
    const durations: Record<string, string> = {
      'network': '5-15 minutes',
      'web': '10-30 minutes',
      'database': '5-20 minutes',
      'comprehensive': '30-60 minutes'
    };
    
    return durations[scanType] || '15-45 minutes';
  }
}

