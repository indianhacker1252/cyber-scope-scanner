import OpenAI from 'openai';

class OpenAIService {
  private client: OpenAI | null = null;
  private apiKey: string | null = null;

  constructor() {
    // Check for API key in localStorage
    this.apiKey = localStorage.getItem('openai_api_key');
    if (this.apiKey) {
      this.initializeClient();
    }
  }

  private initializeClient() {
    if (this.apiKey) {
      this.client = new OpenAI({
        apiKey: this.apiKey,
        dangerouslyAllowBrowser: true
      });
    }
  }

  setApiKey(apiKey: string) {
    this.apiKey = apiKey;
    localStorage.setItem('openai_api_key', apiKey);
    this.initializeClient();
  }

  getApiKey() {
    return this.apiKey;
  }

  hasApiKey() {
    return !!this.apiKey;
  }

  getClient() {
    return this.client;
  }

  clearApiKey() {
    this.apiKey = null;
    localStorage.removeItem('openai_api_key');
    this.client = null;
  }

  async analyzeVulnerabilities(scanResults: any[]) {
    if (!this.client) {
      throw new Error('OpenAI API key not configured');
    }

    const vulnerabilityData = scanResults.map(result => ({
      tool: result.tool,
      target: result.target,
      findings: result.findings,
      output: result.output?.substring(0, 2000) // Limit output length
    }));

    const prompt = `
You are a cybersecurity expert. Analyze the following vulnerability scan results and provide a comprehensive security assessment:

Scan Results:
${JSON.stringify(vulnerabilityData, null, 2)}

Please provide:
1. Executive Summary
2. Critical Vulnerabilities (if any)
3. Risk Assessment (High/Medium/Low)
4. Detailed Analysis of each finding
5. Remediation Recommendations
6. Attack Vectors that could exploit these vulnerabilities
7. Compliance Impact (OWASP, NIST, etc.)

Format your response in clear sections with actionable insights.
`;

    const completion = await this.client.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2000,
      temperature: 0.3
    });

    return completion.choices[0]?.message?.content || 'Analysis failed';
  }

  async generatePayloads(vulnerabilityType: string, target: string, context?: string) {
    if (!this.client) {
      throw new Error('OpenAI API key not configured');
    }

    const prompt = `
You are a penetration testing expert. Generate modern, effective payloads for testing the following vulnerability:

Vulnerability Type: ${vulnerabilityType}
Target: ${target}
Context: ${context || 'General testing'}

Generate payloads for:
1. Initial Discovery/Detection
2. Exploitation Attempts
3. Privilege Escalation (if applicable)
4. Data Extraction (if applicable)
5. Persistence (if applicable)

Important: 
- Provide payloads for educational/authorized testing only
- Include detection evasion techniques
- Explain the purpose of each payload
- Include both manual and automated testing approaches
- Focus on latest techniques (2024)

Format as JSON with categories and explanations.
`;

    const completion = await this.client.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 1500,
      temperature: 0.7
    });

    return completion.choices[0]?.message?.content || 'Payload generation failed';
  }

  async generateTechnicalReport(analysisData: any, scanResults: any[]) {
    if (!this.client) {
      throw new Error('OpenAI API key not configured');
    }

    const prompt = `
Generate a professional penetration testing report based on the following data:

Analysis: ${analysisData}
Scan Results: ${JSON.stringify(scanResults.slice(0, 3), null, 2)}

Create a comprehensive report with:
1. Executive Summary
2. Methodology
3. Findings Summary Table
4. Detailed Technical Findings
5. Risk Matrix
6. Recommendations
7. Appendices

Use professional cybersecurity report formatting and include CVSS scores where applicable.
`;

    const completion = await this.client.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2500,
      temperature: 0.2
    });

    return completion.choices[0]?.message?.content || 'Report generation failed';
  }
}

export default new OpenAIService();