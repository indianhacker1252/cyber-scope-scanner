import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain, task } = await req.json();
    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');

    if (!LOVABLE_API_KEY) {
      throw new Error('LOVABLE_API_KEY not configured');
    }

    const prompts: Record<string, string> = {
      'network-security': `As a network security expert (CISSP, CCNP Security certified), provide comprehensive guidance on:
- Network segmentation strategies
- Firewall rule optimization
- IDS/IPS deployment
- Zero Trust architecture
- Network monitoring best practices
Keep responses actionable and specific.`,

      'incident-response': `As an incident response specialist (GCIH, GCFA certified), provide:
- IR playbook recommendations
- Containment strategies
- Evidence collection procedures
- Timeline reconstruction methods
- Post-incident analysis framework
Focus on practical, immediately actionable steps.`,

      'cloud-security': `As a cloud security architect (CCSP, AWS/Azure/GCP certified), advise on:
- Cloud security posture management
- IAM best practices
- Data encryption strategies
- Compliance frameworks (SOC2, ISO 27001)
- Container and serverless security
Provide platform-specific recommendations when relevant.`,

      'application-security': `As an application security expert (CSSLP, OSWE certified), guide on:
- Secure SDLC implementation
- Code review strategies
- SAST/DAST/IAST integration
- API security best practices
- Security testing automation
Include specific tools and frameworks.`,

      'cryptography': `As a cryptography specialist, explain:
- Algorithm selection criteria
- Key management best practices
- PKI implementation
- Post-quantum cryptography readiness
- Common cryptographic mistakes
Make complex concepts accessible.`,

      'compliance': `As a compliance expert (CISA, CRISC certified), detail:
- Regulatory requirement mapping
- Control implementation
- Evidence collection
- Audit preparation
- Gap analysis methodology
Focus on GDPR, HIPAA, PCI-DSS, SOX as applicable.`,

      'threat-intelligence': `As a threat intelligence analyst (GCTI certified), provide:
- Intel collection strategies
- IOC analysis and enrichment
- Threat actor profiling
- Attribution techniques
- Intelligence-driven defense
Include specific tools and data sources.`,

      'forensics': `As a digital forensics investigator (GCFE, EnCE certified), guide on:
- Evidence acquisition methods
- Chain of custody procedures
- Memory and disk forensics
- Timeline analysis
- Anti-forensics detection
Maintain legal admissibility focus.`,

      'iam': `As an IAM architect, advise on:
- Identity lifecycle management
- MFA/passwordless strategies
- Privileged access management
- Federation and SSO
- Role-based access control design
Include modern solutions like FIDO2, OAuth2, OIDC.`,

      'devsecops': `As a DevSecOps engineer, recommend:
- Security pipeline integration
- Shift-left practices
- Container security scanning
- Infrastructure as Code security
- Continuous compliance monitoring
Focus on automation and tooling.`,

      'social-engineering': `As a social engineering expert, teach:
- Attack vector identification
- User awareness training
- Phishing simulation programs
- Physical security testing
- Psychological manipulation tactics
Emphasize defensive strategies.`,

      'siem': `As a SIEM architect, guide on:
- Log source integration
- Use case development
- Detection engineering
- Alert tuning and optimization
- Threat hunting queries
Include Splunk, ELK, Sentinel examples.`,

      'risk-management': `As a risk management professional (CRISC certified), advise on:
- Risk assessment methodologies
- Threat modeling approaches
- Control selection frameworks
- Risk quantification techniques
- Risk register maintenance
Use industry-standard frameworks.`,
    };

    const systemPrompt = prompts[domain] || `You are an expert cybersecurity professional with deep knowledge in ${domain}. Provide detailed, actionable guidance.`;

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: task }
        ],
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
          status: 429,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`AI API error: ${response.status}`);
    }

    const data = await response.json();
    const advice = data.choices[0].message.content;

    return new Response(JSON.stringify({ advice }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Security advisor error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
