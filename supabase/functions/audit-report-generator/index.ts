import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: authHeader } } }
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Authentication required" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { evidenceId } = await req.json();
    if (!evidenceId) {
      return new Response(JSON.stringify({ error: "Missing evidenceId" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Fetch evidence
    const { data: evidence, error: fetchErr } = await supabase
      .from("validation_evidence")
      .select("*")
      .eq("id", evidenceId)
      .eq("user_id", user.id)
      .single();

    if (fetchErr || !evidence) {
      return new Response(JSON.stringify({ error: "Evidence not found" }), {
        status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    const prompt = `Generate a professional security remediation report in Markdown for a bug bounty / penetration test finding.

**Finding Title:** ${evidence.finding_title}
**Severity:** ${evidence.finding_severity}
**Target:** ${evidence.target}
**Vulnerability Type:** ${evidence.vulnerability_type || "Unknown"}
**Execution Output:**
${evidence.execution_output || "No output available"}

**HTTP Request Data:** ${JSON.stringify(evidence.http_request_data || {})}
**HTTP Response Data:** ${JSON.stringify(evidence.http_response_data || {})}

Generate a report with these sections:
1. **Executive Summary** - Brief business-impact summary
2. **Technical Details** - Exact technical explanation of the vulnerability
3. **Steps to Reproduce** - Numbered steps any tester can follow
4. **Proof of Concept** - The validation evidence from execution output
5. **Impact Analysis** - What an attacker could achieve
6. **CVSS 3.1 Score** - Calculate and explain the score breakdown
7. **Remediation Recommendations** - Specific patches, config changes, or code fixes
8. **References** - Relevant CVEs, OWASP references, CWE IDs

Use proper Markdown formatting with headers, code blocks, and tables where appropriate.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: "You are a senior penetration testing report writer. Generate professional, detailed security reports following industry standards (OWASP, NIST, PTES). Be precise, technical, and actionable." },
          { role: "user", content: prompt },
        ],
        temperature: 0.2,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) return new Response(JSON.stringify({ error: "Rate limited" }), { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      if (response.status === 402) return new Response(JSON.stringify({ error: "Credits exhausted" }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      throw new Error(`AI error: ${response.status}`);
    }

    const data = await response.json();
    const report = data.choices?.[0]?.message?.content || "Report generation failed";

    // Extract CVSS score if present
    const cvssMatch = report.match(/CVSS.*?(\d+\.\d+)/i);
    const cvssScore = cvssMatch ? parseFloat(cvssMatch[1]) : null;

    // Save report and evidence package to DB
    const evidencePackage = {
      finding: evidence.finding_title,
      target: evidence.target,
      severity: evidence.finding_severity,
      httpRequest: evidence.http_request_data,
      httpResponse: evidence.http_response_data,
      pocScript: evidence.poc_script,
      executionOutput: evidence.execution_output,
      validatedAt: evidence.validated_at,
      reportGeneratedAt: new Date().toISOString(),
    };

    await supabase.from("validation_evidence").update({
      remediation_report: report,
      cvss_score: cvssScore,
      evidence_package: evidencePackage,
    }).eq("id", evidenceId).eq("user_id", user.id);

    return new Response(JSON.stringify({ report, cvssScore, evidencePackage }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("audit-report-generator error:", e);
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
