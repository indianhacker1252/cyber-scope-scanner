import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { finding, target, vulnerabilityType, severity, language = "python" } = await req.json();

    if (!finding || !target) {
      return new Response(JSON.stringify({ error: "Missing finding or target" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    const systemPrompt = `You are a senior penetration testing engineer writing Proof of Concept (PoC) validation scripts for authorized security audits. 

RULES:
- Generate ONLY non-destructive, read-only verification scripts
- Scripts must PROVE the vulnerability exists without exploiting it destructively
- Use ${language === "python" ? "Python with 'requests' library" : "Node.js with 'fetch'"}
- Include proper error handling, timeouts (max 15 seconds), and clean output
- Print clear VERIFIED/NOT_VERIFIED status at the end
- Include comments explaining each step
- Never include destructive payloads (no DROP, DELETE, rm -rf, etc.)
- Focus on: response analysis, header checks, timing analysis, DNS resolution, port connectivity
- Always set a User-Agent header identifying this as authorized security testing`;

    const userPrompt = `Generate a ${language} PoC validation script for the following finding:

**Finding:** ${finding}
**Target:** ${target}
**Vulnerability Type:** ${vulnerabilityType || "Unknown"}
**Severity:** ${severity || "Medium"}

The script must:
1. Safely verify if this vulnerability exists on the target
2. Capture HTTP request/response evidence
3. Print structured output with [EVIDENCE], [STATUS], and [DETAILS] tags
4. Handle errors gracefully with informative messages
5. Complete within 15 seconds maximum`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.3,
      }),
    });

    if (!response.ok) {
      const status = response.status;
      if (status === 429) return new Response(JSON.stringify({ error: "Rate limited, try again shortly" }), { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      if (status === 402) return new Response(JSON.stringify({ error: "Credits exhausted" }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      throw new Error(`AI gateway error: ${status}`);
    }

    const data = await response.json();
    const script = data.choices?.[0]?.message?.content || "";

    // Extract code block from markdown if present
    const codeMatch = script.match(/```(?:python|javascript|js|node)?\n([\s\S]*?)```/);
    const cleanScript = codeMatch ? codeMatch[1].trim() : script;

    return new Response(JSON.stringify({ script: cleanScript, language, raw: script }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("validation-scaffolder error:", e);
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
