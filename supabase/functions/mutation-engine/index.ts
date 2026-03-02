import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// ─── Mutation Strategy Types ───
interface MutationRequest {
  originalPayload: string;
  targetContext: string;
  errorReason: string;
  attemptNumber: number;
  attackType: string;
  techStack?: string[];
}

interface MutationResponse {
  mutatedPayload: string;
  strategy: string;
  confidence: number;
  reasoning: string;
}

// ─── Encoding & Obfuscation Strategies ───
const ENCODING_STRATEGIES = [
  "double-url-encode",
  "unicode-escape",
  "hex-encode",
  "html-entity-encode",
  "base64-inline",
  "case-alternation",
  "null-byte-injection",
  "comment-insertion",
  "whitespace-obfuscation",
  "concat-splitting",
];

function applyLocalMutation(payload: string, strategy: string): string {
  switch (strategy) {
    case "double-url-encode":
      return payload.replace(/[<>"'&]/g, (c) => 
        `%25${c.charCodeAt(0).toString(16).toUpperCase()}`
      );
    case "unicode-escape":
      return payload.replace(/[a-zA-Z]/g, (c) => 
        `\\u00${c.charCodeAt(0).toString(16)}`
      );
    case "hex-encode":
      return payload.replace(/[<>"']/g, (c) => 
        `&#x${c.charCodeAt(0).toString(16)};`
      );
    case "html-entity-encode":
      return payload
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    case "case-alternation":
      return payload.replace(/[a-zA-Z]/g, (c, i) => 
        i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
      );
    case "null-byte-injection":
      return payload.replace(/(select|union|script|alert)/gi, (m) => 
        m.split("").join("%00")
      );
    case "comment-insertion":
      return payload.replace(/(select|union|from|where)/gi, (m) => 
        m.split("").join("/**/")
      );
    case "whitespace-obfuscation":
      return payload.replace(/ /g, "/**/").replace(/\t/g, "%09");
    case "concat-splitting":
      if (payload.includes("alert")) {
        return payload.replace(/alert/g, "al\\u0065rt");
      }
      if (payload.includes("SELECT")) {
        return payload.replace(/SELECT/gi, "SEL/**/ECT");
      }
      return payload;
    default:
      return payload;
  }
}

// ─── AI-Powered Mutation via Lovable AI Gateway ───
async function generateAIMutation(req: MutationRequest): Promise<MutationResponse> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  
  const systemPrompt = `You are an expert penetration testing payload mutation engine used by authorized security professionals. Your role is to help evade WAF/IDS signatures for legitimate VAPT assessments.

RULES:
- Output ONLY the raw mutated payload string on the first line
- On the second line, output the strategy name (e.g., "unicode-bypass", "polyglot-xss")
- On the third line, a confidence score 0-100
- No markdown, no explanations, no code blocks
- The mutated payload MUST be functionally equivalent to the original
- Use advanced evasion: encoding mixing, polyglots, regex bypass, WAF fingerprint-specific tricks
- Consider the technology stack and error type to craft targeted evasion`;

  const userPrompt = `The payload '${req.originalPayload}' was blocked by a security filter on target '${req.targetContext}' with error '${req.errorReason}'. Attack type: ${req.attackType}. Attempt #${req.attemptNumber}. Tech stack: ${req.techStack?.join(", ") || "unknown"}.

Generate a single, functionally equivalent but syntactically obfuscated payload to evade detection. Use a DIFFERENT evasion technique than standard encoding. Consider polyglots, nested encoding, WAF-specific bypass patterns, or HTTP parameter pollution.`;

  if (!LOVABLE_API_KEY) {
    // Fallback to local mutation if no AI key
    const strategy = ENCODING_STRATEGIES[req.attemptNumber % ENCODING_STRATEGIES.length];
    const mutated = applyLocalMutation(req.originalPayload, strategy);
    return {
      mutatedPayload: mutated,
      strategy: `local-${strategy}`,
      confidence: 40,
      reasoning: "Fallback local mutation (no AI key available)",
    };
  }

  try {
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.8,
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      console.error("AI gateway error:", response.status);
      const strategy = ENCODING_STRATEGIES[req.attemptNumber % ENCODING_STRATEGIES.length];
      return {
        mutatedPayload: applyLocalMutation(req.originalPayload, strategy),
        strategy: `local-fallback-${strategy}`,
        confidence: 35,
        reasoning: `AI unavailable (${response.status}), used local mutation`,
      };
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content?.trim() || "";

    // Parse AI response (3-line format)
    const lines = content.split("\n").filter((l: string) => l.trim());
    const mutatedPayload = lines[0]?.trim() || "";
    const strategy = lines[1]?.trim() || "ai-mutation";
    const confidence = parseInt(lines[2]?.trim()) || 65;

    // Validate: AI hallucination guard
    if (!mutatedPayload || mutatedPayload.length < 3 || mutatedPayload === req.originalPayload) {
      console.warn("AI returned invalid mutation, falling back to local");
      const fallbackStrategy = ENCODING_STRATEGIES[(req.attemptNumber + 2) % ENCODING_STRATEGIES.length];
      return {
        mutatedPayload: applyLocalMutation(req.originalPayload, fallbackStrategy),
        strategy: `hallucination-fallback-${fallbackStrategy}`,
        confidence: 30,
        reasoning: "AI produced invalid output; local mutation applied",
      };
    }

    return {
      mutatedPayload,
      strategy,
      confidence: Math.min(confidence, 95),
      reasoning: `AI-generated evasion using ${strategy}`,
    };
  } catch (error) {
    console.error("AI mutation error:", error);
    const strategy = ENCODING_STRATEGIES[req.attemptNumber % ENCODING_STRATEGIES.length];
    return {
      mutatedPayload: applyLocalMutation(req.originalPayload, strategy),
      strategy: `error-fallback-${strategy}`,
      confidence: 25,
      reasoning: `AI error: ${error.message}`,
    };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body: MutationRequest = await req.json();
    const { originalPayload, targetContext, errorReason, attemptNumber, attackType, techStack } = body;

    if (!originalPayload || !targetContext || !errorReason) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: originalPayload, targetContext, errorReason" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`[MutationEngine] Mutating payload for ${targetContext} | Attempt #${attemptNumber} | Error: ${errorReason}`);

    const result = await generateAIMutation({
      originalPayload,
      targetContext,
      errorReason,
      attemptNumber: attemptNumber || 1,
      attackType: attackType || "unknown",
      techStack,
    });

    console.log(`[MutationEngine] Strategy: ${result.strategy} | Confidence: ${result.confidence}%`);

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("[MutationEngine] Fatal error:", error);
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
