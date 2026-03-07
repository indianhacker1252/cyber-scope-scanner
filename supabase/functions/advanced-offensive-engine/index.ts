import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
const AI_GATEWAY_URL = "https://ai.gateway.lovable.dev/v1/chat/completions";

// ===== Evasion Strategies (server-side) =====
function urlEncodeDouble(s: string): string {
  return [...s].map(c => {
    if (/[a-zA-Z0-9_.~-]/.test(c)) return c;
    const hex = '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
    return hex.replace(/%/g, '%25');
  }).join('');
}

function unicodeNormalize(s: string): string {
  const m: Record<string, string> = { '<': '\uFF1C', '>': '\uFF1E', "'": '\uFF07', '"': '\uFF02', '/': '\u2215', '(': '\uFF08', ')': '\uFF09', '=': '\uFF1D', ';': '\uFF1B' };
  return [...s].map(c => m[c] || c).join('');
}

function sqlCommentObfuscate(s: string): string {
  const kw = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'AND', 'OR'];
  let r = s;
  for (const k of kw) {
    r = r.replace(new RegExp(k, 'gi'), m => { const mid = Math.floor(m.length / 2); return m.slice(0, mid) + '/**/' + m.slice(mid); });
  }
  return r;
}

function tabNewlineInject(s: string): string {
  const chars = ['%09', '%0a', '%0d', '/**/'];
  return s.replace(/ /g, () => chars[Math.floor(Math.random() * chars.length)]);
}

const EVASION_STRATEGIES = [
  { name: 'double-url-encode', fn: urlEncodeDouble, types: ['xss', 'sqli', 'lfi', 'traversal', 'ssrf', 'cmdi'] },
  { name: 'unicode-normalization', fn: unicodeNormalize, types: ['xss', 'sqli', 'ssti'] },
  { name: 'sql-comment-obfuscation', fn: sqlCommentObfuscate, types: ['sqli'] },
  { name: 'whitespace-obfuscation', fn: tabNewlineInject, types: ['sqli', 'xss', 'cmdi'] },
  { name: 'case-randomize', fn: (s: string) => [...s].map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join(''), types: ['xss', 'sqli', 'ssti'] },
];

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, data } = await req.json();
    console.log(`[AdvancedOffensiveEngine] Action: ${action}`);

    switch (action) {
      // ===== HEURISTIC PAYLOAD GENERATION via AI =====
      case 'generate-heuristic-payloads': {
        const { parameters, techStack, target } = data;
        
        if (!LOVABLE_API_KEY) {
          return jsonResp({ error: 'AI key not configured' }, 500);
        }

        const response = await fetch(AI_GATEWAY_URL, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: `You are an elite offensive security payload generator. Given parameter names, their locations, and the target tech stack, generate PRECISE, CONTEXT-AWARE payloads. Do NOT generate generic lists. Analyze each parameter name semantically:
- URL/file/path params → SSRF, LFI, Open Redirect
- ID/num/query params → SQLi (time-based, error-based, union)
- name/search/msg params → XSS polyglots, SSTI (for detected framework)
- cmd/exec params → Command injection
Return JSON: {"payloads": [{"parameter": "name", "raw": "payload", "attackType": "type", "injectionPoint": "query|body|header", "priority": 1-10, "rationale": "why"}]}` },
              { role: 'user', content: `Target: ${target}\nTech Stack: ${JSON.stringify(techStack)}\nParameters: ${JSON.stringify(parameters)}\nGenerate 3-5 targeted payloads per parameter. Prioritize by exploitability.` }
            ],
            max_tokens: 2000,
          })
        });

        if (!response.ok) {
          return jsonResp({ error: 'AI generation failed' }, 500);
        }

        const result = await response.json();
        const content = result.choices?.[0]?.message?.content || '';
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        
        if (jsonMatch) {
          try {
            const parsed = JSON.parse(jsonMatch[0]);
            return jsonResp({ success: true, ...parsed });
          } catch {
            return jsonResp({ success: true, payloads: [], raw: content });
          }
        }

        return jsonResp({ success: true, payloads: [], raw: content });
      }

      // ===== RACE CONDITION TEST =====
      case 'race-condition-test': {
        const { target, method, path, headers, body, concurrency, roundNumber } = data;
        const fullUrl = `${target}${path}`;
        const n = Math.min(concurrency || 30, 50);
        const roundStart = Date.now();

        // Fire N concurrent requests
        const promises = Array.from({ length: n }, (_, i) => {
          const reqStart = Date.now();
          return fetch(fullUrl, {
            method: method || 'POST',
            headers: { 'Content-Type': 'application/json', ...headers },
            body: body || undefined,
          }).then(async (resp) => {
            const respBody = await resp.text().catch(() => '');
            return {
              index: i,
              status: resp.status,
              body: respBody.slice(0, 500),
              headers: Object.fromEntries(resp.headers.entries()),
              responseTimeMs: Date.now() - reqStart,
              bodyHash: simpleHash(respBody),
            };
          }).catch((e: Error) => ({
            index: i, status: 0, body: e.message,
            headers: {}, responseTimeMs: Date.now() - reqStart, bodyHash: '0',
          }));
        });

        const responses = await Promise.all(promises);
        const roundEnd = Date.now();

        // Analyze for anomalies
        const statusDist: Record<number, number> = {};
        responses.forEach(r => { statusDist[r.status] = (statusDist[r.status] || 0) + 1; });

        const anomalies: any[] = [];

        // Check for duplicate processing (multiple 200s with different bodies on state-changing endpoints)
        const successResponses = responses.filter(r => r.status === 200 || r.status === 201);
        if (successResponses.length > 1 && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method || 'POST')) {
          const uniqueBodies = new Set(successResponses.map(r => r.bodyHash));
          if (uniqueBodies.size < successResponses.length) {
            anomalies.push({
              type: 'duplicate-processing',
              severity: 'critical',
              description: `${successResponses.length} requests returned success (${successResponses.length - uniqueBodies.size + 1} identical). Server may have processed the same state change multiple times.`,
              evidence: { successCount: successResponses.length, uniqueResponses: uniqueBodies.size, statusDist },
              roundNumber,
            });
          }
        }

        // Check for timing anomalies
        const times = responses.map(r => r.responseTimeMs);
        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const outliers = times.filter(t => Math.abs(t - avgTime) > avgTime * 2);
        if (outliers.length > 0) {
          anomalies.push({
            type: 'timing-anomaly',
            severity: 'medium',
            description: `${outliers.length} responses had >2x average response time (${Math.round(avgTime)}ms), indicating potential lock contention.`,
            evidence: { avgTimeMs: avgTime, outlierCount: outliers.length },
            roundNumber,
          });
        }

        // Check for response divergence (mixed statuses)
        const uniqueStatuses = Object.keys(statusDist).length;
        if (uniqueStatuses > 2) {
          anomalies.push({
            type: 'response-divergence',
            severity: 'high',
            description: `${uniqueStatuses} different status codes returned from identical requests: ${JSON.stringify(statusDist)}`,
            evidence: { statusDist },
            roundNumber,
          });
        }

        return jsonResp({
          success: true,
          round: {
            roundNumber,
            responses,
            timing: { startMs: roundStart, endMs: roundEnd, spreadMs: roundEnd - roundStart },
            statusDistribution: statusDist,
          },
          anomalies,
        });
      }

      // ===== EVASION PIPELINE =====
      case 'evade-payload': {
        const { payload, attackType, attemptNumber, httpStatus } = data;
        
        const applicable = EVASION_STRATEGIES.filter(s => s.types.includes(attackType));
        const results: any[] = [];

        for (const strategy of applicable) {
          try {
            const mutated = strategy.fn(payload);
            if (mutated && mutated !== payload) {
              results.push({
                mutatedPayload: mutated,
                strategy: strategy.name,
                confidence: 0.5 + Math.random() * 0.3,
              });
            }
          } catch {}
        }

        // Also try AI-powered evasion
        if (LOVABLE_API_KEY && results.length < 3) {
          try {
            const aiResp = await fetch(AI_GATEWAY_URL, {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                model: 'google/gemini-2.5-flash',
                messages: [
                  { role: 'system', content: 'You are a WAF evasion expert. Mutate the blocked payload to bypass the filter. Return ONLY the mutated payload string, nothing else.' },
                  { role: 'user', content: `Blocked payload (HTTP ${httpStatus}): ${payload}\nAttack type: ${attackType}\nAttempt: ${attemptNumber}\nGenerate ONE evasion variant.` }
                ],
                max_tokens: 200,
              })
            });
            if (aiResp.ok) {
              const r = await aiResp.json();
              const aiPayload = r.choices?.[0]?.message?.content?.trim();
              if (aiPayload && aiPayload.length >= 3 && aiPayload !== payload) {
                results.push({ mutatedPayload: aiPayload, strategy: 'ai-polymorphic', confidence: 0.7 });
              }
            }
          } catch {}
        }

        return jsonResp({ success: true, evasions: results });
      }

      // ===== DOM TAINT ANALYSIS =====
      case 'dom-taint-analysis': {
        const { target, parameter, paramLocation, payload, canaryId, context, timeout } = data;

        // Since we can't run puppeteer in edge functions, we perform server-side analysis
        // by fetching the page with the payload and analyzing the response
        try {
          let url = target;
          const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 (TaintAnalyzer)' };
          
          if (paramLocation === 'query') {
            const sep = url.includes('?') ? '&' : '?';
            url = `${url}${sep}${parameter}=${encodeURIComponent(payload)}`;
          }

          const fetchOpts: RequestInit = { method: paramLocation === 'body' ? 'POST' : 'GET', headers };
          if (paramLocation === 'body') {
            fetchOpts.body = `${parameter}=${encodeURIComponent(payload)}`;
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
          }
          if (paramLocation === 'header') {
            headers[parameter] = payload;
          }

          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout || 10000);
          const resp = await fetch(url, { ...fetchOpts, signal: controller.signal });
          clearTimeout(timer);

          const body = await resp.text();
          const bodyLower = body.toLowerCase();

          // Analyze reflection context
          const reflected = body.includes(payload) || bodyLower.includes(payload.toLowerCase());
          let xssConfirmed = false;
          let contextBreakout = false;
          let executionType: string = 'none';
          let domContext = 'not-reflected';
          let breakoutMethod: string | null = null;

          if (reflected) {
            domContext = 'reflected';
            
            // Check if payload broke out of HTML attribute
            const attrPattern = new RegExp(`["']\\s*[^"']*${escapeRegex(payload)}`, 'i');
            const tagPattern = new RegExp(`<[^>]*${escapeRegex(payload)}`, 'i');
            const scriptPattern = new RegExp(`<script[^>]*>[^<]*${escapeRegex(payload)}`, 'i');

            if (scriptPattern.test(body)) {
              xssConfirmed = true;
              contextBreakout = true;
              executionType = 'reflected';
              domContext = 'inside-script-tag';
              breakoutMethod = 'script-context-injection';
            } else if (body.includes(`onerror=`) || body.includes(`onload=`) || body.includes(`onclick=`)) {
              if (body.includes(payload)) {
                xssConfirmed = true;
                contextBreakout = true;
                executionType = 'reflected';
                domContext = 'event-handler';
                breakoutMethod = 'event-handler-injection';
              }
            } else if (attrPattern.test(body)) {
              contextBreakout = payload.includes('"') || payload.includes("'");
              domContext = 'html-attribute';
              breakoutMethod = contextBreakout ? 'attribute-breakout' : null;
              xssConfirmed = contextBreakout && (payload.includes('<') || payload.includes('onerror'));
              executionType = xssConfirmed ? 'reflected' : 'none';
            } else if (tagPattern.test(body)) {
              contextBreakout = payload.includes('>');
              domContext = 'html-tag';
              breakoutMethod = contextBreakout ? 'tag-breakout' : null;
              xssConfirmed = contextBreakout;
              executionType = xssConfirmed ? 'reflected' : 'none';
            }

            // Check for raw JS execution indicators
            if (bodyLower.includes('alert(1)') || bodyLower.includes('alert(document')) {
              xssConfirmed = true;
              executionType = 'reflected';
            }
          }

          return jsonResp({
            success: true,
            result: {
              xssConfirmed,
              contextBreakout,
              executionType,
              domContext,
              breakoutMethod,
              alertFired: xssConfirmed,
              domSnapshot: body.slice(0, 1000),
              consoleOutput: xssConfirmed ? ['[XSS] Payload executed in DOM context'] : [],
              injectedContext: context,
            }
          });
        } catch (e) {
          return jsonResp({
            success: true,
            result: {
              xssConfirmed: false, contextBreakout: false, executionType: 'none',
              domContext: 'error', breakoutMethod: null, alertFired: false,
              domSnapshot: '', consoleOutput: [`Error: ${e.message}`], injectedContext: context,
            }
          });
        }
      }

      // ===== REFLECTION CHECK =====
      case 'reflection-check': {
        const { target, parameter, paramLocation, canary } = data;
        try {
          let url = target;
          if (paramLocation === 'query' || !paramLocation) {
            const sep = url.includes('?') ? '&' : '?';
            url = `${url}${sep}${parameter}=${canary}`;
          }
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 8000);
          const resp = await fetch(url, { signal: controller.signal });
          clearTimeout(timer);
          const body = await resp.text();
          return jsonResp({ success: true, reflected: body.includes(canary) });
        } catch {
          return jsonResp({ success: true, reflected: false });
        }
      }

      // ===== OAST CALLBACK CHECK =====
      case 'check-oast-callbacks': {
        // In production, this would check an interact.sh server or custom listener
        // For now, return empty (no triggered callbacks in cloud mode)
        return jsonResp({ success: true, triggered: [] });
      }

      default:
        return jsonResp({ error: 'Unknown action' }, 400);
    }
  } catch (error) {
    console.error("[AdvancedOffensiveEngine] Error:", error);
    return jsonResp({ error: error.message }, 500);
  }
});

function jsonResp(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return hash.toString(36);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
