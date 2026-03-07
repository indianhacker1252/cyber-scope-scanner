/**
 * HeadlessTaintAnalyzer - DOM Taint Tracking for XSS Verification
 * Instead of relying on static regex matching of HTTP responses,
 * this engine evaluates the live DOM to confirm if injected payloads
 * broke out of HTML context or executed JavaScript.
 * 
 * Uses the edge function to run headless browser analysis since
 * puppeteer can't run client-side.
 */

import { supabase } from '@/integrations/supabase/client';

export interface TaintResult {
  id: string;
  target: string;
  parameter: string;
  payload: string;
  canaryId: string;
  xssConfirmed: boolean;
  contextBreakout: boolean;
  executionType: 'reflected' | 'stored' | 'dom-based' | 'none';
  domContext: string; // Where the canary landed in the DOM
  evidence: {
    injectedContext: string; // HTML context (attribute, tag, script, etc.)
    breakoutMethod: string | null;
    alertFired: boolean;
    domSnapshot: string;
    consoleOutput: string[];
  };
  severity: 'critical' | 'high' | 'medium' | 'info';
  poc: string;
}

export interface TaintConfig {
  target: string;
  parameters: { name: string; location: 'query' | 'body' | 'header' }[];
  payloads?: string[];
  timeout?: number;
}

// Default XSS canary payloads that test different DOM contexts
const CANARY_PAYLOADS = [
  // Context-breaking payloads
  { payload: '"><svg/onload=alert(1)>', context: 'attribute-breakout' },
  { payload: "'-alert(1)-'", context: 'js-string-breakout' },
  { payload: '</script><script>alert(1)</script>', context: 'script-breakout' },
  { payload: '{{constructor.constructor("alert(1)")()}}', context: 'template-injection' },
  { payload: 'javascript:alert(1)//', context: 'href-injection' },
  { payload: '<img src=x onerror=alert(1)>', context: 'tag-injection' },
  { payload: '<details/open/ontoggle=alert(1)>', context: 'event-handler' },
  // DOM-based XSS
  { payload: '#"><img src=x onerror=alert(1)>', context: 'fragment-injection' },
  { payload: 'data:text/html,<script>alert(1)</script>', context: 'data-uri' },
];

export class HeadlessTaintAnalyzer {
  /**
   * Analyze a target for XSS by injecting canary strings and evaluating DOM
   */
  async analyze(config: TaintConfig): Promise<TaintResult[]> {
    const results: TaintResult[] = [];

    for (const param of config.parameters) {
      const paramResults = await this.analyzeParameter(config.target, param, config.payloads, config.timeout);
      results.push(...paramResults);
    }

    return results;
  }

  /**
   * Analyze a single parameter
   */
  private async analyzeParameter(
    target: string,
    param: { name: string; location: 'query' | 'body' | 'header' },
    customPayloads?: string[],
    timeout?: number
  ): Promise<TaintResult[]> {
    const results: TaintResult[] = [];
    const payloads = customPayloads 
      ? customPayloads.map(p => ({ payload: p, context: 'custom' }))
      : CANARY_PAYLOADS;

    for (const { payload, context } of payloads) {
      const canaryId = `taint_${crypto.randomUUID().slice(0, 8)}`;

      try {
        const { data, error } = await supabase.functions.invoke('advanced-offensive-engine', {
          body: {
            action: 'dom-taint-analysis',
            data: {
              target,
              parameter: param.name,
              paramLocation: param.location,
              payload,
              canaryId,
              context,
              timeout: timeout || 10000,
            }
          }
        });

        if (error) {
          console.warn(`[TaintAnalyzer] Error for ${param.name}:`, error);
          continue;
        }

        if (data?.result) {
          const r = data.result;
          results.push({
            id: crypto.randomUUID(),
            target,
            parameter: param.name,
            payload,
            canaryId,
            xssConfirmed: r.xssConfirmed || false,
            contextBreakout: r.contextBreakout || false,
            executionType: r.executionType || 'none',
            domContext: r.domContext || 'unknown',
            evidence: {
              injectedContext: r.injectedContext || context,
              breakoutMethod: r.breakoutMethod || null,
              alertFired: r.alertFired || false,
              domSnapshot: r.domSnapshot || '',
              consoleOutput: r.consoleOutput || [],
            },
            severity: r.xssConfirmed ? 'critical' : r.contextBreakout ? 'high' : 'info',
            poc: r.xssConfirmed
              ? `XSS Confirmed via DOM Taint Analysis\nTarget: ${target}\nParameter: ${param.name}\nPayload: ${payload}\nContext: ${context}\nExecution: ${r.executionType}\nDOM Evidence: ${r.domSnapshot?.slice(0, 200)}`
              : `No XSS confirmed for ${param.name} with payload context: ${context}`,
          });
        }
      } catch (e) {
        console.warn(`[TaintAnalyzer] Failed:`, e);
      }
    }

    return results;
  }

  /**
   * Quick reflection check - tests if a canary string is reflected in the response
   * and then escalates to DOM analysis only if reflected
   */
  async smartAnalyze(target: string, parameters: { name: string; location: 'query' | 'body' | 'header' }[]): Promise<TaintResult[]> {
    const results: TaintResult[] = [];

    // Phase 1: Inject simple canary to find reflected params
    const reflectedParams: typeof parameters = [];

    for (const param of parameters) {
      const canary = `xsstaint${Math.random().toString(36).slice(2, 8)}`;
      
      try {
        const { data } = await supabase.functions.invoke('advanced-offensive-engine', {
          body: {
            action: 'reflection-check',
            data: { target, parameter: param.name, paramLocation: param.location, canary }
          }
        });

        if (data?.reflected) {
          reflectedParams.push(param);
        }
      } catch {}
    }

    // Phase 2: Only run full DOM taint analysis on reflected parameters
    if (reflectedParams.length > 0) {
      const domResults = await this.analyze({ target, parameters: reflectedParams });
      results.push(...domResults);
    }

    return results;
  }
}

export const headlessTaintAnalyzer = new HeadlessTaintAnalyzer();
