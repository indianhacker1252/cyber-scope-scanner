/**
 * TurboSmash - Race Condition & HTTP/2 Concurrency Engine
 * Exploits TOCTOU (Time-of-Check to Time-of-Use) logic flaws via
 * single-packet HTTP/2 attack methodology.
 * Sends N identical/mutating requests simultaneously to detect state handling bugs.
 */

import { supabase } from '@/integrations/supabase/client';

export interface RaceConfig {
  target: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  headers?: Record<string, string>;
  body?: string;
  concurrency: number; // 10-50 simultaneous requests
  mutations?: RaceMutation[];
  authToken?: string;
  maxRounds?: number; // How many rounds to run
}

export interface RaceMutation {
  field: string;
  values: string[]; // Cycling values like different amounts
}

export interface RaceResult {
  id: string;
  target: string;
  path: string;
  concurrency: number;
  rounds: RaceRound[];
  raceConditionDetected: boolean;
  anomalies: RaceAnomaly[];
  executionTime: number;
  summary: string;
}

export interface RaceRound {
  roundNumber: number;
  responses: RaceResponse[];
  timing: { startMs: number; endMs: number; spreadMs: number };
  statusDistribution: Record<number, number>;
}

export interface RaceResponse {
  index: number;
  status: number;
  body: string;
  headers: Record<string, string>;
  responseTimeMs: number;
  bodyHash: string;
}

export interface RaceAnomaly {
  type: 'duplicate-processing' | 'state-inconsistency' | 'timing-anomaly' | 'response-divergence';
  severity: 'critical' | 'high' | 'medium';
  description: string;
  evidence: any;
  roundNumber: number;
}

export class TurboSmash {
  /**
   * Execute a race condition attack via the edge function
   */
  async execute(config: RaceConfig): Promise<RaceResult> {
    const startTime = Date.now();
    const rounds: RaceRound[] = [];
    const anomalies: RaceAnomaly[] = [];
    const maxRounds = config.maxRounds || 3;
    const concurrency = Math.min(config.concurrency || 30, 50);

    for (let round = 1; round <= maxRounds; round++) {
      const { data, error } = await supabase.functions.invoke('advanced-offensive-engine', {
        body: {
          action: 'race-condition-test',
          data: {
            target: config.target,
            method: config.method,
            path: config.path,
            headers: config.headers || {},
            body: config.body,
            concurrency,
            mutations: config.mutations,
            authToken: config.authToken,
            roundNumber: round,
          }
        }
      });

      if (error) {
        console.error(`[TurboSmash] Round ${round} error:`, error);
        continue;
      }

      if (data?.round) {
        rounds.push(data.round);
        if (data.anomalies) anomalies.push(...data.anomalies);
      }

      // Brief delay between rounds
      if (round < maxRounds) {
        await new Promise(r => setTimeout(r, 500));
      }
    }

    const raceConditionDetected = anomalies.some(a => 
      a.type === 'duplicate-processing' || a.type === 'state-inconsistency'
    );

    const result: RaceResult = {
      id: crypto.randomUUID(),
      target: config.target,
      path: config.path,
      concurrency,
      rounds,
      raceConditionDetected,
      anomalies,
      executionTime: Date.now() - startTime,
      summary: raceConditionDetected
        ? `🔴 RACE CONDITION DETECTED: ${anomalies.length} anomalies found across ${rounds.length} rounds. ` +
          `Server processed duplicate state changes indicating TOCTOU vulnerability.`
        : `✅ No race condition detected after ${rounds.length} rounds of ${concurrency} concurrent requests.`,
    };

    return result;
  }

  /**
   * Quick test for common race-prone endpoints
   */
  async testCommonEndpoints(baseUrl: string, authToken?: string): Promise<RaceResult[]> {
    const commonPaths = [
      { path: '/api/checkout', method: 'POST' as const, body: '{"item_id":"1","quantity":1}' },
      { path: '/api/transfer', method: 'POST' as const, body: '{"to":"test","amount":1}' },
      { path: '/api/redeem', method: 'POST' as const, body: '{"code":"TEST"}' },
      { path: '/api/vote', method: 'POST' as const, body: '{"choice":"1"}' },
      { path: '/api/like', method: 'POST' as const, body: '{"post_id":"1"}' },
      { path: '/api/follow', method: 'POST' as const, body: '{"user_id":"1"}' },
      { path: '/api/apply-coupon', method: 'POST' as const, body: '{"coupon":"SAVE10"}' },
    ];

    const results: RaceResult[] = [];
    for (const ep of commonPaths) {
      try {
        const result = await this.execute({
          target: baseUrl,
          method: ep.method,
          path: ep.path,
          body: ep.body,
          concurrency: 30,
          authToken,
          maxRounds: 2,
          headers: { 'Content-Type': 'application/json' },
        });
        results.push(result);
      } catch {
        // Skip unreachable endpoints
      }
    }

    return results.filter(r => r.rounds.length > 0);
  }
}

export const turboSmash = new TurboSmash();
