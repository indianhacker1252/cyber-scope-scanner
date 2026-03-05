/**
 * TechFingerprinter.ts — Deep Technology Fingerprinting Service
 * Analyzes HTTP headers, Wappalyzer signatures, and scan results
 * to extract exact technology stack with version numbers.
 */

export interface TargetAsset {
  target: string;
  technologies: TechProfile[];
  serverInfo: ServerInfo;
  fingerprinted_at: string;
}

export interface TechProfile {
  name: string;
  version: string | null;
  category: 'server' | 'framework' | 'language' | 'cms' | 'cdn' | 'waf' | 'database' | 'os' | 'js-library' | 'other';
  confidence: number; // 0–1
  source: string; // how we detected it
  cpe?: string; // CPE identifier for NVD lookup
}

export interface ServerInfo {
  ip: string | null;
  server: string | null;
  poweredBy: string | null;
  headers: Record<string, string>;
  ports: number[];
}

// Wappalyzer-style signature patterns
const TECH_SIGNATURES: Record<string, { pattern: RegExp; category: TechProfile['category']; versionGroup?: number }> = {
  'Apache':       { pattern: /Apache\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'server', versionGroup: 1 },
  'Nginx':        { pattern: /nginx\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'server', versionGroup: 1 },
  'IIS':          { pattern: /Microsoft-IIS\/?(\d+\.\d+)?/i, category: 'server', versionGroup: 1 },
  'LiteSpeed':    { pattern: /LiteSpeed\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'server', versionGroup: 1 },
  'PHP':          { pattern: /PHP\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'language', versionGroup: 1 },
  'ASP.NET':      { pattern: /ASP\.NET(?:\s+(\d+\.\d+))?/i, category: 'framework', versionGroup: 1 },
  'Express':      { pattern: /Express/i, category: 'framework' },
  'Django':       { pattern: /Django\/?(\d+\.\d+)?/i, category: 'framework', versionGroup: 1 },
  'Rails':        { pattern: /Rails\/?(\d+\.\d+)?/i, category: 'framework', versionGroup: 1 },
  'WordPress':    { pattern: /WordPress\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'cms', versionGroup: 1 },
  'Drupal':       { pattern: /Drupal\/?(\d+)?/i, category: 'cms', versionGroup: 1 },
  'Joomla':       { pattern: /Joomla!?\/?(\d+\.\d+)?/i, category: 'cms', versionGroup: 1 },
  'Cloudflare':   { pattern: /cloudflare/i, category: 'cdn' },
  'Akamai':       { pattern: /AkamaiGHost/i, category: 'cdn' },
  'Varnish':      { pattern: /Varnish/i, category: 'cdn' },
  'OpenSSL':      { pattern: /OpenSSL\/?(\d+\.\d+\.\d+[a-z]?)/i, category: 'other', versionGroup: 1 },
  'Node.js':      { pattern: /Node\.?js\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'language', versionGroup: 1 },
  'Java':         { pattern: /Java\/?(\d+[\.\d]*)?/i, category: 'language', versionGroup: 1 },
  'Tomcat':       { pattern: /Tomcat\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'server', versionGroup: 1 },
  'Spring':       { pattern: /Spring(?:\s+Boot)?\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'framework', versionGroup: 1 },
  'jQuery':       { pattern: /jquery[\/\-]?(\d+\.\d+(?:\.\d+)?)/i, category: 'js-library', versionGroup: 1 },
  'React':        { pattern: /react[\/\-]?(\d+\.\d+(?:\.\d+)?)/i, category: 'js-library', versionGroup: 1 },
  'Angular':      { pattern: /angular[\/\-]?(\d+\.\d+(?:\.\d+)?)/i, category: 'js-library', versionGroup: 1 },
  'Vue.js':       { pattern: /vue[\/\-]?(\d+\.\d+(?:\.\d+)?)/i, category: 'js-library', versionGroup: 1 },
  'MySQL':        { pattern: /MySQL\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'database', versionGroup: 1 },
  'PostgreSQL':   { pattern: /PostgreSQL\/?(\d+\.\d+)?/i, category: 'database', versionGroup: 1 },
  'MongoDB':      { pattern: /MongoDB\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'database', versionGroup: 1 },
  'Redis':        { pattern: /Redis\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'database', versionGroup: 1 },
  'ModSecurity':  { pattern: /Mod_?Security\/?(\d+\.\d+(?:\.\d+)?)?/i, category: 'waf', versionGroup: 1 },
  'AWS WAF':      { pattern: /AWSELB|awselb|aws/i, category: 'waf' },
};

// Header-to-tech mapping
const HEADER_TECH_MAP: Record<string, (value: string) => TechProfile | null> = {
  'server': (v) => matchSignatures(v),
  'x-powered-by': (v) => matchSignatures(v),
  'x-aspnet-version': (v) => ({ name: 'ASP.NET', version: v, category: 'framework', confidence: 0.95, source: 'X-AspNet-Version header' }),
  'x-generator': (v) => matchSignatures(v),
  'x-drupal-cache': () => ({ name: 'Drupal', version: null, category: 'cms', confidence: 0.9, source: 'X-Drupal-Cache header' }),
  'x-wordpress': () => ({ name: 'WordPress', version: null, category: 'cms', confidence: 0.85, source: 'X-WordPress header' }),
  'x-amz-cf-id': () => ({ name: 'CloudFront', version: null, category: 'cdn', confidence: 0.95, source: 'X-Amz-Cf-Id header' }),
  'cf-ray': () => ({ name: 'Cloudflare', version: null, category: 'cdn', confidence: 0.99, source: 'CF-Ray header' }),
};

function matchSignatures(text: string): TechProfile | null {
  for (const [name, sig] of Object.entries(TECH_SIGNATURES)) {
    const match = text.match(sig.pattern);
    if (match) {
      return {
        name,
        version: sig.versionGroup && match[sig.versionGroup] ? match[sig.versionGroup] : null,
        category: sig.category,
        confidence: match[sig.versionGroup ?? -1] ? 0.95 : 0.75,
        source: `signature match in "${text.substring(0, 60)}"`,
      };
    }
  }
  return null;
}

/**
 * Generate a CPE identifier for NVD lookup
 */
function generateCPE(tech: TechProfile): string {
  const vendor = tech.name.toLowerCase().replace(/\s+/g, '_').replace(/\./g, '');
  const product = vendor;
  const version = tech.version || '*';
  return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
}

/**
 * Fingerprint a target from scan results
 */
export function fingerprintFromScanResults(
  target: string,
  scanResults: {
    headers?: Record<string, string>;
    body?: string;
    technologies?: string[];
    ports?: number[];
    serviceVersions?: Record<string, string>;
  }
): TargetAsset {
  const techs: TechProfile[] = [];
  const seen = new Set<string>();

  const addTech = (t: TechProfile | null) => {
    if (!t) return;
    const key = `${t.name}|${t.version || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    t.cpe = generateCPE(t);
    techs.push(t);
  };

  // 1. Parse HTTP headers
  if (scanResults.headers) {
    for (const [header, value] of Object.entries(scanResults.headers)) {
      const headerLower = header.toLowerCase();
      const mapper = HEADER_TECH_MAP[headerLower];
      if (mapper) {
        addTech(mapper(value));
      }
      // Also try generic signature matching on all header values
      addTech(matchSignatures(value));
    }
  }

  // 2. Parse body for tech signatures
  if (scanResults.body) {
    // WordPress indicators
    if (scanResults.body.includes('wp-content') || scanResults.body.includes('wp-includes')) {
      const wpVersion = scanResults.body.match(/WordPress\s+(\d+\.\d+(?:\.\d+)?)/i);
      addTech({ name: 'WordPress', version: wpVersion?.[1] || null, category: 'cms', confidence: 0.9, source: 'HTML body analysis' });
    }
    // Drupal
    if (scanResults.body.includes('Drupal.settings') || scanResults.body.includes('drupal.js')) {
      addTech({ name: 'Drupal', version: null, category: 'cms', confidence: 0.85, source: 'HTML body analysis' });
    }
    // React
    if (scanResults.body.includes('__NEXT_DATA__') || scanResults.body.includes('_next/static')) {
      addTech({ name: 'Next.js', version: null, category: 'framework', confidence: 0.9, source: 'HTML body analysis' });
    }
    // JS libs from script tags
    for (const [name, sig] of Object.entries(TECH_SIGNATURES)) {
      if (sig.category === 'js-library') {
        const bodyMatch = scanResults.body.match(sig.pattern);
        if (bodyMatch) {
          addTech({
            name,
            version: sig.versionGroup && bodyMatch[sig.versionGroup] ? bodyMatch[sig.versionGroup] : null,
            category: sig.category,
            confidence: 0.8,
            source: 'HTML body script analysis',
          });
        }
      }
    }
  }

  // 3. Parse technology list from scanner output
  if (scanResults.technologies) {
    for (const techStr of scanResults.technologies) {
      const matched = matchSignatures(techStr);
      if (matched) {
        addTech(matched);
      } else {
        // Try to parse "TechName/Version" format
        const parts = techStr.match(/^([^\/\s]+)\/?(\d[\d.]*)?/);
        if (parts) {
          addTech({
            name: parts[1],
            version: parts[2] || null,
            category: 'other',
            confidence: 0.7,
            source: 'scanner technology list',
          });
        }
      }
    }
  }

  // 4. Parse service versions from port scans
  if (scanResults.serviceVersions) {
    for (const [, version] of Object.entries(scanResults.serviceVersions)) {
      addTech(matchSignatures(version));
    }
  }

  return {
    target,
    technologies: techs,
    serverInfo: {
      ip: null,
      server: scanResults.headers?.['server'] || scanResults.headers?.['Server'] || null,
      poweredBy: scanResults.headers?.['x-powered-by'] || scanResults.headers?.['X-Powered-By'] || null,
      headers: scanResults.headers || {},
      ports: scanResults.ports || [],
    },
    fingerprinted_at: new Date().toISOString(),
  };
}

/**
 * Merge multiple fingerprint results into a single consolidated asset
 */
export function mergeAssets(assets: TargetAsset[]): TargetAsset {
  if (assets.length === 0) throw new Error('No assets to merge');
  if (assets.length === 1) return assets[0];

  const merged = { ...assets[0] };
  const seen = new Set(merged.technologies.map(t => `${t.name}|${t.version || ''}`));

  for (let i = 1; i < assets.length; i++) {
    for (const tech of assets[i].technologies) {
      const key = `${tech.name}|${tech.version || ''}`;
      if (!seen.has(key)) {
        seen.add(key);
        merged.technologies.push(tech);
      }
    }
    // Merge ports
    merged.serverInfo.ports = [...new Set([...merged.serverInfo.ports, ...assets[i].serverInfo.ports])];
  }

  return merged;
}
