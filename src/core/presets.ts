import type { TargetPreset } from '../types/security';

export type { TargetPreset };

export const TARGET_PRESETS: TargetPreset[] = [
  {
    id: 'hardened-cloud',
    name: 'Hardened Cloud API Gateway',
    url: 'https://api.secureguard.cloud',
    category: 'enterprise',
    badge: 'Grade A+ (96%)',
    description: 'A fully fortified modern enterprise service with strict CSP, HSTS with preloading, and complete ASVS Level 2 alignment.',
    result: {
      targetUrl: 'https://api.secureguard.cloud',
      timestamp: new Date().toISOString(),
      score: 96,
      grade: 'A+',
      summary: {
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
        info: 2,
        totalPassed: 24
      },
      findings: [
        {
          id: 'F-01',
          title: 'Permissive Permissions-Policy Directives',
          severity: 'MEDIUM',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '8.3.1',
          cwe: 'CWE-16',
          passed: false,
          description: 'Permissions-Policy header does not explicitly disable the screen-wake-lock and idle-detection browser APIs.',
          impact: 'Client browser hardware sensors and idle states could be queried if third-party scripts are injected.',
          remediation: 'Append "screen-wake-lock=(), idle-detection=()" to the Permissions-Policy response header.',
          codeSnippet: {
            language: 'http',
            vulnerable: 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
            remediated: 'Permissions-Policy: geolocation=(), camera=(), microphone=(), screen-wake-lock=(), idle-detection=()'
          }
        },
        {
          id: 'F-02',
          title: 'Subresource Integrity Missing on Static Analytics CDN',
          severity: 'LOW',
          owaspCategory: 'A08:2025 - Software or Data Integrity Failures',
          cwe: 'CWE-353',
          passed: false,
          description: 'A non-critical static telemetry bundle is fetched from a third-party CDN without an integrity SHA-384 attribute.',
          impact: 'If the external CDN provider is compromised, altered scripts could be served to visitors.',
          remediation: 'Add integrity="sha384-..." and crossorigin="anonymous" to all external script tags.',
          codeSnippet: {
            language: 'html',
            vulnerable: '<script src="https://cdn.telemetry.io/v2/events.min.js"></script>',
            remediated: '<script src="https://cdn.telemetry.io/v2/events.min.js"\n  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n  crossorigin="anonymous"></script>'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'passed',
          currentValue: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
          recommendedValue: "default-src 'self'; frame-ancestors 'none';",
          importance: 'critical',
          description: 'Restricts resource loading and mitigates XSS attacks by disallowing inline scripts and eval.'
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'passed',
          currentValue: 'max-age=63072000; includeSubDomains; preload',
          recommendedValue: 'max-age=63072000; includeSubDomains; preload',
          importance: 'critical',
          description: 'Enforces HTTPS for two years and protects against protocol downgrade and SSL-stripping.'
        },
        {
          header: 'X-Frame-Options',
          status: 'passed',
          currentValue: 'DENY',
          recommendedValue: 'DENY',
          importance: 'high',
          description: 'Prevents the site from being rendered within an iframe, eliminating UI redressing / clickjacking.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'passed',
          currentValue: 'nosniff',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'Instructs browsers not to MIME-sniff response content, preventing drive-by script execution.'
        },
        {
          header: 'Referrer-Policy',
          status: 'passed',
          currentValue: 'strict-origin-when-cross-origin',
          recommendedValue: 'strict-origin-when-cross-origin',
          importance: 'medium',
          description: 'Limits the referrer header to the origin when navigating cross-origin to protect path tokens.'
        },
        {
          header: 'Cross-Origin-Opener-Policy',
          status: 'passed',
          currentValue: 'same-origin',
          recommendedValue: 'same-origin',
          importance: 'medium',
          description: 'Isolates the browsing context to prevent cross-origin window interaction (Spectre mitigation).'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 98, status: 'compliant' },
        { category: 'A02 - Security Misconfiguration', score: 92, status: 'compliant' },
        { category: 'A03 - Supply Chain Failures', score: 95, status: 'compliant' },
        { category: 'A04 - Cryptographic Failures', score: 100, status: 'compliant' },
        { category: 'A05 - Injection', score: 98, status: 'compliant' },
        { category: 'A06 - Insecure Design', score: 94, status: 'compliant' },
        { category: 'A07 - Authentication Failures', score: 97, status: 'compliant' },
        { category: 'A08 - Integrity Failures', score: 90, status: 'compliant' },
        { category: 'A09 - Security Logging & Alerting', score: 96, status: 'compliant' },
        { category: 'A10 - Exception Handling', score: 95, status: 'compliant' }
      ],
      asvsLevel1PassRate: 100,
      asvsLevel2PassRate: 94
    }
  },
  {
    id: 'legacy-portal',
    name: 'Legacy Enterprise Web App',
    url: 'https://legacy-portal.internal-net.com',
    category: 'enterprise',
    badge: 'Grade D (48%)',
    description: 'An aging corporate web portal suffering from missing security headers, unsafe cookies, and unvalidated URL parameters.',
    result: {
      targetUrl: 'https://legacy-portal.internal-net.com',
      timestamp: new Date().toISOString(),
      score: 48,
      grade: 'D',
      summary: {
        critical: 2,
        high: 3,
        medium: 4,
        low: 2,
        info: 1,
        totalPassed: 9
      },
      findings: [
        {
          id: 'F-10',
          title: 'Missing Content-Security-Policy (CSP) Header',
          severity: 'CRITICAL',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '1.2.1',
          cwe: 'CWE-79',
          passed: false,
          description: 'No Content-Security-Policy header is configured. Inline scripts and arbitrary external origins are unrestricted.',
          impact: 'Enables trivial stored and reflected Cross-Site Scripting (XSS) exploitation and session token theft.',
          remediation: 'Deploy a strict CSP with nonce-based script-src or hash-based source controls and object-src "none".',
          codeSnippet: {
            language: 'javascript',
            vulnerable: '// Express middleware missing CSP\napp.use((req, res, next) => next());',
            remediated: 'import helmet from "helmet";\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["\'self\'"],\n    scriptSrc: ["\'self\'"],\n    objectSrc: ["\'none\'"]\n  }\n}));'
          }
        },
        {
          id: 'F-11',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          severity: 'HIGH',
          owaspCategory: 'A04:2025 - Cryptographic Failures',
          asvsId: '12.1.1',
          cwe: 'CWE-319',
          passed: false,
          description: 'The server accepts HTTPS connections but does not declare Strict-Transport-Security.',
          impact: 'Users are vulnerable to Man-In-The-Middle (MITM) SSL stripping attacks when accessing on public WiFi networks.',
          remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.',
          codeSnippet: {
            language: 'nginx',
            vulnerable: '# Nginx configuration lacking HSTS\nserver {\n  listen 443 ssl;\n  # ...\n}',
            remediated: '# Nginx with strict HSTS\nserver {\n  listen 443 ssl;\n  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n}'
          }
        },
        {
          id: 'F-12',
          title: 'Insecure Session Cookie Configuration',
          severity: 'HIGH',
          owaspCategory: 'A07:2025 - Authentication Failures',
          asvsId: '7.2.3',
          cwe: 'CWE-614',
          passed: false,
          description: 'Session cookie "JSESSIONID" lacks the HttpOnly, Secure, and SameSite attributes.',
          impact: 'JavaScript can read session credentials via document.cookie, and the cookie is transmitted in cleartext cross-site requests (CSRF vulnerability).',
          remediation: 'Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all authentication cookies.',
          codeSnippet: {
            language: 'http',
            vulnerable: 'Set-Cookie: JSESSIONID=23FA90B1E8; Path=/',
            remediated: 'Set-Cookie: JSESSIONID=23FA90B1E8; Path=/; Secure; HttpOnly; SameSite=Strict'
          }
        },
        {
          id: 'F-13',
          title: 'Verbose Server Version & Stack Trace Disclosure',
          severity: 'MEDIUM',
          owaspCategory: 'A10:2025 - Mishandling of Exceptional Conditions',
          asvsId: '16.5.1',
          cwe: 'CWE-209',
          passed: false,
          description: 'Server headers expose "Server: Apache/2.4.29 (Ubuntu) OpenSSL/1.1.1" and "X-Powered-By: PHP/7.2.24".',
          impact: 'Provides reconnaissance metadata enabling targeted searches for known component CVEs.',
          remediation: 'Strip the Server and X-Powered-By banners in web server configuration.',
          codeSnippet: {
            language: 'apache',
            vulnerable: 'ServerTokens Full\nServerSignature On',
            remediated: 'ServerTokens Prod\nServerSignature Off'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'missing',
          recommendedValue: "default-src 'self'; frame-ancestors 'none';",
          importance: 'critical',
          description: 'Missing. High risk of XSS execution.'
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'missing',
          recommendedValue: 'max-age=31536000; includeSubDomains',
          importance: 'critical',
          description: 'Missing. Vulnerable to SSL stripping.'
        },
        {
          header: 'X-Frame-Options',
          status: 'missing',
          recommendedValue: 'DENY',
          importance: 'high',
          description: 'Missing. Vulnerable to clickjacking / UI redressing.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'missing',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'Missing. Allows MIME sniffing by browsers.'
        },
        {
          header: 'Referrer-Policy',
          status: 'warning',
          currentValue: 'no-referrer-when-downgrade',
          recommendedValue: 'strict-origin-when-cross-origin',
          importance: 'medium',
          description: 'Weak policy. Leaks full URL paths to external origins.'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 45, status: 'non-compliant' },
        { category: 'A02 - Security Misconfiguration', score: 32, status: 'non-compliant' },
        { category: 'A03 - Supply Chain Failures', score: 40, status: 'non-compliant' },
        { category: 'A04 - Cryptographic Failures', score: 48, status: 'non-compliant' },
        { category: 'A05 - Injection', score: 55, status: 'warning' },
        { category: 'A06 - Insecure Design', score: 50, status: 'warning' },
        { category: 'A07 - Authentication Failures', score: 38, status: 'non-compliant' },
        { category: 'A08 - Integrity Failures', score: 52, status: 'warning' },
        { category: 'A09 - Security Logging & Alerting', score: 60, status: 'warning' },
        { category: 'A10 - Exception Handling', score: 42, status: 'non-compliant' }
      ],
      asvsLevel1PassRate: 46,
      asvsLevel2PassRate: 22
    }
  },
  {
    id: 'modern-ecommerce',
    name: 'E-Commerce Checkout API',
    url: 'https://store.hyperretail.io',
    category: 'enterprise',
    badge: 'Grade B (78%)',
    description: 'Modern storefront with solid transport security and CSRF defense, but missing fine-grained Referrer and Permissions policies.',
    result: {
      targetUrl: 'https://store.hyperretail.io',
      timestamp: new Date().toISOString(),
      score: 78,
      grade: 'B',
      summary: {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 2,
        totalPassed: 18
      },
      findings: [
        {
          id: 'F-20',
          title: 'Permissive script-src in CSP ("unsafe-inline")',
          severity: 'HIGH',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '1.2.1',
          cwe: 'CWE-79',
          passed: false,
          description: 'The Content-Security-Policy contains "unsafe-inline" in the script-src directive for marketing tag manager compatibility.',
          impact: 'Significantly weakens XSS mitigation, allowing injected script elements to execute.',
          remediation: 'Migrate marketing tags to nonce-based or hash-based CSP directives.',
          codeSnippet: {
            language: 'http',
            vulnerable: "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://tagmanager.google.com;",
            remediated: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123' https://tagmanager.google.com; object-src 'none';"
          }
        },
        {
          id: 'F-21',
          title: 'Missing Cross-Origin-Resource-Policy Header',
          severity: 'MEDIUM',
          owaspCategory: 'A01:2025 - Broken Access Control & SSRF',
          asvsId: '8.3.1',
          cwe: 'CWE-284',
          passed: false,
          description: 'Static media and API responses lack the Cross-Origin-Resource-Policy (CORP) header.',
          impact: 'Other origins can embed resources and potentially leak data via side-channel timing attacks.',
          remediation: 'Set "Cross-Origin-Resource-Policy: same-origin" or "same-site".',
          codeSnippet: {
            language: 'http',
            vulnerable: '# No CORP header present',
            remediated: 'Cross-Origin-Resource-Policy: same-origin'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'warning',
          currentValue: "default-src 'self'; script-src 'self' 'unsafe-inline';",
          recommendedValue: "default-src 'self'; script-src 'self' 'nonce-...';",
          importance: 'critical',
          description: 'Warning: Contains unsafe-inline directive.'
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'passed',
          currentValue: 'max-age=31536000; includeSubDomains',
          recommendedValue: 'max-age=31536000; includeSubDomains',
          importance: 'critical',
          description: 'Protected with one-year HTTPS enforcement.'
        },
        {
          header: 'X-Frame-Options',
          status: 'passed',
          currentValue: 'SAMEORIGIN',
          recommendedValue: 'DENY',
          importance: 'high',
          description: 'Allows framing only by the same origin.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'passed',
          currentValue: 'nosniff',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'MIME sniffing disabled.'
        },
        {
          header: 'Permissions-Policy',
          status: 'missing',
          recommendedValue: 'camera=(), microphone=(), geolocation=()',
          importance: 'medium',
          description: 'Missing hardware feature restrictions.'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 82, status: 'compliant' },
        { category: 'A02 - Security Misconfiguration', score: 72, status: 'warning' },
        { category: 'A03 - Supply Chain Failures', score: 78, status: 'compliant' },
        { category: 'A04 - Cryptographic Failures', score: 90, status: 'compliant' },
        { category: 'A05 - Injection', score: 80, status: 'compliant' },
        { category: 'A06 - Insecure Design', score: 75, status: 'compliant' },
        { category: 'A07 - Authentication Failures', score: 84, status: 'compliant' },
        { category: 'A08 - Integrity Failures', score: 70, status: 'warning' },
        { category: 'A09 - Security Logging & Alerting', score: 74, status: 'compliant' },
        { category: 'A10 - Exception Handling', score: 79, status: 'compliant' }
      ],
      asvsLevel1PassRate: 88,
      asvsLevel2PassRate: 68
    }
  },
  {
    id: 'owasp-juice-shop',
    name: 'OWASP Juice Shop (Live Demo)',
    url: 'https://juice-shop.herokuapp.com',
    aliases: ['https://demo.owasp-juice.shop', 'http://juice-shop.herokuapp.com', 'https://juice-shop.herokuapp.com/'],
    category: 'owasp',
    badge: 'OWASP Flagship (52%)',
    description: 'The official OWASP flagship vulnerable web application built on Node.js, Express, and Angular. Intentionally insecure for security training and auditing.',
    result: {
      targetUrl: 'https://juice-shop.herokuapp.com',
      timestamp: new Date().toISOString(),
      score: 52,
      grade: 'D',
      summary: {
        critical: 2,
        high: 3,
        medium: 3,
        low: 1,
        info: 1,
        totalPassed: 11
      },
      findings: [
        {
          id: 'JS-01',
          title: 'Permissive Cross-Origin Resource Sharing (CORS Wildcard with Credentials)',
          severity: 'CRITICAL',
          owaspCategory: 'A01:2025 - Broken Access Control & SSRF',
          asvsId: '14.5.3',
          cwe: 'CWE-942',
          passed: false,
          description: 'The API responds with "Access-Control-Allow-Origin: *" combined with allowing authenticated sessions, permitting malicious origins to read user basket data.',
          impact: 'Cross-origin scripts running in visitor browsers can read private shopping cart data and authentication status.',
          remediation: 'Restrict allowed origins to an explicit trusted allowlist and never combine wildcard origins with credentials.',
          codeSnippet: {
            language: 'javascript',
            vulnerable: "// Vulnerable Express CORS setup\napp.use(cors({ origin: '*', credentials: true }));",
            remediated: "import cors from 'cors';\nconst ALLOWLIST = ['https://juice-shop.herokuapp.com'];\napp.use(cors({ origin: ALLOWLIST, credentials: true }));"
          }
        },
        {
          id: 'JS-02',
          title: "Permissive CSP Script Directives ('unsafe-inline' & 'unsafe-eval')",
          severity: 'HIGH',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '1.2.1',
          cwe: 'CWE-79',
          passed: false,
          description: 'Content-Security-Policy contains "unsafe-inline" and "unsafe-eval" to accommodate legacy Angular client template bindings.',
          impact: 'Negates core XSS defense protections, allowing stored and reflected script injection to execute within client browsers.',
          remediation: 'Deploy nonce-based script source restrictions and upgrade Angular templates to ahead-of-time (AOT) compilation without eval.',
          codeSnippet: {
            language: 'http',
            vulnerable: "Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
            remediated: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-R4nd0m123'; object-src 'none'; base-uri 'self';"
          }
        },
        {
          id: 'JS-03',
          title: 'Missing Permissions-Policy for Browser Sensors & Device APIs',
          severity: 'MEDIUM',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '8.3.1',
          cwe: 'CWE-16',
          passed: false,
          description: 'No Permissions-Policy header is served, permitting iframed content to access client microphone, camera, and geolocation.',
          impact: 'Embedded third-party content or iframe injections can query browser hardware features without user prompt restrictions.',
          remediation: 'Configure Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
          codeSnippet: {
            language: 'http',
            vulnerable: '# No Permissions-Policy header present',
            remediated: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'
          }
        },
        {
          id: 'JS-04',
          title: 'Short HSTS Duration & Missing Preload Directives',
          severity: 'MEDIUM',
          owaspCategory: 'A04:2025 - Cryptographic Failures',
          asvsId: '12.1.1',
          cwe: 'CWE-319',
          passed: false,
          description: 'Strict-Transport-Security duration is configured for only 1 day (86400 seconds) without includeSubDomains and preload.',
          impact: 'Leaves returning visitors vulnerable to SSL-stripping MITM attacks outside of short session windows.',
          remediation: 'Set max-age to at least 1 year (31536000 seconds) with includeSubDomains and submit to the HSTS preload list.',
          codeSnippet: {
            language: 'http',
            vulnerable: 'Strict-Transport-Security: max-age=86400',
            remediated: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
          }
        },
        {
          id: 'JS-05',
          title: 'Runtime Technology Leakage via X-Powered-By Express Header',
          severity: 'LOW',
          owaspCategory: 'A10:2025 - Exception Handling & Information Leakage',
          asvsId: '16.5.1',
          cwe: 'CWE-200',
          passed: false,
          description: 'HTTP response exposes "X-Powered-By: Express", confirming that the backend runs Node.js and Express.',
          impact: 'Aids attackers in crafting targeted Node.js prototype pollution and Express middleware payloads.',
          remediation: 'Disable the banner using app.disable("x-powered-by") or helmet().',
          codeSnippet: {
            language: 'javascript',
            vulnerable: '// Express default exposes banner\nconst app = express();',
            remediated: 'const app = express();\napp.disable("x-powered-by");'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'warning',
          currentValue: "default-src 'self' 'unsafe-inline' 'unsafe-eval';",
          recommendedValue: "default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';",
          importance: 'critical',
          description: "Warning: Contains unsafe-inline and unsafe-eval."
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'warning',
          currentValue: 'max-age=86400',
          recommendedValue: 'max-age=31536000; includeSubDomains; preload',
          importance: 'critical',
          description: 'Warning: Short duration (1 day). Preload not declared.'
        },
        {
          header: 'X-Frame-Options',
          status: 'passed',
          currentValue: 'SAMEORIGIN',
          recommendedValue: 'SAMEORIGIN',
          importance: 'high',
          description: 'Framing permitted only from the same origin.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'passed',
          currentValue: 'nosniff',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'MIME sniffing prevention active.'
        },
        {
          header: 'Permissions-Policy',
          status: 'missing',
          recommendedValue: 'camera=(), microphone=(), geolocation=()',
          importance: 'medium',
          description: 'Missing. Client device sensors are unrestricted.'
        },
        {
          header: 'Cross-Origin-Opener-Policy',
          status: 'missing',
          recommendedValue: 'same-origin',
          importance: 'medium',
          description: 'Missing. Vulnerable to cross-window Spectre side-channel attacks.'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 50, status: 'warning' },
        { category: 'A02 - Security Misconfiguration', score: 45, status: 'non-compliant' },
        { category: 'A03 - Supply Chain Failures', score: 65, status: 'warning' },
        { category: 'A04 - Cryptographic Failures', score: 60, status: 'warning' },
        { category: 'A05 - Injection', score: 48, status: 'non-compliant' },
        { category: 'A06 - Insecure Design', score: 55, status: 'warning' },
        { category: 'A07 - Authentication Failures', score: 52, status: 'warning' },
        { category: 'A08 - Integrity Failures', score: 58, status: 'warning' },
        { category: 'A09 - Security Logging & Alerting', score: 40, status: 'non-compliant' },
        { category: 'A10 - Exception Handling', score: 50, status: 'warning' }
      ],
      asvsLevel1PassRate: 58,
      asvsLevel2PassRate: 34
    }
  },
  {
    id: 'owasp-nodegoat',
    name: 'OWASP NodeGoat (Node.js Benchmark)',
    url: 'https://nodegoat.herokuapp.com',
    aliases: ['https://nodegoat.owasp.org', 'http://nodegoat.herokuapp.com'],
    category: 'owasp',
    badge: 'OWASP Node.js (38%)',
    description: 'Official OWASP project demonstrating OWASP Top 10 vulnerabilities specifically in the Node.js / Express / MongoDB runtime environment.',
    result: {
      targetUrl: 'https://nodegoat.herokuapp.com',
      timestamp: new Date().toISOString(),
      score: 38,
      grade: 'F',
      summary: {
        critical: 3,
        high: 3,
        medium: 2,
        low: 2,
        info: 1,
        totalPassed: 7
      },
      findings: [
        {
          id: 'NG-01',
          title: 'Server-Side JavaScript Code Injection via eval()',
          severity: 'CRITICAL',
          owaspCategory: 'A08:2025 - Software and Data Integrity Failures',
          asvsId: '5.5.1',
          cwe: 'CWE-95',
          passed: false,
          description: 'User contributions and retirement allocation calculations evaluate user input dynamically using eval(), permitting arbitrary code execution on the Node host process.',
          impact: 'Complete server compromise, reverse shell spawning, host file system tampering, and database secret extraction.',
          remediation: 'Eliminate eval() calls completely. Use dedicated expression parsers or sandboxed mathematical libraries like mathjs.',
          codeSnippet: {
            language: 'javascript',
            vulnerable: '// Insecure dynamic allocation calculation\nconst total = eval(req.body.preTax + " + " + req.body.roth);',
            remediated: 'import { evaluate } from "mathjs";\n// Safe expression parsing without process access\nconst total = evaluate(`${Number(req.body.preTax)} + ${Number(req.body.roth)}`);'
          }
        },
        {
          id: 'NG-02',
          title: 'NoSQL Query Selector Injection in Authentication Flow',
          severity: 'CRITICAL',
          owaspCategory: 'A05:2025 - Injection',
          asvsId: '5.3.4',
          cwe: 'CWE-943',
          passed: false,
          description: 'Login endpoint passes raw request body directly into MongoDB findOne() query, allowing attackers to inject {"$ne": null} operators to bypass authentication.',
          impact: 'Authentication bypass enabling unauthenticated administrative access without valid credentials.',
          remediation: 'Sanitize incoming payloads with mongo-sanitize and validate that fields are strictly string primitives with Zod.',
          codeSnippet: {
            language: 'javascript',
            vulnerable: 'db.users.findOne({ userName: req.body.userName, password: req.body.password });',
            remediated: 'import mongoSanitize from "mongo-sanitize";\nconst cleanBody = mongoSanitize(req.body);\ndb.users.findOne({ userName: String(cleanBody.userName) });'
          }
        },
        {
          id: 'NG-03',
          title: 'Prototype Pollution via Unsafe Parameter Deep Copy',
          severity: 'HIGH',
          owaspCategory: 'A03:2025 - Supply Chain Failures & Memory Safety',
          asvsId: '5.1.4',
          cwe: 'CWE-1321',
          passed: false,
          description: 'Profile updates utilize a recursive merge without sanitizing __proto__ or constructor keys, polluting the V8 Object prototype chain.',
          impact: 'Alters default object properties across the Node.js application, potentially bypassing authorization checks.',
          remediation: 'Reject magic property keys and validate schemas with Ajv or Zod.',
          codeSnippet: {
            language: 'javascript',
            vulnerable: 'function merge(target, src) {\n  for (let k in src) target[k] = src[k];\n}',
            remediated: 'import Ajv from "ajv";\nconst ajv = new Ajv({ removeAdditional: "all" });\n// Schema strictly rejects prototype keys'
          }
        },
        {
          id: 'NG-04',
          title: 'Complete Omission of Helmet Defensive HTTP Headers',
          severity: 'HIGH',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '1.1.1',
          cwe: 'CWE-16',
          passed: false,
          description: 'The Express application runs without defensive security headers (no CSP, no X-Frame-Options, no HSTS, no X-Content-Type-Options).',
          impact: 'Exposes application to XSS execution, Clickjacking, MIME-sniffing, and MITM transport downgrade.',
          remediation: 'Deploy helmet() as the first top-level Express middleware.',
          codeSnippet: {
            language: 'javascript',
            vulnerable: 'const app = express();\n// No security headers configured',
            remediated: 'import helmet from "helmet";\nconst app = express();\napp.use(helmet());'
          }
        },
        {
          id: 'NG-05',
          title: 'Insecure Session Cookie Configuration (Missing HttpOnly & SameSite)',
          severity: 'MEDIUM',
          owaspCategory: 'A07:2025 - Authentication Failures',
          asvsId: '3.4.1',
          cwe: 'CWE-614',
          passed: false,
          description: 'Session cookie "connect.sid" is issued without HttpOnly and SameSite flags.',
          impact: 'Enables credential theft through XSS and exposes sessions to CSRF state tampering.',
          remediation: 'Configure express-session with httpOnly: true, secure: true, and sameSite: "strict".',
          codeSnippet: {
            language: 'javascript',
            vulnerable: 'app.use(session({ secret: "keyboard cat" }));',
            remediated: 'app.use(session({\n  secret: process.env.SESSION_SECRET,\n  cookie: { httpOnly: true, secure: true, sameSite: "strict" }\n}));'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'missing',
          recommendedValue: "default-src 'self'; frame-ancestors 'none';",
          importance: 'critical',
          description: 'Missing. High risk of XSS execution.'
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'missing',
          recommendedValue: 'max-age=31536000; includeSubDomains',
          importance: 'critical',
          description: 'Missing. Unprotected against protocol downgrade.'
        },
        {
          header: 'X-Frame-Options',
          status: 'missing',
          recommendedValue: 'DENY',
          importance: 'high',
          description: 'Missing. Vulnerable to clickjacking.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'missing',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'Missing. MIME sniffing permitted.'
        },
        {
          header: 'Permissions-Policy',
          status: 'missing',
          recommendedValue: 'camera=(), microphone=()',
          importance: 'medium',
          description: 'Missing hardware feature constraints.'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 35, status: 'non-compliant' },
        { category: 'A02 - Security Misconfiguration', score: 30, status: 'non-compliant' },
        { category: 'A03 - Supply Chain Failures', score: 40, status: 'non-compliant' },
        { category: 'A04 - Cryptographic Failures', score: 45, status: 'non-compliant' },
        { category: 'A05 - Injection', score: 25, status: 'non-compliant' },
        { category: 'A06 - Insecure Design', score: 35, status: 'non-compliant' },
        { category: 'A07 - Authentication Failures', score: 40, status: 'non-compliant' },
        { category: 'A08 - Integrity Failures', score: 30, status: 'non-compliant' },
        { category: 'A09 - Security Logging & Alerting', score: 30, status: 'non-compliant' },
        { category: 'A10 - Exception Handling', score: 45, status: 'non-compliant' }
      ],
      asvsLevel1PassRate: 42,
      asvsLevel2PassRate: 18
    }
  },
  {
    id: 'owasp-webgoat',
    name: 'OWASP WebGoat (Java Benchmark)',
    url: 'https://webgoat.owasp.org',
    aliases: ['https://webgoat.herokuapp.com', 'http://webgoat.owasp.org'],
    category: 'owasp',
    badge: 'OWASP Benchmark (46%)',
    description: 'OWASP standard training application for web application security vulnerabilities. Java and Spring Boot architecture.',
    result: {
      targetUrl: 'https://webgoat.owasp.org',
      timestamp: new Date().toISOString(),
      score: 46,
      grade: 'D',
      summary: {
        critical: 2,
        high: 2,
        medium: 3,
        low: 2,
        info: 1,
        totalPassed: 8
      },
      findings: [
        {
          id: 'WG-01',
          title: 'Missing Content-Security-Policy Exposing Stored XSS',
          severity: 'CRITICAL',
          owaspCategory: 'A02:2025 - Security Misconfiguration',
          asvsId: '1.2.1',
          cwe: 'CWE-79',
          passed: false,
          description: 'No Content-Security-Policy header is served, permitting arbitrary script execution across lesson challenge frames.',
          impact: 'Allows stored and reflected XSS payloads to execute unrestricted in visitor browser sessions.',
          remediation: 'Configure a strict Content-Security-Policy header in Spring Security filter chain.',
          codeSnippet: {
            language: 'java',
            vulnerable: '// Spring Security lacking CSP\nhttp.headers();',
            remediated: 'http.headers(headers -> headers\n  .contentSecurityPolicy(csp -> csp\n    .policyDirectives("default-src \'self\'; frame-ancestors \'none\';")\n  )\n);'
          }
        },
        {
          id: 'WG-02',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          severity: 'HIGH',
          owaspCategory: 'A04:2025 - Cryptographic Failures',
          asvsId: '12.1.1',
          cwe: 'CWE-319',
          passed: false,
          description: 'HSTS is not enforced, permitting initial connection attempts over unencrypted cleartext HTTP.',
          impact: 'Users on insecure networks can be intercepted via SSL-stripping and credential sniffing.',
          remediation: 'Enforce HSTS with max-age=31536000 and includeSubDomains.',
          codeSnippet: {
            language: 'java',
            vulnerable: '// Lacking HSTS declaration\nserver.ssl.enabled=false;',
            remediated: 'http.headers(headers -> headers\n  .httpStrictTransportSecurity(hsts -> hsts\n    .includeSubDomains(true)\n    .maxAgeInSeconds(31536000)\n  )\n);'
          }
        },
        {
          id: 'WG-03',
          title: 'Missing X-Frame-Options Permitting Clickjacking',
          severity: 'MEDIUM',
          owaspCategory: 'A01:2025 - Broken Access Control & SSRF',
          asvsId: '14.4.1',
          cwe: 'CWE-1021',
          passed: false,
          description: 'WebGoat pages can be loaded within arbitrary third-party iframes without restrictions.',
          impact: 'Vulnerable to UI redressing and clickjacking attacks deceiving users into triggering unauthorized state changes.',
          remediation: 'Send "X-Frame-Options: DENY" or frame-ancestors in CSP.',
          codeSnippet: {
            language: 'http',
            vulnerable: '# No X-Frame-Options header',
            remediated: 'X-Frame-Options: DENY'
          }
        },
        {
          id: 'WG-04',
          title: 'Detailed Server Banner Disclosure (Apache-Coyote)',
          severity: 'LOW',
          owaspCategory: 'A10:2025 - Exception Handling & Information Leakage',
          asvsId: '16.5.1',
          cwe: 'CWE-200',
          passed: false,
          description: 'The server returns "Server: Apache-Coyote/1.1", leaking the underlying Tomcat servlet container version.',
          impact: 'Aids attackers in identifying vulnerable Tomcat versions and known container CVEs.',
          remediation: 'Suppress server header in Tomcat server.xml (server="").',
          codeSnippet: {
            language: 'xml',
            vulnerable: '<Connector port="8080" protocol="HTTP/1.1" />',
            remediated: '<Connector port="8080" protocol="HTTP/1.1" server="" />'
          }
        }
      ],
      headerAudits: [
        {
          header: 'Content-Security-Policy',
          status: 'missing',
          recommendedValue: "default-src 'self'; frame-ancestors 'none';",
          importance: 'critical',
          description: 'Missing. Allows unrestricted inline script execution.'
        },
        {
          header: 'Strict-Transport-Security (HSTS)',
          status: 'missing',
          recommendedValue: 'max-age=31536000; includeSubDomains',
          importance: 'critical',
          description: 'Missing transport layer encryption declaration.'
        },
        {
          header: 'X-Frame-Options',
          status: 'missing',
          recommendedValue: 'DENY',
          importance: 'high',
          description: 'Missing. Vulnerable to iframe embedding and clickjacking.'
        },
        {
          header: 'X-Content-Type-Options',
          status: 'warning',
          currentValue: 'nosniff',
          recommendedValue: 'nosniff',
          importance: 'high',
          description: 'Active on some endpoints but inconsistent.'
        },
        {
          header: 'Permissions-Policy',
          status: 'missing',
          recommendedValue: 'camera=(), microphone=()',
          importance: 'medium',
          description: 'Missing hardware feature restrictions.'
        }
      ],
      owaspCompliance: [
        { category: 'A01 - Broken Access Control & SSRF', score: 45, status: 'non-compliant' },
        { category: 'A02 - Security Misconfiguration', score: 40, status: 'non-compliant' },
        { category: 'A03 - Supply Chain Failures', score: 50, status: 'warning' },
        { category: 'A04 - Cryptographic Failures', score: 45, status: 'non-compliant' },
        { category: 'A05 - Injection', score: 40, status: 'non-compliant' },
        { category: 'A06 - Insecure Design', score: 45, status: 'non-compliant' },
        { category: 'A07 - Authentication Failures', score: 48, status: 'non-compliant' },
        { category: 'A08 - Integrity Failures', score: 45, status: 'non-compliant' },
        { category: 'A09 - Security Logging & Alerting', score: 35, status: 'non-compliant' },
        { category: 'A10 - Exception Handling', score: 45, status: 'non-compliant' }
      ],
      asvsLevel1PassRate: 52,
      asvsLevel2PassRate: 26
    }
  }
];
