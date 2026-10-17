import { ScanResult } from '../types/security';

export interface TargetPreset {
  id: string;
  name: string;
  url: string;
  badge: string;
  description: string;
  result: ScanResult;
}

export const TARGET_PRESETS: TargetPreset[] = [
  {
    id: 'hardened-cloud',
    name: 'Hardened Cloud API Gateway',
    url: 'https://api.secureguard.cloud',
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
  }
];
