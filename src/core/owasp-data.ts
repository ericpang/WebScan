export interface OwaspCategoryInfo {
  id: string;
  name: string;
  shortDesc: string;
  keyMitigations: string[];
  cweList: string[];
}

export const OWASP_TOP_10_2025: OwaspCategoryInfo[] = [
  {
    id: 'A01',
    name: 'Broken Access Control & SSRF',
    shortDesc: 'Unauthorized information disclosure, privilege escalation, and Server-Side Request Forgery.',
    keyMitigations: [
      'Deny access by default; enforce authorization at the service layer.',
      'Validate and restrict target hostnames/IPs against private subnets (SSRF guard).',
      'Disable directory listing and enforce record ownership checks on IDs.'
    ],
    cweList: ['CWE-200', 'CWE-284', 'CWE-285', 'CWE-918', 'CWE-639']
  },
  {
    id: 'A02',
    name: 'Security Misconfiguration',
    shortDesc: 'Unpatched flaws, default accounts, open cloud storage, and missing security headers.',
    keyMitigations: [
      'Implement strict Content-Security-Policy (CSP) and HSTS headers.',
      'Disable debug endpoints and detailed stack traces in production.',
      'Automate configuration audits and hardening scripts in CI/CD pipelines.'
    ],
    cweList: ['CWE-16', 'CWE-209', 'CWE-1004', 'CWE-614']
  },
  {
    id: 'A03',
    name: 'Software Supply Chain Failures',
    shortDesc: 'Compromised third-party packages, vulnerable dependencies, and untrusted registries.',
    keyMitigations: [
      'Enforce lockfile integrity (package-lock.json) and verify SBOM.',
      'Automate vulnerability scans with npm audit / Snyk / Dependabot.',
      'Pin library versions and avoid running installation scripts with root privileges.'
    ],
    cweList: ['CWE-1395', 'CWE-1104', 'CWE-829']
  },
  {
    id: 'A04',
    name: 'Cryptographic Failures',
    shortDesc: 'Weak encryption algorithms, exposed sensitive data in transit or rest, and weak TLS ciphers.',
    keyMitigations: [
      'Enforce TLS 1.3 or TLS 1.2+ with modern authenticated ciphers (AES-256-GCM).',
      'Hash passwords with modern memory-hard functions (Argon2id or bcrypt).',
      'Never transmit sensitive tokens or PII in URL query parameters.'
    ],
    cweList: ['CWE-310', 'CWE-327', 'CWE-328', 'CWE-319']
  },
  {
    id: 'A05',
    name: 'Injection',
    shortDesc: 'SQL, NoSQL, OS Command, and Cross-Site Scripting (XSS) from untrusted input.',
    keyMitigations: [
      'Use parameterized queries or typed ORM abstractions exclusively.',
      'Context-aware output encoding (HTML, URL, JavaScript).',
      'Strict input schema validation with allowlists before sinking to interpreters.'
    ],
    cweList: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-77']
  },
  {
    id: 'A06',
    name: 'Insecure Design',
    shortDesc: 'Flaws introduced before coding: lack of threat modeling, rate-limiting, and defense-in-depth.',
    keyMitigations: [
      'Conduct STRIDE threat modeling during feature specification.',
      'Enforce strict rate limits on authentication, password resets, and critical endpoints.',
      'Design fail-closed architectures with defense-in-depth controls.'
    ],
    cweList: ['CWE-1059', 'CWE-256', 'CWE-501']
  },
  {
    id: 'A07',
    name: 'Authentication Failures',
    shortDesc: 'Credential stuffing, session hijacking, weak password policies, and missing MFA.',
    keyMitigations: [
      'Implement Multi-Factor Authentication (MFA) and check against breached credentials.',
      'Issue cryptographically random session tokens (128+ bits entropy) rotated on login.',
      'Store cookies with HttpOnly, Secure, and SameSite=Strict flags.'
    ],
    cweList: ['CWE-287', 'CWE-384', 'CWE-613', 'CWE-307']
  },
  {
    id: 'A08',
    name: 'Software or Data Integrity Failures',
    shortDesc: 'Unsafe deserialization, unsigned code updates, and unvalidated CDN script imports.',
    keyMitigations: [
      'Implement Subresource Integrity (SRI) on external CDN assets.',
      'Avoid unsafe deserialization of arbitrary objects from untrusted sources.',
      'Verify digital signatures for downloaded plugins, firmware, or updates.'
    ],
    cweList: ['CWE-502', 'CWE-353', 'CWE-494']
  },
  {
    id: 'A09',
    name: 'Security Logging and Alerting Failures',
    shortDesc: 'Undetected breaches due to missing audit trails, unmonitored logs, and absent alerting.',
    keyMitigations: [
      'Log all authentication, access control failures, and suspicious exceptions.',
      'Standardize structured JSON logging with synchronized NTP timestamps.',
      'Protect logs from tampering and log injection attacks; stream off-box.'
    ],
    cweList: ['CWE-778', 'CWE-117', 'CWE-532']
  },
  {
    id: 'A10',
    name: 'Mishandling of Exceptional Conditions',
    shortDesc: 'Information leakage through verbose stack traces, fail-open states, and crash states.',
    keyMitigations: [
      'Implement global error handlers returning sanitized human-readable messages.',
      'Ensure fail-closed states when security checks encounter unexpected errors.',
      'Keep internal diagnostic details strictly in server-side logs.'
    ],
    cweList: ['CWE-209', 'CWE-703', 'CWE-755']
  }
];
