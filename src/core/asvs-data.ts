export interface AsvsRequirement {
  id: string;
  chapter: string;
  title: string;
  level: 'L1' | 'L2' | 'L3';
  description: string;
  verificationGuide: string;
}

export const ASVS_5_REQUIREMENTS: AsvsRequirement[] = [
  // Authentication & Passwords
  {
    id: '6.2.1',
    chapter: 'Authentication (V6)',
    title: 'Minimum Password Length',
    level: 'L1',
    description: 'Verify passwords are at least 8 characters in length, with 15+ characters strongly recommended.',
    verificationGuide: 'Check user registration and password reset validation rules.'
  },
  {
    id: '6.2.4',
    chapter: 'Authentication (V6)',
    title: 'Breached & Common Password Blacklist',
    level: 'L1',
    description: 'Verify the application blocks at least the top 3,000 common and easily guessed passwords.',
    verificationGuide: 'Test registration with "password123", "admin", "qwerty" - must reject.'
  },
  {
    id: '6.2.5',
    chapter: 'Authentication (V6)',
    title: 'No Arbitrary Composition Rules',
    level: 'L1',
    description: 'Verify that arbitrary character composition rules (e.g. must contain 1 uppercase, 1 symbol) are not enforced, permitting passphrases.',
    verificationGuide: 'Permit users to choose long passphrases without artificial restriction.'
  },
  {
    id: '6.2.7',
    chapter: 'Authentication (V6)',
    title: 'Password Manager & Paste Support',
    level: 'L1',
    description: 'Verify password fields allow pasting and support browser and external password managers.',
    verificationGuide: 'Verify no onpaste="return false;" or paste-blocking event handlers.'
  },
  {
    id: '6.3.1',
    chapter: 'Authentication (V6)',
    title: 'Anti-Automation & Brute Force Defense',
    level: 'L1',
    description: 'Verify rate limiting, account lockout with exponential backoff, or CAPTCHA prevents automated credential stuffing.',
    verificationGuide: 'Examine login endpoint response headers and 429 Too Many Requests triggers.'
  },
  {
    id: '6.3.3',
    chapter: 'Authentication (V6)',
    title: 'Multi-Factor Authentication (MFA)',
    level: 'L2',
    description: 'Verify multi-factor authentication (TOTP, WebAuthn/FIDO2) is available or required for sensitive operations.',
    verificationGuide: 'Audit account security settings for authenticator app or hardware token integration.'
  },

  // Session Management
  {
    id: '7.2.3',
    chapter: 'Session Management (V7)',
    title: 'CSPRNG Session Token Entropy',
    level: 'L1',
    description: 'Verify session identifiers are generated using cryptographically secure pseudo-random number generators with at least 128 bits of entropy.',
    verificationGuide: 'Ensure crypto.randomBytes(16) or equivalent is used instead of Math.random().'
  },
  {
    id: '7.2.4',
    chapter: 'Session Management (V7)',
    title: 'Session Token Regeneration on Auth',
    level: 'L1',
    description: 'Verify a new session identifier is issued upon user authentication and privilege change (session fixation defense).',
    verificationGuide: 'Inspect cookie headers before and after login.'
  },
  {
    id: '7.4.1',
    chapter: 'Session Management (V7)',
    title: 'Immediate Session Invalidation on Logout',
    level: 'L1',
    description: 'Verify session identifiers are invalidated server-side immediately upon logout or timeout.',
    verificationGuide: 'Replay old session cookie after logout request; must return 401.'
  },

  // Access Control & Input
  {
    id: '8.2.1',
    chapter: 'Access Control (V8)',
    title: 'Explicit Function-Level Permissions',
    level: 'L1',
    description: 'Verify users can only access functions and endpoints for which they have explicitly granted permissions (RBAC/ABAC).',
    verificationGuide: 'Check server middleware verifies roles before controller logic executes.'
  },
  {
    id: '8.3.1',
    chapter: 'Access Control (V8)',
    title: 'Server-Side Authorization Enforcement',
    level: 'L1',
    description: 'Verify access control checks cannot be bypassed or overridden by client-side manipulation of headers or hidden fields.',
    verificationGuide: 'Enforce all permission checks strictly in backend service code.'
  },
  {
    id: '1.2.4',
    chapter: 'Data Protection & Injection (V1)',
    title: 'Parameterized Database Queries',
    level: 'L1',
    description: 'Verify all database queries use parameterized inputs, prepared statements, or strongly typed ORM wrappers.',
    verificationGuide: 'Audit repository queries for string concatenation of user parameters.'
  },
  {
    id: '2.2.1',
    chapter: 'Validation & Sanitization (V2)',
    title: 'Service-Layer Input Validation',
    level: 'L1',
    description: 'Verify all incoming data is validated against strict schemas (allowlists) at the trusted service layer.',
    verificationGuide: 'Inspect API request validation schemas (e.g. Zod, Joi, or class-validator).'
  },

  // Cryptography & Communications
  {
    id: '12.1.1',
    chapter: 'Communications (V12)',
    title: 'TLS 1.2+ for External Traffic',
    level: 'L1',
    description: 'Verify all public web endpoints enforce TLS 1.2 or TLS 1.3 with deprecation of SSLv3, TLS 1.0, and TLS 1.1.',
    verificationGuide: 'Audit server TLS cipher negotiation and certificate chain.'
  },
  {
    id: '14.2.1',
    chapter: 'Data Protection (V14)',
    title: 'No Sensitive Data in Query Parameters',
    level: 'L1',
    description: 'Verify tokens, passwords, and sensitive PII are never passed via URL query strings or GET parameters.',
    verificationGuide: 'Inspect API designs for auth tokens in query string.'
  },

  // Logging & Exceptional Conditions
  {
    id: '16.3.1',
    chapter: 'Security Logging (V16)',
    title: 'Audit Logging for Authentication Events',
    level: 'L2',
    description: 'Verify successful and failed authentication attempts, password resets, and MFA challenges are logged.',
    verificationGuide: 'Inspect server audit logs for login event schema.'
  },
  {
    id: '16.5.1',
    chapter: 'Error Handling (V16)',
    title: 'Sanitized User Error Messages',
    level: 'L2',
    description: 'Verify application returns generic, sanitized error messages to the client without exposing stack traces or database errors.',
    verificationGuide: 'Trigger 500 error; ensure response contains correlation ID, not stack trace.'
  }
];
