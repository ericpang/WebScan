import { NodeAuditAnalysis } from '../types/security';

export const NODE_AUDIT_PRESETS: NodeAuditAnalysis[] = [
  {
    id: 'NODE-PRESET-01',
    scenarioName: 'OWASP Juice Shop / Express — Prototype Pollution via Deep Object Merge',
    framework: 'Express',
    vulnerabilityName: 'Prototype Pollution (V8 Prototype Chain Manipulation)',
    description: 'The endpoint performs an unconstrained recursive merge of untrusted JSON request bodies into existing system objects without validating magic properties (__proto__, constructor, prototype). In Node.js (V8 engine), modifying Object.prototype pollutes all objects instantiated across the entire runtime.',
    rootCause: 'Lack of key-path sanitization and absent prototype-free dictionary objects (Object.create(null)). Recursive key assignment iterates directly over user-controlled keys, allowing mutations to Object.prototype in the V8 heap.',
    owaspId: 'A03:2025 - Injection & Memory Safety',
    asvsId: 'V5.1.4 (Prohibit Object Prototype Manipulation)',
    cwe: 'CWE-1321: Improperly Controlled Modification of Object Prototype Attributes',
    impact: 'Global object property tampering, authorization bypass (e.g. injecting isAdmin flag into empty user checks), Denial of Service, or Remote Code Execution (RCE) via downstream library gadgets.',
    severity: 'CRITICAL',
    pocConceptual: {
      title: 'Safe Abstract Prototype Injection Verification',
      description: 'Abstract, non-weaponized JSON payload verifying that property lookup traverses the modified Object prototype.',
      payloadExample: `// Conceptual trigger payload sent to /api/user/profile
POST /api/user/profile HTTP/1.1
Content-Type: application/json

{
  "theme": "dark",
  "__proto__": {
    "pollutedFlag": true,
    "role": "admin"
  }
}

// Verification check in Node.js runtime:
// ({}).pollutedFlag === true // Proves Object.prototype has been altered!`,
      behaviorNote: 'Defensive demonstration only. Confirms V8 runtime prototype pollution vulnerability without deploying secondary RCE gadgets.'
    },
    remediation: {
      guidance: 'Enforce schema-based validation on all incoming JSON payloads using Ajv or Zod. Strip magical property keys (__proto__, constructor, prototype), utilize Map objects or Object.create(null) for unconstrained key-value dictionaries, or freeze Object.prototype during initialization.',
      vulnerableCode: `// ❌ Vulnerable Express endpoint
import express from 'express';
const app = express();
app.use(express.json());

function mergeUserConfig(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      mergeUserConfig(target[key], source[key]); // Unsafe recursion!
    } else {
      target[key] = source[key]; // Injects __proto__ directly
    }
  }
  return target;
}

app.post('/api/user/settings', (req, res) => {
  const userSettings = {};
  mergeUserConfig(userSettings, req.body);
  res.json({ status: 'ok', settings: userSettings });
});`,
      remediatedCode: `// ✅ Remediated Express endpoint using Ajv & Safe Key Filtering
import express from 'express';
import Ajv from 'ajv';

const app = express();
app.use(express.json({ limit: '100kb' }));

const ajv = new Ajv({ removeAdditional: 'all' });
const SettingsSchema = {
  type: 'object',
  properties: {
    theme: { type: 'string', enum: ['light', 'dark', 'system'] },
    notifications: { type: 'boolean' }
  },
  required: ['theme'],
  additionalProperties: false // Reject prototype/unexpected keys
};
const validate = ajv.compile(SettingsSchema);

app.post('/api/user/settings', (req, res) => {
  // 1. Strict schema validation
  const valid = validate(req.body);
  if (!valid) {
    return res.status(400).json({ error: 'Validation failed', details: validate.errors });
  }

  // 2. Safe prototype-free storage
  const safeConfig = Object.create(null);
  safeConfig.theme = req.body.theme;
  safeConfig.notifications = Boolean(req.body.notifications);

  res.json({ status: 'ok', settings: safeConfig });
});`,
      ecosystemPackages: [
        { name: 'ajv', npmInstall: 'npm install ajv', role: 'JSON Schema validator enforcing strict property allowlisting and rejecting prototype keys' },
        { name: 'zod', npmInstall: 'npm install zod', role: 'TypeScript-first schema declaration and data validation with automatic type inference' },
        { name: 'lodash.merge (patched)', npmInstall: 'npm install lodash.merge@latest', role: 'Maintained deep merge library protected against prototype pollution' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-02',
    scenarioName: 'Fastify / Express — Event Loop Starvation via ReDoS',
    framework: 'Fastify',
    vulnerabilityName: 'Regular Expression Denial of Service (ReDoS) Event Loop Starvation',
    description: 'A synchronous regular expression with polynomial or exponential backtracking evaluates user-supplied input strings on the primary V8 thread. Because Node.js relies on a single-threaded libuv event loop, catastrophic backtracking freezes all concurrent I/O operations and stops incoming request processing.',
    rootCause: 'Nested quantifiers in regular expressions (e.g. (a+)+ or ([a-zA-Z]+)*) evaluated synchronously by the V8 regex engine against adversarial strings.',
    owaspId: 'A06:2025 - Insecure Design & Resilience',
    asvsId: 'V13.2.1 (Prevent Event Loop Starvation & ReDoS)',
    cwe: 'CWE-1333: Inefficient Regular Expression Complexity',
    impact: 'Complete service Denial of Service (DoS), 100% CPU lockup on host process, dropped socket connections, and failure of health check probes.',
    severity: 'HIGH',
    pocConceptual: {
      title: 'Safe Catastrophic Backtracking Trigger (O(2^n))',
      description: 'Input exhibiting quadratic/exponential state permutations in vulnerable non-deterministic finite automata (NFA).',
      payloadExample: `// Conceptual trigger payload sent to validation endpoint:
POST /api/validate/email HTTP/1.1
Content-Type: application/json

{
  "identifier": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
}

// Regex: /^([a-zA-Z0-9_\\.-]+)+@([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,4}$/
// Result: 50+ trailing characters without '@' causes 2^50 backtracking steps,
// locking the Node.js event loop for >45 seconds.`,
      behaviorNote: 'Defensive theoretical demonstration. Evaluates algorithm complexity without executing distributed attack traffic.'
    },
    remediation: {
      guidance: 'Replace backtrack-prone regex engines with linear-time engines like Google RE2 via the re2 npm package. Enforce strict character length bounds before running regex, validate patterns with safe-regex2 at build time, and delegate computationally expensive parsing to worker threads.',
      vulnerableCode: `// ❌ Vulnerable synchronous regex on Node.js main thread
import fastify from 'fastify';
const app = fastify();

// Vulnerable nested quantifier regex
const IDENTIFIER_REGEX = /^([a-zA-Z0-9]+)+$/;

app.post('/api/validate', async (req, reply) => {
  const { input } = req.body;
  // Blocks the single-threaded event loop!
  const isMatch = IDENTIFIER_REGEX.test(input);
  return { valid: isMatch };
});`,
      remediatedCode: `// ✅ Remediated with RE2 linear engine & length boundary
import fastify from 'fastify';
import RE2 from 're2'; // Google RE2 guarantees linear O(n) execution time

const app = fastify();

// Linear time regular expression guarantee (no catastrophic backtracking)
const SAFE_IDENTIFIER_REGEX = new RE2('^[a-zA-Z0-9]{1,64}$');

app.post('/api/validate', async (req, reply) => {
  const { input } = req.body;

  // 1. Enforce strict length cap before regex processing
  if (typeof input !== 'string' || input.length === 0 || input.length > 64) {
    return reply.status(400).send({ error: 'Input must be a string between 1 and 64 characters' });
  }

  // 2. Safe execution guaranteed in linear time
  const isMatch = SAFE_IDENTIFIER_REGEX.test(input);
  return { valid: isMatch };
});`,
      ecosystemPackages: [
        { name: 're2', npmInstall: 'npm install re2', role: 'Drop-in C++ Google RE2 wrapper ensuring O(n) linear regex time and preventing ReDoS' },
        { name: 'safe-regex2', npmInstall: 'npm install safe-regex2', role: 'Static linting tool to detect vulnerable backtracking patterns in regexes' },
        { name: 'express-rate-limit', npmInstall: 'npm install express-rate-limit', role: 'Rate limiting middleware preventing high-frequency computational abuse' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-03',
    scenarioName: 'Node.js / Axios — SSRF in Outbound Webhook Dispatcher',
    framework: 'Node.js Core',
    vulnerabilityName: 'Server-Side Request Forgery (SSRF) via Unvalidated Outbound HTTP',
    description: 'An application accepts a user-defined URL parameter (e.g. for outgoing webhooks, avatar fetching, or RSS ingestion) and dispatches an outbound HTTP request using Axios or node-fetch without IP resolution checks, allowing attackers to access internal cloud metadata and private microservices.',
    rootCause: 'Omission of pre-request DNS resolution and CIDR allowlist/blocklist validation. Target URL scheme and host are trusted blindly by client HTTP libraries.',
    owaspId: 'A01:2025 - Broken Access Control & SSRF',
    asvsId: 'V12.6.1 (Mitigate Server-Side Request Forgery)',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    impact: 'Exfiltration of Cloud Instance Metadata (AWS IMDSv1/v2 credentials at 169.254.169.254), internal port discovery, interaction with unauthenticated Redis/RabbitMQ clusters, and container escape.',
    severity: 'CRITICAL',
    pocConceptual: {
      title: 'Safe SSRF Boundary Traversal Representation',
      description: 'Abstract request targeting link-local cloud metadata endpoints within the internal network perimeter.',
      payloadExample: `// Conceptual trigger payload sent to webhook registration:
POST /api/webhooks/register HTTP/1.1
Content-Type: application/json

{
  "targetUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

// Server executes outbound request:
// axios.get("http://169.254.169.254/...")
// Response containing IAM role temporary token leaked back to client!`,
      behaviorNote: 'Defensive representation. Demonstrates SSRF risk without executing real cloud metadata exfiltration.'
    },
    remediation: {
      guidance: 'Perform strict scheme checking (HTTP/HTTPS only). Resolve DNS addresses before establishing connections, reject loopback (127.0.0.0/8), private RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and link-local cloud metadata (169.254.169.254). Enforce no-redirect policy on outbound clients.',
      vulnerableCode: `// ❌ Vulnerable outbound request handler
import express from 'express';
import axios from 'axios';
const app = express();
app.use(express.json());

app.post('/api/webhooks/trigger', async (req, res) => {
  const { url } = req.body;
  // Blind outbound request without SSRF protection!
  const response = await axios.post(url, { event: 'ping' });
  res.json({ status: 'delivered', code: response.status });
});`,
      remediatedCode: `// ✅ Remediated outbound client with DNS resolution guard
import express from 'express';
import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import axios from 'axios';

const app = express();
app.use(express.json());

async function validateOutboundUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Disallowed scheme');
  }

  // Resolve hostname to IP to prevent DNS rebinding
  const { address } = await dns.lookup(parsed.hostname);
  const addr = ipaddr.parse(address);
  const range = addr.range();

  // Block private, loopback, link-local, carrier-grade NAT
  const BLOCKED_RANGES = ['loopback', 'private', 'linkLocal', 'carrierGradeNat', 'uniqueLocal'];
  if (BLOCKED_RANGES.includes(range) || address === '169.254.169.254') {
    throw new Error(\`SSRF Guard: IP \${address} resolves to blocked internal network\`);
  }

  return parsed.href;
}

app.post('/api/webhooks/trigger', async (req, res) => {
  try {
    const verifiedUrl = await validateOutboundUrl(req.body.url);
    const client = axios.create({
      timeout: 3000,
      maxRedirects: 0 // Prevent redirect to internal IPs
    });
    await client.post(verifiedUrl, { event: 'ping' });
    res.json({ status: 'delivered' });
  } catch (err) {
    res.status(400).json({ error: 'Outbound delivery blocked: Invalid destination URL' });
  }
});`,
      ecosystemPackages: [
        { name: 'ipaddr.js', npmInstall: 'npm install ipaddr.js', role: 'IPv4 and IPv6 parsing and subnet range validation library' },
        { name: 'ssrf-req-filter', npmInstall: 'npm install ssrf-req-filter', role: 'Agent wrapper blocking requests to RFC 1918 and loopback addresses' },
        { name: 'agentkeepalive', npmInstall: 'npm install agentkeepalive', role: 'Hardened HTTP agent with connection pooling and DNS pinning capabilities' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-04',
    scenarioName: 'NestJS — Broken Object Level Authorization (BOLA / IDOR)',
    framework: 'NestJS',
    vulnerabilityName: 'Broken Object Level Authorization (BOLA / IDOR)',
    description: 'A NestJS resource controller accepts an entity identifier directly from path parameters (@Param(\'id\')) and queries the database repository without verifying that the authenticated user possesses ownership or organizational tenancy over that specific object.',
    rootCause: 'Access control checks rely exclusively on role-based endpoint guards (@UseGuards(JwtAuthGuard)) while omitting record-level ownership checks inside the service layer.',
    owaspId: 'A01:2025 - Broken Access Control & SSRF',
    asvsId: 'V4.1.1 (Enforce Context-Aware Access Control on Data Records)',
    cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
    impact: 'Horizontal privilege escalation allowing authenticated users to read, update, or delete confidential documents belonging to other tenants or users.',
    severity: 'HIGH',
    pocConceptual: {
      title: 'Safe IDOR Parameter Tampering Scenario',
      description: 'Abstract HTTP transaction demonstrating missing tenant boundary check.',
      payloadExample: `// User 1002 authenticates and receives valid JWT:
GET /api/invoices/inv-8842 HTTP/1.1
Host: api.enterprise.app
Authorization: Bearer <valid_jwt_for_user_1002>

// Vulnerable Controller executes:
// repository.findOne({ where: { id: 'inv-8842' } })
// Invoice belonging to User 9941 is returned without authorization error!`,
      behaviorNote: 'Defensive conceptual check. Demonstrates horizontal authorization bypass across distinct tenant boundaries.'
    },
    remediation: {
      guidance: 'Always scope database queries using the authenticated user identity or tenant ID extracted securely from request context (req.user.tenantId). Implement policy-based authorization using CASL or NestJS Interceptors.',
      vulnerableCode: `// ❌ Vulnerable NestJS Controller
import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { InvoiceService } from './invoice.service';

@Controller('invoices')
@UseGuards(JwtAuthGuard)
export class InvoiceController {
  constructor(private readonly invoiceService: InvoiceService) {}

  @Get(':id')
  async getInvoice(@Param('id') id: string) {
    // Flaw: Fetches record purely by client ID without user ownership check!
    return this.invoiceService.findById(id);
  }
}`,
      remediatedCode: `// ✅ Remediated NestJS Controller with Ownership Scoping
import { Controller, Get, Param, UseGuards, ForbiddenException, Req } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { InvoiceService } from './invoice.service';

@Controller('invoices')
@UseGuards(JwtAuthGuard)
export class InvoiceController {
  constructor(private readonly invoiceService: InvoiceService) {}

  @Get(':id')
  async getInvoice(@Param('id') id: string, @Req() req: any) {
    const authenticatedTenantId = req.user.tenantId;

    // Secure: Queries database scoped strictly to authenticated tenant context
    const invoice = await this.invoiceService.findOneScoped({
      id,
      tenantId: authenticatedTenantId
    });

    if (!invoice) {
      // Safe 404 prevents resource enumeration
      throw new ForbiddenException('Access denied or resource does not exist.');
    }

    return invoice;
  }
}`,
      ecosystemPackages: [
        { name: '@casl/ability', npmInstall: 'npm install @casl/ability @casl/angular', role: 'Isomorphic authorization library enforcing attribute-based access control (ABAC)' },
        { name: 'nestjs-casl', npmInstall: 'npm install nestjs-casl', role: 'NestJS module providing declarative permissions guards and decorators' },
        { name: 'passport', npmInstall: 'npm install passport @nestjs/passport', role: 'Authentication framework managing verified identity propagation' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-05',
    scenarioName: 'OWASP NodeGoat / Mongoose — NoSQL Operator Injection in Auth',
    framework: 'Mongoose',
    vulnerabilityName: 'NoSQL Operator Injection in Document Queries',
    description: 'User-provided objects from req.body or query strings are passed directly into Mongoose/MongoDB query methods (e.g. findOne(req.body)). Attackers can supply BSON query operators like {"$ne": null} or {"$gt": ""} to bypass authentication checks without knowing credentials.',
    rootCause: 'Express body parser parses nested JSON objects. Passing raw objects to database drivers treats keys starting with "$" as query operators rather than literal string values.',
    owaspId: 'A03:2025 - Injection & Memory Safety',
    asvsId: 'V5.3.4 (Prevent Database Query Selector & NoSQL Injection)',
    cwe: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
    impact: 'Complete authentication bypass, data exfiltration of password hashes and private records, and arbitrary document manipulation.',
    severity: 'CRITICAL',
    pocConceptual: {
      title: 'Safe Abstract Query Selector Injection',
      description: 'Abstract representation of MongoDB BSON operator altering boolean evaluation.',
      payloadExample: `// Conceptual login payload:
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": { "$ne": null }
}

// Resulting MongoDB Query:
// db.users.findOne({ username: "admin", password: { "$ne": null } })
// Evaluation resolves to true because admin password is not null!
// Authentication bypassed without password!`,
      behaviorNote: 'Defensive representation. Demonstrates BSON operator interpretation in database query layer.'
    },
    remediation: {
      guidance: 'Sanitize incoming payloads using mongo-sanitize to strip keys containing dollar signs ($). Strictly validate types with Zod or express-validator to enforce that parameters are primitive strings. Never pass entire body objects directly to database query functions.',
      vulnerableCode: `// ❌ Vulnerable Mongoose query handler
import express from 'express';
import mongoose from 'express';
import { User } from './models/user';

const app = express();
app.use(express.json());

app.post('/api/login', async (req, res) => {
  // Dangerous: Passing entire req.body allows $ne, $gt, $regex operators!
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password
  });

  if (user) {
    res.json({ token: 'mock-session-token' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`,
      remediatedCode: `// ✅ Remediated with mongo-sanitize and strict primitive type guards
import express from 'express';
import mongoSanitize from 'mongo-sanitize';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { User } from './models/user';

const app = express();
app.use(express.json());

// 1. Strict input validation schema ensuring string primitives
const LoginSchema = z.object({
  username: z.string().min(3).max(50),
  password: z.string().min(8).max(128)
});

app.post('/api/login', async (req, res) => {
  // 2. Strip any lingering "$" or "." prefix keys
  const cleanBody = mongoSanitize(req.body);

  const parsed = LoginSchema.safeParse(cleanBody);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid credentials format' });
  }

  // 3. Query strictly by username, verify hashed password with bcrypt
  const user = await User.findOne({ username: parsed.data.username }).select('+password');
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ status: 'authenticated' });
});`,
      ecosystemPackages: [
        { name: 'mongo-sanitize', npmInstall: 'npm install mongo-sanitize', role: 'Strips out any keys that start with "$" from user inputs to prevent operator injection' },
        { name: 'zod', npmInstall: 'npm install zod', role: 'Validates that values are strictly string primitives and disallows unexpected nested objects' },
        { name: 'bcrypt', npmInstall: 'npm install bcrypt', role: 'Provides secure salted password hashing resisting database injection extraction' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-06',
    scenarioName: 'OWASP Juice Shop / Express — Insecure Session Cookie & Missing Defensive Headers',
    framework: 'Express',
    vulnerabilityName: 'Missing Defensive HTTP Headers & Insecure Session Cookie Attributes',
    description: 'The Express application runs without defensive security headers (CSP, HSTS, X-Frame-Options) and issues session cookies without HttpOnly, SameSite, and Secure flags, leaving the session open to XSS theft and CSRF attacks.',
    rootCause: 'Absence of the Helmet security header middleware and omitted security attribute declarations in express-session configuration.',
    owaspId: 'A07:2025 - Identification and Authentication Failures',
    asvsId: 'V3.4.1 (Enforce Secure, HttpOnly, and SameSite Cookie Attributes)',
    cwe: 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
    impact: 'Session hijacking through client-side script injection (document.cookie exfiltration), Clickjacking via unconstrained framing, and Cross-Site Request Forgery (CSRF).',
    severity: 'MEDIUM',
    pocConceptual: {
      title: 'Safe Cookie Header Inspection',
      description: 'Abstract HTTP response header showing omitted defensive flags.',
      payloadExample: `// HTTP Response issued by vulnerable server:
HTTP/1.1 200 OK
Set-Cookie: connect.sid=s%3A7a9b...; Path=/
X-Powered-By: Express

// Deficiencies:
// 1. Missing 'HttpOnly' -> accessible via client-side JavaScript
// 2. Missing 'Secure' -> sent over cleartext HTTP
// 3. Missing 'SameSite=Strict' -> vulnerable to CSRF requests
// 4. Missing 'Content-Security-Policy' & 'X-Frame-Options'`,
      behaviorNote: 'Defensive compliance check. Analyzes HTTP header contract against ASVS 5.0 baseline.'
    },
    remediation: {
      guidance: 'Deploy helmet() as top-level Express middleware to inject hardened security headers. Configure express-session with secure: true, httpOnly: true, sameSite: \'strict\', and appropriate domain/path constraints.',
      vulnerableCode: `// ❌ Insecure Express configuration
import express from 'express';
import session from 'express-session';

const app = express();

// Vulnerable session setup
app.use(session({
  secret: 'insecure_default_secret',
  resave: false,
  saveUninitialized: true
  // Cookie defaults leave HttpOnly and Secure missing!
}));`,
      remediatedCode: `// ✅ Hardened Express server with Helmet & Secure Cookies
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';

const app = express();

// 1. Enforce comprehensive security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. Hardened session configuration
app.use(session({
  name: '__Host-session', // Prefixed cookie enforces HTTPS & path root
  secret: process.env.SESSION_SECRET || 'strong_random_entropy_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,        // Mitigates XSS cookie exfiltration
    secure: true,          // Enforces HTTPS transport only
    sameSite: 'strict',    // Mitigates Cross-Site Request Forgery
    maxAge: 3600000        // 1-hour expiration
  }
}));`,
      ecosystemPackages: [
        { name: 'helmet', npmInstall: 'npm install helmet', role: 'Configures 15 standard defensive HTTP headers including CSP, HSTS, and X-Content-Type-Options' },
        { name: 'express-session', npmInstall: 'npm install express-session', role: 'Server-side session management middleware with configurable cookie security' },
        { name: 'csurf / csrf-csrf', npmInstall: 'npm install csrf-csrf', role: 'Modern stateless CSRF protection middleware for Express applications' }
      ]
    }
  },
  {
    id: 'NODE-PRESET-07',
    scenarioName: 'OWASP NodeGoat / Node.js Core — Insecure Deserialization & Dynamic Eval Execution',
    framework: 'Node.js Core',
    vulnerabilityName: 'Insecure Dynamic Evaluation (eval / Function / vm2 escape)',
    description: 'The application executes dynamic code strings composed from untrusted input using eval(), new Function(), or unhardened sandbox packages (vm2 / node:vm). Node\'s native vm module does not provide a secure sandbox boundary for untrusted code execution.',
    rootCause: 'Dynamic evaluation of user-controlled code within the V8 runtime context, providing access to Process and host system capabilities.',
    owaspId: 'A08:2025 - Software and Data Integrity Failures',
    asvsId: 'V5.5.1 (Prohibit Dynamic Code Execution on Untrusted Input)',
    cwe: 'CWE-502: Deserialization of Untrusted Data / CWE-95: Eval Injection',
    impact: 'Complete host compromise, arbitrary Remote Code Execution (RCE), reverse shell spawn, host file system reading and tampering.',
    severity: 'CRITICAL',
    pocConceptual: {
      title: 'Safe Host Namespace Traversal Expression',
      description: 'Abstract verification showing how dynamic code accesses Node process primitives.',
      payloadExample: `// Conceptual string passed to dynamic calculator/template engine:
"this.constructor.constructor('return process.env')()"

// Evaluation inside unhardened eval/vm context:
// Accesses global Function constructor -> accesses process object
// -> returns all server environment variables and secrets!`,
      behaviorNote: 'Defensive verification demonstration. Illustrates V8 constructor hopping without destructive OS payload.'
    },
    remediation: {
      guidance: 'Eliminate eval() and new Function() calls entirely. For mathematical expression parsing, use mathjs with limited scope or jsep. If dynamic scripting is required, run it inside isolated-vm with strict memory limits and zero process bindings.',
      vulnerableCode: `// ❌ Vulnerable dynamic evaluation
import express from 'express';
const app = express();
app.use(express.json());

app.post('/api/calculate', (req, res) => {
  const { formula } = req.body;
  // Extreme Danger: eval grants direct execution within Node host process!
  const result = eval(formula);
  res.json({ result });
});`,
      remediatedCode: `// ✅ Remediated using isolated-vm with zero-privilege sandbox
import express from 'express';
import ivm from 'isolated-vm';

const app = express();
app.use(express.json());

// Initialize isolated V8 isolate with tight resource limits
const isolate = new ivm.Isolate({ memoryLimit: 16 /* 16 MB max */ });

app.post('/api/calculate', async (req, res) => {
  const { formula } = req.body;

  if (typeof formula !== 'string' || formula.length > 100) {
    return res.status(400).json({ error: 'Invalid formula string' });
  }

  try {
    const context = await isolate.createContext();
    const jail = context.global;
    await jail.set('global', jail.derefInto());

    // Execute script strictly isolated from Node process or require()
    const script = await isolate.compileScript(\`'use strict'; (\${formula})\`);
    const result = await script.run(context, { timeout: 100 }); // 100ms execution cap

    res.json({ result: Number(result) });
  } catch (err) {
    res.status(400).json({ error: 'Computation failed or execution timed out' });
  }
});`,
      ecosystemPackages: [
        { name: 'isolated-vm', npmInstall: 'npm install isolated-vm', role: 'True V8 isolate sandboxing with zero access to Node process, filesystem, or require' },
        { name: 'jsep', npmInstall: 'npm install jsep', role: 'JavaScript Expression Parser producing an AST without evaluating unsafe dynamic code' },
        { name: 'eslint-plugin-security', npmInstall: 'npm install eslint-plugin-security', role: 'Static analysis linter flagging dangerous eval and child_process usage' }
      ]
    }
  }
];

export function auditCustomNodeCode(code: string, framework: string): NodeAuditAnalysis {
  const trimmed = code.trim();
  const lower = trimmed.toLowerCase();

  // Rule 1: Prototype Pollution Check
  if (lower.includes('__proto__') || lower.includes('prototype') || lower.includes('object.assign') || lower.includes('merge(')) {
    return {
      id: `CUSTOM-${Date.now()}-PROTO`,
      scenarioName: `Custom ${framework} — Prototype Pollution Analysis`,
      framework: (framework as any) || 'Express',
      vulnerabilityName: 'Prototype Pollution (V8 Prototype Chain Manipulation)',
      description: 'Static pattern matching detected unconstrained property assignment or merge operations referencing Object prototype attributes (__proto__ / prototype) within the Node.js V8 runtime.',
      rootCause: 'Object properties are dynamically traversed or assigned without checking if the property key belongs to the prototype chain (e.g. __proto__, constructor, prototype).',
      owaspId: 'A03:2025 - Injection & Memory Safety',
      asvsId: 'V5.1.4 (Prohibit Object Prototype Manipulation)',
      cwe: 'CWE-1321: Improperly Controlled Modification of Object Prototype Attributes',
      impact: 'Global object property tampering, privilege escalation, bypass of validation checks, and potential Remote Code Execution (RCE).',
      severity: 'CRITICAL',
      pocConceptual: {
        title: 'Safe Prototype Property Modification Check',
        description: 'Verify if Object prototype lookup is modified by unconstrained property assignment.',
        payloadExample: `// Test input:
{ "__proto__": { "injectedProperty": true } }

// Verification assertion:
// ({}).injectedProperty === true`,
        behaviorNote: 'Defensive validation check. Confirms V8 runtime prototype pollution exposure.'
      },
      remediation: {
        guidance: 'Enforce strict schema validation with Ajv or Zod. Reject payloads containing __proto__ or constructor keys. Use Object.create(null) for unconstrained key-value maps.',
        vulnerableCode: trimmed,
        remediatedCode: `// Remediated with schema validation & prototype rejection
import Ajv from 'ajv';
const ajv = new Ajv({ removeAdditional: 'all' });
// Define explicit schema and strip additional unknown properties
const validate = ajv.compile({ type: 'object', additionalProperties: false });`,
        ecosystemPackages: [
          { name: 'ajv', npmInstall: 'npm install ajv', role: 'JSON Schema validator enforcing strict property allowlists' },
          { name: 'zod', npmInstall: 'npm install zod', role: 'TypeScript schema validator stripping unknown prototype keys' }
        ]
      }
    };
  }

  // Rule 2: SSRF Outbound HTTP Check
  if (lower.includes('axios') || lower.includes('fetch(') || lower.includes('http.get') || lower.includes('got(') || lower.includes('request(')) {
    return {
      id: `CUSTOM-${Date.now()}-SSRF`,
      scenarioName: `Custom ${framework} — Outbound Request SSRF Analysis`,
      framework: (framework as any) || 'Node.js Core',
      vulnerabilityName: 'Server-Side Request Forgery (SSRF) via Outbound HTTP Client',
      description: 'The code snippet initiates outbound network requests using an HTTP client (axios, fetch, got) with dynamic parameters, potentially allowing attackers to traverse internal network perimeters.',
      rootCause: 'Target URLs are queried directly without pre-flight DNS resolution and subnet allowlist validation against RFC 1918 private subnets and link-local metadata addresses.',
      owaspId: 'A01:2025 - Broken Access Control & SSRF',
      asvsId: 'V12.6.1 (Mitigate Server-Side Request Forgery)',
      cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
      impact: 'Exfiltration of Cloud Metadata (AWS IMDSv1/v2 credentials at 169.254.169.254), internal service port probing, and private microservice communication.',
      severity: 'CRITICAL',
      pocConceptual: {
        title: 'Safe Internal Network Probe Scenario',
        description: 'Demonstrating outbound connection to loopback/metadata without boundary filtering.',
        payloadExample: `// Target candidate:
"http://169.254.169.254/latest/meta-data/"
// Or internal microservice:
"http://10.0.1.4:8080/internal-admin"`,
        behaviorNote: 'Defensive conceptual check. Demonstrates SSRF risk without real exfiltration.'
      },
      remediation: {
        guidance: 'Validate target URL scheme (HTTP/HTTPS only). Resolve DNS and verify that IP addresses do not fall within private/loopback CIDRs before issuing requests. Prohibit automatic redirects.',
        vulnerableCode: trimmed,
        remediatedCode: `// Remediated outbound client with DNS guard
import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

async function verifySafeUrl(urlStr) {
  const u = new URL(urlStr);
  const { address } = await dns.lookup(u.hostname);
  const parsedIp = ipaddr.parse(address);
  if (['loopback', 'private', 'linkLocal'].includes(parsedIp.range())) {
    throw new Error('SSRF Guard: Blocked internal address');
  }
  return u.href;
}`,
        ecosystemPackages: [
          { name: 'ipaddr.js', npmInstall: 'npm install ipaddr.js', role: 'IP parsing and CIDR range classification' },
          { name: 'ssrf-req-filter', npmInstall: 'npm install ssrf-req-filter', role: 'Agent wrapper blocking requests to internal RFC 1918 subnets' }
        ]
      }
    };
  }

  // Rule 3: Dynamic Code Execution (eval / Function)
  if (lower.includes('eval(') || lower.includes('new function') || lower.includes('child_process') || lower.includes('exec(')) {
    return {
      id: `CUSTOM-${Date.now()}-EVAL`,
      scenarioName: `Custom ${framework} — Dynamic Execution Analysis`,
      framework: (framework as any) || 'Node.js Core',
      vulnerabilityName: 'Dangerous Dynamic Code Execution (eval / Function Injection)',
      description: 'The snippet utilizes dynamic JavaScript evaluation primitives or OS process spawning on runtime data, posing severe risks of code execution within the Node.js runtime.',
      rootCause: 'Dynamic evaluation of user-controlled code strings directly in the V8 process space or unhardened subshell execution.',
      owaspId: 'A08:2025 - Software and Data Integrity Failures',
      asvsId: 'V5.5.1 (Prohibit Dynamic Code Execution on Untrusted Input)',
      cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
      impact: 'Arbitrary Remote Code Execution (RCE) on the host server, process takeover, and secret credential theft.',
      severity: 'CRITICAL',
      pocConceptual: {
        title: 'Safe Dynamic Execution Demonstration',
        description: 'Demonstrating execution of arbitrary runtime statements via eval.',
        payloadExample: `// Dynamic payload string:
"process.version" // Evaluates directly in Node host context`,
        behaviorNote: 'Defensive analysis only. Shows access to host process namespace.'
      },
      remediation: {
        guidance: 'Eliminate eval() completely. Use static AST expression parsers (jsep) or true V8 isolate sandboxing (isolated-vm) with memory and execution timeouts.',
        vulnerableCode: trimmed,
        remediatedCode: `// Remediated with isolated-vm
import ivm from 'isolated-vm';
const isolate = new ivm.Isolate({ memoryLimit: 16 });
const context = await isolate.createContext();
// Script is executed strictly isolated from Node process APIs`,
        ecosystemPackages: [
          { name: 'isolated-vm', npmInstall: 'npm install isolated-vm', role: 'True V8 isolate sandboxing with zero access to Node process or filesystem' },
          { name: 'jsep', npmInstall: 'npm install jsep', role: 'JavaScript Expression Parser producing an AST without evaluation' }
        ]
      }
    };
  }

  // Rule 4: Database / NoSQL Injection
  if (lower.includes('findone(') || lower.includes('find(') || lower.includes('query(') || lower.includes('select ') || lower.includes('where ')) {
    return {
      id: `CUSTOM-${Date.now()}-INJ`,
      scenarioName: `Custom ${framework} — Database Query Safety Analysis`,
      framework: (framework as any) || 'Mongoose',
      vulnerabilityName: 'Query Parameter / NoSQL Operator Injection Vulnerability',
      description: 'The code passes request data into database queries without explicit field sanitization or parameterization, presenting potential SQL or NoSQL operator injection vectors.',
      rootCause: 'Direct query interpolation or passing raw request bodies containing query selectors ($ne, $gt, $regex) into database drivers.',
      owaspId: 'A03:2025 - Injection & Memory Safety',
      asvsId: 'V5.3.4 (Prevent Database Query Selector & NoSQL Injection)',
      cwe: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
      impact: 'Authentication bypass, unauthorized data reading, collection dumping, and database integrity compromise.',
      severity: 'HIGH',
      pocConceptual: {
        title: 'Safe Query Selector Demonstration',
        description: 'Demonstrating BSON query operator evaluation bypassing equality checks.',
        payloadExample: `// Query input with operator:
{ "password": { "$ne": null } }`,
        behaviorNote: 'Defensive representation. Evaluates query selector handling.'
      },
      remediation: {
        guidance: 'Use mongo-sanitize or parameterized queries. Validate that all user inputs are strict primitive strings using Zod or express-validator.',
        vulnerableCode: trimmed,
        remediatedCode: `// Remediated with strict primitive validation and mongo-sanitize
import mongoSanitize from 'mongo-sanitize';
import { z } from 'zod';

const cleanInput = mongoSanitize(req.body);
const schema = z.object({ id: z.string().alphanumeric() });
const validated = schema.parse(cleanInput);`,
        ecosystemPackages: [
          { name: 'mongo-sanitize', npmInstall: 'npm install mongo-sanitize', role: 'Strips keys beginning with $ to prevent MongoDB operator injection' },
          { name: 'zod', npmInstall: 'npm install zod', role: 'Type-safe schema validation enforcing primitive strings' }
        ]
      }
    };
  }

  // Default: General Defensive Architecture Review
  return {
    id: `CUSTOM-${Date.now()}-ARCH`,
    scenarioName: `Custom ${framework} — Defensive Posture & Hardening Audit`,
    framework: (framework as any) || 'Express',
    vulnerabilityName: 'Missing Defensive Architecture Baselines & Input Constraints',
    description: 'The inspected Node.js module lacks standard defensive hardening controls, such as centralized error-handling boundaries, input schema constraints, rate limiting, and defensive header declarations.',
    rootCause: 'Omission of defense-in-depth middleware and unvalidated request parameter consumption in the application pipeline.',
    owaspId: 'A05:2025 - Security Misconfiguration',
    asvsId: 'V1.1.1 (Verify Application Architecture & Defense-in-Depth)',
    cwe: 'CWE-16: Configuration',
    impact: 'Increased attack surface, information leakage through verbose error messages, and susceptibility to automated abuse.',
    severity: 'MEDIUM',
    pocConceptual: {
      title: 'Safe Architecture Baseline Inspection',
      description: 'Reviewing absence of defensive middleware and schema guards.',
      payloadExample: `// Request lacking defensive headers & validation boundaries
GET /api/resource HTTP/1.1
// Response: Lacks CSP, HSTS, and emits detailed error stack traces`,
      behaviorNote: 'Defensive architectural verification.'
    },
    remediation: {
      guidance: 'Deploy helmet for standard defensive HTTP headers, enforce rate-limiting via express-rate-limit, and validate all inputs with Zod schemas.',
      vulnerableCode: trimmed,
      remediatedCode: `// Hardened Node.js architectural baseline
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(express.json({ limit: '100kb' }));`,
      ecosystemPackages: [
        { name: 'helmet', npmInstall: 'npm install helmet', role: 'Sets 15 defensive HTTP headers including CSP, HSTS, and X-Content-Type-Options' },
        { name: 'express-rate-limit', npmInstall: 'npm install express-rate-limit', role: 'Rate-limiting middleware mitigating automated brute-force and DoS' },
        { name: 'zod', npmInstall: 'npm install zod', role: 'Schema validation for request payloads and configuration' }
      ]
    }
  };
}

export function formatNodeAuditToMarkdown(audit: NodeAuditAnalysis): string {
  return `# Node.js Security Audit Report
**Scenario:** ${audit.scenarioName}
**Framework:** ${audit.framework}
**Timestamp:** ${new Date().toISOString()}

---

## 🔍 Vulnerability Identification & Mapping
* **Name & Description:** **${audit.vulnerabilityName}**
  ${audit.description}
* **Root Cause (Node.js Runtime):** ${audit.rootCause}
* **Framework Mapping:**
  - **OWASP Top 10 ID:** \`${audit.owaspId}\`
  - **ASVS Requirement ID:** \`${audit.asvsId}\`
  - **CWE:** \`${audit.cwe}\`

---

## ⚠️ Risk Assessment
* **Impact:** ${audit.impact}
* **Severity:** **${audit.severity}**

---

## 💻 Proof of Concept (Conceptual)
> **Safety Boundary Notice:** ${audit.pocConceptual.behaviorNote}

### ${audit.pocConceptual.title}
${audit.pocConceptual.description}

\`\`\`http
${audit.pocConceptual.payloadExample}
\`\`\`

---

## 🛡️ Remediation & Secure Coding
### Node.js Controls
${audit.remediation.guidance}

#### Vulnerable Code
\`\`\`typescript
${audit.remediation.vulnerableCode}
\`\`\`

#### Remediated Code (Hardened)
\`\`\`typescript
${audit.remediation.remediatedCode}
\`\`\`

### Ecosystem Solutions
${audit.remediation.ecosystemPackages.map(pkg => `- **\`${pkg.name}\`**: ${pkg.role}\n  \`${pkg.npmInstall}\``).join('\n\n')}
`;
}
