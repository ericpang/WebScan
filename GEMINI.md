# WebScan — Project Architecture & AI Agent Guidelines

This document defines the architectural standards, code quality conventions, defensive security protocols, and operational boundaries for AI agents and developers working within the **WebScan** workspace.

---

## 1. Project Overview & Scope

- **Project Name**: WebScan
- **Core Mission**: A modern, high-performance web application designed for comprehensive web security auditing, compliance scanning, and defensive vulnerability posture management.
- **Operational Boundaries**:
  - Focus exclusively on defensive security analysis, vulnerability management, security posture reporting, and compliance checks (OWASP Top 10, ASVS).
  - Strictly adhere to safe, authorized auditing standards.
- **Architectural Philosophy**:
  - **Modularity**: Decoupled presentation, API orchestration, and scanning/analysis engines.
  - **Separation of Concerns**: Isolated service layers with deterministic data contracts.
  - **Defensive by Design**: Strict input validation, zero-trust data flow, least-privilege execution, and complete audit logging.

---

## 2. Technology Stack & Runtime Environment

- **Frontend**: Modern Vanilla TypeScript / HTML5 / CSS3 or React/Vite (per application module needs).
- **Styling & Motion**: Fluid physical motion, modern typography, high-contrast dark mode, and tactile interactions aligned with Apple Design principles.
- **Backend / Engine**: Node.js (LTS v20+) / Express or Fastify.
- **Data Persistence**: SQLite / PostgreSQL with parameterized query drivers or typed ORM (Prisma/Drizzle).
- **Environment & Configuration**:
  - All configuration managed via `.env` files loaded strictly through typed environment schemas (e.g., Zod).
  - **Secrets Handling**: Zero tolerance for hardcoded tokens, passwords, or API keys. Always use `.env.example` as a template with sanitized placeholder values.

---

## 3. Build, Execution & Testing Runbooks

### Standard Commands
```bash
# Install dependencies
npm install

# Start local development server
npm run dev

# Lint and static type check
npm run lint
npm run typecheck

# Run test suites
npm test

# Build production bundle
npm run build
```

### Verification Workflow
Before marking any feature or bug fix as complete:
1. **Lint & Format**: Execute `npm run lint` with 0 warnings/errors.
2. **Type Safety**: Execute `npm run typecheck` to ensure strict typing with no implicit `any`.
3. **Automated Testing**: Run unit and integration suites to verify regression-free state.
4. **Clean Builds**: Validate that `npm run build` generates clean distribution bundles.

---

## 4. Code Quality & Engineering Standards

- **Directory Structure**:
  ```text
  WebScan/
  ├── src/
  │   ├── components/      # Reusable UI widgets & design primitives
  │   ├── core/            # Business logic, scanning orchestrators, analyzers
  │   ├── styles/          # Design system tokens, variables, global styles
  │   ├── types/           # Shared TypeScript interfaces & types
  │   └── utils/           # Pure utility functions & validation helpers
  ├── tests/               # Unit, integration, and E2E test suites
  ├── .agents/             # Project-level skills and agent guidelines
  └── package.json
  ```
- **Naming Conventions**:
  - Files: `kebab-case` for general modules (`audit-runner.ts`), `PascalCase` for UI components (`ScanReportCard.tsx`).
  - Classes & Interfaces: `PascalCase` (`VulnerabilityScanner`, `ScanResult`).
  - Functions & Variables: `camelCase` (`runSecurityAudit`, `isScanCompleted`).
  - Constants: `UPPER_SNAKE_CASE` (`DEFAULT_SCAN_TIMEOUT_MS`).
- **Error Handling**:
  - Catch errors explicitly at service boundaries; do not leave empty catch blocks.
  - Deliver sanitized, human-readable error messages to users without leaking stack traces or internal server internals.
  - Log diagnostic details securely to server-side logs.
- **Documentation Integrity**:
  - Preserve all existing file header comments, architectural docstrings, and license blocks.
  - Document public interfaces with concise JSDoc / TSDoc annotations.

---

## 5. Defensive Security & Compliance (OWASP Aligned)

- **Input Validation & Sanitization**:
  - Validate all incoming user inputs (URLs, scan parameters, header tokens) against strict allowlists and schema validators before processing.
  - Prevent Server-Side Request Forgery (SSRF) by validating target schemes (rejecting internal/private IP ranges like `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, AWS metadata `169.254.169.254`).
- **Injection Prevention**:
  - SQL / NoSQL: Use parameterized queries or ORM abstractions exclusively. Never concatenate raw strings into queries.
  - XSS Prevention: Context-aware HTML escaping, Content Security Policy (CSP), and avoiding unsafe inner HTML rendering.
- **Authentication & Authorization**:
  - Enforce least-privilege access across all endpoints.
  - Secure session storage using `HttpOnly`, `SameSite=Strict`, `Secure` cookies.
- **Dependency Hygiene**:
  - Regularly run `npm audit` and address moderate-to-critical vulnerabilities.
  - Lock package versions with `package-lock.json`.

---

## 6. Design & User Experience Principles

- **Aesthetics & Motion**:
  - Incorporate the principles from the installed `.agents/skills/apple-design` skill: tactile feedback, spring curves, depth with translucent materials, and thoughtful typography.
  - Curated color palettes with rich contrast and cohesive dark mode aesthetics.
- **Accessibility & Responsiveness**:
  - Adhere to WCAG 2.1 AA standards (color contrast ratios, keyboard accessibility, ARIA labels).
  - Fluid, responsive layouts adapting seamlessly from mobile to wide desktop viewports.
- **Semantic HTML**: Use native semantic landmarks (`<header>`, `<main>`, `<section>`, `<article>`, `<footer>`).

---

## 7. Agent Operational Boundaries & Safety

- **Safety Prohibitions**:
  - **No Offensive Exploitation**: Do not generate weaponized exploit code, attack payloads, malicious bypass vectors, or unauthorized execution scripts.
  - **No Unsafe Execution**: Do not run arbitrary untrusted external commands or disable safety barriers.
- **Verification Rule**:
  - Always verify modified files and test functionality before confirming completion to the user.
- **Skill Usage**:
  - Leverage `.agents/skills/apple-design` when designing and refining the user interface and interactions.
  - Leverage `.agents/skills/owasp-security` for defensive security reviews, vulnerability remediation, and verification against OWASP ASVS standards.
  - Leverage `.agents/skills/pdf` for structured PDF executive audit reports and documentation.

---

## 8. Audit Scope: Implemented & Tested vs. Out-of-Scope Capabilities

### What Is Implemented & Audited (Defensive Testing & Compliance)
- **HTTP Security Headers Evaluation**:
  - `Content-Security-Policy` (CSP): Validates directive configurations (script-src, object-src, frame-ancestors, unsafe-inline flags).
  - `Strict-Transport-Security` (HSTS): Validates HTTPS enforcement, max-age duration, includeSubDomains, and preload status.
  - `X-Frame-Options`: Checks for clickjacking / UI-redressing mitigation (`DENY`, `SAMEORIGIN`).
  - `X-Content-Type-Options`: Confirms MIME-sniffing prevention (`nosniff`).
  - `Referrer-Policy`: Verifies leakage prevention on cross-origin requests.
  - `Permissions-Policy`: Confirms restriction of browser hardware sensors and APIs.
- **Transport Layer & Protocol Checks**:
  - Validates TLS enforcement and flags insecure cleartext HTTP configurations.
- **Zero-Trust SSRF Prevention Guard**:
  - Validates incoming URLs against private IPv4 subnets (RFC 1918), loopback (`127.0.0.1`), link-local/cloud metadata (`169.254.169.254`), and non-HTTP schemes.
- **OWASP Top 10:2025 Compliance Mapping**:
  - Evaluates posture against the 10 defensive categories (A01 to A10) with CWE mappings and remediation code diffs.
- **ASVS 5.0 Verification Explorer**:
  - Assesses compliance against Level 1 (minimum security baseline) and Level 2 (recommended enterprise defense-in-depth) criteria.
- **Executive Reporting & Export**:
  - Automated PDF report generation (via `pdf-lib`) and Markdown/JSON export capabilities.

### What Is NOT Tested / Out of Scope (Offensive Penetration Testing)
- **Active Exploit Injection**:
  - Does NOT inject or execute active exploit payloads (e.g., active SQL injections, reflective/DOM XSS payloads, OS command injections, LDAP/XML injections).
- **Authentication Bypass & Brute-Forcing**:
  - Does NOT perform automated credential stuffing, password dictionary attacks, rate-limit bypassing, or session fixation/hijacking exploits.
- **Network & Port Exploitation**:
  - Does NOT perform port scanning, network mapping, banner grabbing beyond HTTP, or service-level protocol exploitation.
- **Business Logic & Workflow Flaws**:
  - Does NOT test complex multi-step application logic, authorization tampering, or payment workflow flaws requiring authenticated session state.
- **Client-Side Dynamic Execution**:
  - Does NOT execute browser-level JavaScript fuzzing or client-side sandbox escapes.
