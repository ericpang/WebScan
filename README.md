# WebScan — Defensive Web Security Auditing & Compliance Posture

WebScan is a modern, high-performance web security auditing application designed for defensive vulnerability posture management, compliance tracking, and automated reporting against **OWASP Top 10:2025** and **ASVS 5.0** benchmarks.

Styled following Apple Design principles with fluid spring physics, tactile interactions, and a high-contrast dark mode.

---

## Features

- **HTTP Security Headers Audit**: Evaluates `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Node.js Security Auditor (4-Tier Ethical Pentest)**: Specialized defensive vulnerability auditing across Express, Fastify, NestJS, and Mongoose with 4-tier output: 🔍 Vulnerability Identification & Mapping (OWASP Top 10:2025 & ASVS 5.0), ⚠️ Risk Assessment (Event Loop / V8 Heap impact), 💻 Proof of Concept (safe conceptual trigger), and 🛡️ Remediation & Secure Coding (code diffs + npm package recommendations like Helmet, Ajv, and RE2).
- **Defensive Posture Scoring**: Computes a deterministic Security Posture Index (0–100%) and Letter Grade (`A+` to `F`).
- **OWASP Top 10:2025 Compliance Matrix**: Detailed compliance breakdowns across categories A01 through A10 with mitigation advice and CWE cross-references.
- **ASVS 5.0 Verification Explorer**: Baseline requirements for Level 1 (minimum bar) and Level 2 (enterprise defense-in-depth).
- **Zero-Trust SSRF Prevention Guard**: Real-time URL validation blocking private subnets (RFC 1918), loopback (`127.0.0.1`), and cloud metadata (`169.254.169.254`).
- **OWASP Testing Targets**: Direct preset integration with official OWASP vulnerable demo applications including **OWASP Juice Shop** (Node.js/Express/Angular), **OWASP NodeGoat** (Node.js/Express/MongoDB), and **OWASP WebGoat** (Java/Spring) for instant defensive benchmarking and training.
- **Executive PDF Reporting**: High-resolution, multi-page executive security audit reports generated via `pdf-lib`.

---

## Quick Start

### Prerequisites
- Node.js LTS (v20+)
- npm (v10+)

### Automated Start (Windows)
Double-click `start.bat` or run:
```cmd
.\start.bat
```
To stop the application server:
```cmd
.\stop.bat
```

### Manual Installation & Run
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build production bundle
npm run build
```

---

## Technology Stack

- **Frontend**: Vanilla TypeScript / HTML5 / CSS3 (Vite)
- **Styling**: Apple Design System tokens, translucent materials (`backdrop-filter`), spring physics
- **PDF Engine**: `pdf-lib` (client-side and headless generation)
- **Compliance Standards**: OWASP Top 10:2025, OWASP ASVS 5.0 (May 2025)

---

## License

MIT License.
