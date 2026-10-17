import './styles/index.css';
import { TARGET_PRESETS } from './core/presets';
import { runSecurityAudit } from './core/scanner';
import { OWASP_TOP_10_2025 } from './core/owasp-data';
import { ASVS_5_REQUIREMENTS } from './core/asvs-data';
import { validateScanTargetUrl } from './utils/ssrf-validator';
import { generateExecutivePdfReport } from './utils/pdf-generator';
import { ScanResult, Severity } from './types/security';

// State Management
let currentResult: ScanResult = TARGET_PRESETS[0].result;
let currentTab: 'overview' | 'headers' | 'owasp' | 'asvs' = 'overview';
let activeSeverityFilter: Severity | 'ALL' = 'ALL';
let isAuditing = false;

// DOM Mount Point
const app = document.getElementById('app')!;

function renderApp() {
  app.innerHTML = `
    <!-- Top Glass Header -->
    <header class="app-header">
      <div class="header-content">
        <div class="brand-wrapper">
          <div class="brand-shield">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
          </div>
          <div class="brand-text">
            <h1>WebScan <span class="brand-badge">OWASP Defensive</span></h1>
            <div class="brand-subtext">Security Auditing & ASVS 5.0 Compliance Posture</div>
          </div>
        </div>

        <!-- Segmented Tab Navigation -->
        <nav class="nav-segmented" role="tablist">
          <button class="nav-item ${currentTab === 'overview' ? 'active' : ''}" data-tab="overview">
            <span>🛡️ Posture Overview</span>
          </button>
          <button class="nav-item ${currentTab === 'headers' ? 'active' : ''}" data-tab="headers">
            <span>🔍 Security Headers</span>
          </button>
          <button class="nav-item ${currentTab === 'owasp' ? 'active' : ''}" data-tab="owasp">
            <span>📋 OWASP Top 10</span>
          </button>
          <button class="nav-item ${currentTab === 'asvs' ? 'active' : ''}" data-tab="asvs">
            <span>📜 ASVS 5.0 Explorer</span>
          </button>
        </nav>

        <!-- Actions -->
        <div class="header-actions">
          <button id="btn-export-json" class="btn">
            <span>⬇️ JSON</span>
          </button>
          <button id="btn-download-pdf-header" class="btn" style="background: rgba(59, 130, 246, 0.15); border-color: rgba(59, 130, 246, 0.35); color: #93c5fd;">
            <span>📑 PDF Report</span>
          </button>
          <button id="btn-view-report" class="btn btn-primary">
            <span>📄 Executive View</span>
          </button>
        </div>
      </div>
    </header>

    <!-- Main Workspace Container -->
    <main class="app-container">
      <!-- Target URL & Audit Hero Bar -->
      <section class="glass-panel hero-card">
        <div class="hero-glow"></div>
        <div class="scan-progress-bar" id="scan-progress-bar"></div>

        <h2 class="hero-title">Defensive <span>Security Posture</span> Auditing</h2>
        <p class="hero-desc">
          Safe, zero-trust web application audit suite. Evaluates security headers, transport encryption, and compliance against OWASP Top 10:2025 and ASVS 5.0.
        </p>

        <!-- Scan Input Box -->
        <div class="scan-input-box">
          <div class="url-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          </div>
          <input
            id="scan-url-input"
            class="scan-input"
            type="text"
            placeholder="Enter target URL (e.g. https://api.secureguard.cloud)"
            value="${currentResult.targetUrl}"
          />
          <div id="ssrf-indicator" class="ssrf-guard-indicator">
            <span>🛡️ SSRF Guard Active</span>
          </div>
          <button id="btn-run-audit" class="btn btn-primary" ${isAuditing ? 'disabled' : ''}>
            ${isAuditing ? '<span>Auditing...</span>' : '<span>Run Security Audit</span>'}
          </button>
        </div>

        <div id="ssrf-error-message" style="display: none; margin-top: 10px; color: #f87171; font-size: 0.85rem; font-weight: 500;"></div>

        <!-- Presets Bar -->
        <div class="presets-group">
          <span class="presets-label">Preset Targets:</span>
          ${TARGET_PRESETS.map(preset => `
            <button class="preset-chip ${preset.url === currentResult.targetUrl ? 'active' : ''}" data-preset-id="${preset.id}">
              <span>${preset.name}</span>
              <small style="opacity: 0.7;">(${preset.badge})</small>
            </button>
          `).join('')}
        </div>
      </section>

      <!-- Dynamic Tab Views -->
      <section id="tab-content-area">
        ${renderCurrentTab()}
      </section>
    </main>

    <!-- Executive Report Modal -->
    <div id="report-modal" class="modal-overlay">
      <div class="glass-panel modal-card">
        <div class="modal-header">
          <h3 style="font-size: 1.25rem; font-weight: 700;">Executive Security Audit Summary</h3>
          <button id="btn-close-modal" class="btn" style="padding: 4px 10px;">✕ Close</button>
        </div>
        <div class="modal-body">
          <pre id="modal-markdown-content" style="font-family: var(--font-family-mono); font-size: 0.82rem; color: #cbd5e1; background: #07090e; padding: 18px; border-radius: var(--radius-md); white-space: pre-wrap;"></pre>
        </div>
        <div style="margin-top: 18px; display: flex; justify-content: flex-end; gap: 10px; flex-wrap: wrap;">
          <button id="btn-copy-report" class="btn">📋 Copy Markdown</button>
          <button id="btn-download-pdf-modal" class="btn" style="background: rgba(59, 130, 246, 0.2); border-color: rgba(59, 130, 246, 0.4); color: #93c5fd;">📑 Export PDF Report</button>
          <button id="btn-download-report" class="btn btn-primary">⬇️ Download Markdown</button>
        </div>
      </div>
    </div>
  `;

  attachEventListeners();
}

function renderCurrentTab() {
  switch (currentTab) {
    case 'overview':
      return renderOverviewTab();
    case 'headers':
      return renderHeadersTab();
    case 'owasp':
      return renderOwaspTab();
    case 'asvs':
      return renderAsvsTab();
  }
}

function renderOverviewTab() {
  const strokeOffset = 565 - (565 * currentResult.score) / 100;
  let strokeColor = '#10b981';
  if (currentResult.score < 60) strokeColor = '#ef4444';
  else if (currentResult.score < 80) strokeColor = '#f59e0b';
  else if (currentResult.score < 90) strokeColor = '#3b82f6';

  const filteredFindings = activeSeverityFilter === 'ALL'
    ? currentResult.findings
    : currentResult.findings.filter(f => f.severity === activeSeverityFilter);

  return `
    <div class="dashboard-grid">
      <!-- Left Column: Score Radial & Key Metrics -->
      <div class="glass-panel score-card">
        <div class="score-title">Security Posture Index</div>
        <div class="score-sub">Aggregated defensive assurance score</div>

        <div class="gauge-wrapper">
          <svg class="gauge-svg" viewBox="0 0 200 200">
            <circle class="gauge-track" cx="100" cy="100" r="90" />
            <circle class="gauge-value" cx="100" cy="100" r="90"
              style="stroke: ${strokeColor}; stroke-dashoffset: ${strokeOffset};" />
          </svg>
          <div class="gauge-center">
            <div class="grade-badge" style="color: ${strokeColor};">${currentResult.grade}</div>
            <div class="score-number">${currentResult.score}% Rating</div>
          </div>
        </div>

        <div class="metric-pills-row">
          <div class="metric-pill-item">
            <span class="metric-pill-val" style="color: #f87171;">${currentResult.summary.critical}</span>
            <span class="metric-pill-lbl">Critical</span>
          </div>
          <div class="metric-pill-item">
            <span class="metric-pill-val" style="color: #fb923c;">${currentResult.summary.high}</span>
            <span class="metric-pill-lbl">High</span>
          </div>
          <div class="metric-pill-item">
            <span class="metric-pill-val" style="color: #fbbf24;">${currentResult.summary.medium}</span>
            <span class="metric-pill-lbl">Medium</span>
          </div>
          <div class="metric-pill-item">
            <span class="metric-pill-val" style="color: #34d399;">${currentResult.summary.totalPassed}</span>
            <span class="metric-pill-lbl">Passed</span>
          </div>
        </div>
      </div>

      <!-- Right Column: Compliance Summary & Findings -->
      <div class="overview-panel">
        <div class="stats-card-row">
          <div class="stat-card">
            <div class="stat-card-title">ASVS 5.0 (L1 Bar)</div>
            <div class="stat-card-value" style="color: #34d399;">${currentResult.asvsLevel1PassRate}%</div>
            <div class="stat-card-footer">Minimum security baseline</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-title">ASVS 5.0 (L2 Enterprise)</div>
            <div class="stat-card-value" style="color: #60a5fa;">${currentResult.asvsLevel2PassRate}%</div>
            <div class="stat-card-footer">Recommended defense-in-depth</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-title">Headers Evaluated</div>
            <div class="stat-card-value">${currentResult.headerAudits.length}</div>
            <div class="stat-card-footer">${currentResult.headerAudits.filter(h => h.status === 'passed').length} Passed</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-title">Last Audit Timestamp</div>
            <div class="stat-card-value" style="font-size: 1.15rem; font-family: var(--font-family-mono); padding-top: 8px;">
              ${new Date(currentResult.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </div>
            <div class="stat-card-footer">Deterministic verification</div>
          </div>
        </div>

        <!-- Findings Accordion -->
        <div class="glass-panel findings-container">
          <div class="panel-header">
            <div>
              <h3 class="panel-title">Audited Security Findings (${currentResult.findings.length})</h3>
              <p style="font-size: 0.8rem; color: var(--text-tertiary);">Prioritized by severity with concrete remediation code diffs</p>
            </div>
            <div class="filter-pills">
              ${(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as (Severity | 'ALL')[]).map(sev => `
                <button class="filter-pill ${activeSeverityFilter === sev ? 'active' : ''}" data-filter="${sev}">
                  ${sev}
                </button>
              `).join('')}
            </div>
          </div>

          <div class="findings-list">
            ${filteredFindings.length === 0 ? `
              <div style="padding: 24px; text-align: center; color: var(--text-tertiary); font-size: 0.9rem;">
                ✅ No findings match this filter. The target satisfies these defense requirements.
              </div>
            ` : filteredFindings.map(finding => `
              <div class="finding-item" id="finding-${finding.id}">
                <div class="finding-header" data-toggle-finding="${finding.id}">
                  <div class="finding-meta">
                    <span class="severity-tag ${finding.severity}">${finding.severity}</span>
                    <span class="finding-title-text">${finding.title}</span>
                    <span class="finding-category-label">${finding.owaspCategory}</span>
                  </div>
                  <span class="finding-chevron">▼</span>
                </div>
                <div class="finding-details">
                  <div class="detail-section">
                    <div class="detail-label">Vulnerability Analysis</div>
                    <div class="detail-body">${finding.description}</div>
                  </div>
                  <div class="detail-section">
                    <div class="detail-label">Exploit Impact (Blast Radius)</div>
                    <div class="detail-body">${finding.impact}</div>
                  </div>
                  <div class="detail-section">
                    <div class="detail-label">Remediation Guidance</div>
                    <div class="detail-body">${finding.remediation}</div>
                  </div>
                  ${finding.codeSnippet ? `
                    <div class="detail-section">
                      <div class="detail-label">Remediation Code Diff</div>
                      <div class="code-diff-box">
                        <div class="diff-title">Configuration / Source Code Diff</div>
                        <div class="diff-content">
                          <div class="diff-vulnerable">- ${finding.codeSnippet.vulnerable.split('\n').join('\n- ')}</div>
                          <div class="diff-remediated">+ ${finding.codeSnippet.remediated.split('\n').join('\n+ ')}</div>
                        </div>
                      </div>
                    </div>
                  ` : ''}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderHeadersTab() {
  return `
    <div class="glass-panel" style="padding: 28px;">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">HTTP Security Headers Evaluation</h3>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">
            Auditing defense-in-depth response headers for modern browser security standards.
          </p>
        </div>
      </div>

      <div style="overflow-x: auto;">
        <table class="header-table">
          <thead>
            <tr>
              <th>Security Header</th>
              <th>Status</th>
              <th>Current Response Value</th>
              <th>Recommended Configuration</th>
              <th>Description & Mitigation</th>
            </tr>
          </thead>
          <tbody>
            ${currentResult.headerAudits.map(h => `
              <tr>
                <td style="font-weight: 600; color: #ffffff;">${h.header}</td>
                <td>
                  <span class="header-badge ${h.status}">
                    ${h.status === 'passed' ? '✓ Passed' : h.status === 'warning' ? '⚠ Warning' : '✕ Missing'}
                  </span>
                </td>
                <td style="font-family: var(--font-family-mono); font-size: 0.78rem; max-width: 240px; word-break: break-all; color: var(--text-secondary);">
                  ${h.currentValue || '<span style="color: #f87171; font-style: italic;">Not Present</span>'}
                </td>
                <td style="font-family: var(--font-family-mono); font-size: 0.78rem; max-width: 240px; word-break: break-all; color: #34d399;">
                  ${h.recommendedValue}
                </td>
                <td style="color: var(--text-secondary); font-size: 0.82rem; max-width: 300px;">
                  ${h.description}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderOwaspTab() {
  return `
    <div class="glass-panel" style="padding: 28px;">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">OWASP Top 10:2025 Defensive Compliance Matrix</h3>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">
            Verification of application security controls against the newest 2025 OWASP standard.
          </p>
        </div>
      </div>

      <div class="matrix-grid">
        ${OWASP_TOP_10_2025.map((cat, idx) => {
          const comp = currentResult.owaspCompliance[idx] || { score: 85, status: 'compliant' };
          return `
            <div class="matrix-card">
              <div class="matrix-card-header">
                <span class="matrix-id">${cat.id}:2025</span>
                <span style="font-size: 0.82rem; font-weight: 700; color: ${comp.status === 'compliant' ? '#34d399' : comp.status === 'warning' ? '#fbbf24' : '#f87171'};">
                  ${comp.score}% Assurance
                </span>
              </div>
              <div class="matrix-card-title">${cat.name}</div>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">${cat.shortDesc}</p>

              <div class="matrix-progress-bar">
                <div class="matrix-progress-fill" style="width: ${comp.score}%; background: ${comp.status === 'compliant' ? '#10b981' : comp.status === 'warning' ? '#f59e0b' : '#ef4444'};"></div>
              </div>

              <div style="font-size: 0.75rem; color: var(--text-tertiary); margin-top: 4px;">
                <strong>Key Mitigations:</strong>
                <ul style="padding-left: 18px; margin-top: 4px; line-height: 1.45;">
                  ${cat.keyMitigations.map(m => `<li>${m}</li>`).join('')}
                </ul>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function renderAsvsTab() {
  return `
    <div class="glass-panel" style="padding: 28px;">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">OWASP ASVS 5.0 Verification Explorer</h3>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">
            Application Security Verification Standard (ASVS 5.0 - May 2025) baseline checklist.
          </p>
        </div>
      </div>

      <div class="findings-list">
        ${ASVS_5_REQUIREMENTS.map(req => `
          <div class="finding-item open">
            <div class="finding-header" style="cursor: default;">
              <div class="finding-meta">
                <span class="severity-tag ${req.level === 'L1' ? 'LOW' : 'HIGH'}">${req.level}</span>
                <span style="font-family: var(--font-family-mono); font-weight: 700; color: #60a5fa;">${req.id}</span>
                <span class="finding-title-text">${req.title}</span>
                <span class="finding-category-label">${req.chapter}</span>
              </div>
            </div>
            <div class="finding-details" style="display: block;">
              <div class="detail-section">
                <div class="detail-label">Verification Requirement</div>
                <div class="detail-body">${req.description}</div>
              </div>
              <div class="detail-section">
                <div class="detail-label">Auditor Verification Guide</div>
                <div class="detail-body" style="color: #93c5fd;">🔍 ${req.verificationGuide}</div>
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function attachEventListeners() {
  // Navigation Tabs
  document.querySelectorAll('.nav-item').forEach(button => {
    button.addEventListener('click', (e) => {
      const tab = (e.currentTarget as HTMLElement).getAttribute('data-tab') as any;
      if (tab) {
        currentTab = tab;
        renderApp();
      }
    });
  });

  // Target Input & Real-time SSRF Validation
  const scanInput = document.getElementById('scan-url-input') as HTMLInputElement;
  const ssrfIndicator = document.getElementById('ssrf-indicator')!;
  const ssrfErrorMsg = document.getElementById('ssrf-error-message')!;

  scanInput?.addEventListener('input', () => {
    const val = scanInput.value.trim();
    if (!val) {
      ssrfIndicator.className = 'ssrf-guard-indicator';
      ssrfIndicator.innerHTML = '<span>🛡️ SSRF Guard Active</span>';
      ssrfErrorMsg.style.display = 'none';
      return;
    }

    const check = validateScanTargetUrl(val);
    if (!check.isValid && check.isPrivateOrInternal) {
      ssrfIndicator.className = 'ssrf-guard-indicator warning';
      ssrfIndicator.innerHTML = '<span>⚠️ SSRF Blocked</span>';
      ssrfErrorMsg.textContent = check.error || 'Blocked internal / loopback address.';
      ssrfErrorMsg.style.display = 'block';
    } else {
      ssrfIndicator.className = 'ssrf-guard-indicator';
      ssrfIndicator.innerHTML = '<span>🛡️ Safe Target</span>';
      ssrfErrorMsg.style.display = 'none';
    }
  });

  // Run Audit Button
  document.getElementById('btn-run-audit')?.addEventListener('click', async () => {
    const url = scanInput?.value.trim();
    if (!url) return;

    isAuditing = true;
    renderApp();

    const progressBar = document.getElementById('scan-progress-bar');

    try {
      const result = await runSecurityAudit(url, (_, percent) => {
        if (progressBar) progressBar.style.width = `${percent}%`;
      });
      currentResult = result;
    } catch (err: any) {
      alert(`Audit halted: ${err.message}`);
    } finally {
      isAuditing = false;
      renderApp();
    }
  });

  // Preset Chips
  document.querySelectorAll('.preset-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      const id = (e.currentTarget as HTMLElement).getAttribute('data-preset-id');
      const found = TARGET_PRESETS.find(p => p.id === id);
      if (found) {
        currentResult = found.result;
        renderApp();
      }
    });
  });

  // Finding Accordions
  document.querySelectorAll('[data-toggle-finding]').forEach(header => {
    header.addEventListener('click', (e) => {
      const id = (e.currentTarget as HTMLElement).getAttribute('data-toggle-finding');
      const item = document.getElementById(`finding-${id}`);
      item?.classList.toggle('open');
    });
  });

  // Severity Filter Pills
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', (e) => {
      const filter = (e.currentTarget as HTMLElement).getAttribute('data-filter') as any;
      if (filter) {
        activeSeverityFilter = filter;
        renderApp();
      }
    });
  });

  // Modal Controls
  const reportModal = document.getElementById('report-modal')!;
  document.getElementById('btn-view-report')?.addEventListener('click', () => {
    const md = generateMarkdownReport(currentResult);
    document.getElementById('modal-markdown-content')!.textContent = md;
    reportModal.classList.add('open');
  });

  document.getElementById('btn-close-modal')?.addEventListener('click', () => {
    reportModal.classList.remove('open');
  });

  document.getElementById('btn-copy-report')?.addEventListener('click', () => {
    const content = document.getElementById('modal-markdown-content')!.textContent || '';
    navigator.clipboard.writeText(content).then(() => alert('Markdown report copied to clipboard!'));
  });

  // PDF Generation & Download Handler
  const handlePdfDownload = async () => {
    try {
      const pdfBytes = await generateExecutivePdfReport(currentResult);
      const blob = new Blob([pdfBytes as any], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const hostname = new URL(currentResult.targetUrl).hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
      a.download = `WebScan-Executive-Report-${hostname}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Failed to generate PDF: ${err.message}`);
    }
  };

  document.getElementById('btn-download-pdf-header')?.addEventListener('click', handlePdfDownload);
  document.getElementById('btn-download-pdf-modal')?.addEventListener('click', handlePdfDownload);

  document.getElementById('btn-download-report')?.addEventListener('click', () => {
    const content = document.getElementById('modal-markdown-content')!.textContent || '';
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WebScan-Audit-${new URL(currentResult.targetUrl).hostname}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById('btn-export-json')?.addEventListener('click', () => {
    const jsonStr = JSON.stringify(currentResult, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WebScan-Audit-${new URL(currentResult.targetUrl).hostname}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

function generateMarkdownReport(result: ScanResult): string {
  return `# Security Audit & Compliance Assessment Report
Generated by WebScan (OWASP Defensive & ASVS 5.0)

- **Target URL**: ${result.targetUrl}
- **Timestamp**: ${result.timestamp}
- **Security Posture Score**: ${result.score}/100 (Grade: ${result.grade})
- **ASVS Level 1 Pass Rate**: ${result.asvsLevel1PassRate}%
- **ASVS Level 2 Pass Rate**: ${result.asvsLevel2PassRate}%

---

## 1. Executive Summary
- Critical Vulnerabilities: ${result.summary.critical}
- High Severity Issues: ${result.summary.high}
- Medium Severity Issues: ${result.summary.medium}
- Low Severity Issues: ${result.summary.low}
- Passing Verifications: ${result.summary.totalPassed}

---

## 2. Security Findings
${result.findings.map(f => `
### [${f.severity}] ${f.title}
- **OWASP Category**: ${f.owaspCategory}
- **CWE**: ${f.cwe}${f.asvsId ? ` | **ASVS**: ${f.asvsId}` : ''}
- **Analysis**: ${f.description}
- **Impact**: ${f.impact}
- **Remediation**: ${f.remediation}
`).join('\n')}

---

## 3. HTTP Security Headers
| Header | Status | Current Value | Recommended |
|---|---|---|---|
${result.headerAudits.map(h => `| ${h.header} | ${h.status.toUpperCase()} | \`${h.currentValue || 'None'}\` | \`${h.recommendedValue}\` |`).join('\n')}
`;
}

// Initial Boot
renderApp();
