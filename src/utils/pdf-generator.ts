import { PDFDocument, rgb, StandardFonts, PDFPage, PDFFont } from 'pdf-lib';
import { ScanResult } from '../types/security';

export async function generateExecutivePdfReport(result: ScanResult): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();

  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

  // A4 Page dimensions: 595.28 x 841.89 points
  const pageWidth = 595.28;
  const pageHeight = 841.89;
  const margin = 40;
  const contentWidth = pageWidth - (margin * 2);

  let currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
  let y = pageHeight - margin;

  // Helper to check page bounds and auto-paginate
  function checkPageBreak(requiredHeight: number): void {
    if (y - requiredHeight < margin + 40) {
      currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
      y = pageHeight - margin;
      drawHeaderChrome(currentPage, fontRegular, fontBold, pageWidth, pageHeight, margin);
      y -= 30;
    }
  }

  // --- Page 1: Header Banner ---
  currentPage.drawRectangle({
    x: 0,
    y: pageHeight - 90,
    width: pageWidth,
    height: 90,
    color: rgb(0.04, 0.06, 0.11), // Deep navy
  });

  // Top accent line
  currentPage.drawRectangle({
    x: 0,
    y: pageHeight - 4,
    width: pageWidth,
    height: 4,
    color: rgb(0.23, 0.51, 0.96), // Brand blue
  });

  currentPage.drawText('WebScan — Defensive Security Audit', {
    x: margin,
    y: pageHeight - 42,
    size: 20,
    font: fontBold,
    color: rgb(1, 1, 1),
  });

  currentPage.drawText('Executive Compliance & Vulnerability Posture Assessment (OWASP Top 10:2025 & ASVS 5.0)', {
    x: margin,
    y: pageHeight - 65,
    size: 9.5,
    font: fontRegular,
    color: rgb(0.65, 0.75, 0.88),
  });

  y = pageHeight - 115;

  // --- Target & Assessment Metadata Box ---
  currentPage.drawRectangle({
    x: margin,
    y: y - 75,
    width: contentWidth,
    height: 75,
    color: rgb(0.96, 0.97, 0.99),
    borderColor: rgb(0.85, 0.88, 0.92),
    borderWidth: 1,
  });

  // Posture Score Box on the Right
  let gradeColor = rgb(0.06, 0.72, 0.5); // green
  if (result.score < 60) gradeColor = rgb(0.93, 0.27, 0.27);
  else if (result.score < 80) gradeColor = rgb(0.96, 0.62, 0.05);
  else if (result.score < 90) gradeColor = rgb(0.23, 0.51, 0.96);

  currentPage.drawRectangle({
    x: pageWidth - margin - 105,
    y: y - 65,
    width: 95,
    height: 55,
    color: rgb(1, 1, 1),
    borderColor: rgb(0.85, 0.88, 0.92),
    borderWidth: 1,
  });

  currentPage.drawText(result.grade, {
    x: pageWidth - margin - 78,
    y: y - 38,
    size: 26,
    font: fontBold,
    color: gradeColor,
  });

  currentPage.drawText(`Score: ${result.score}%`, {
    x: pageWidth - margin - 85,
    y: y - 55,
    size: 9,
    font: fontBold,
    color: rgb(0.3, 0.35, 0.45),
  });

  // Metadata Text
  currentPage.drawText(`Target URL:`, { x: margin + 14, y: y - 22, size: 9, font: fontBold, color: rgb(0.4, 0.45, 0.55) });
  currentPage.drawText(result.targetUrl, { x: margin + 85, y: y - 22, size: 9, font: fontMono, color: rgb(0.1, 0.15, 0.25) });

  currentPage.drawText(`Audit Date:`, { x: margin + 14, y: y - 40, size: 9, font: fontBold, color: rgb(0.4, 0.45, 0.55) });
  currentPage.drawText(new Date(result.timestamp).toUTCString(), { x: margin + 85, y: y - 40, size: 9, font: fontRegular, color: rgb(0.2, 0.25, 0.35) });

  currentPage.drawText(`Methodology:`, { x: margin + 14, y: y - 58, size: 9, font: fontBold, color: rgb(0.4, 0.45, 0.55) });
  currentPage.drawText(`OWASP Top 10:2025 • ASVS 5.0 (L1/L2) • SSRF Zero-Trust Guard`, { x: margin + 85, y: y - 58, size: 8.5, font: fontRegular, color: rgb(0.2, 0.25, 0.35) });

  y -= 95;

  // --- Section 1: Executive Summary Metrics ---
  currentPage.drawText('1. Executive Vulnerability Summary', {
    x: margin,
    y: y,
    size: 13,
    font: fontBold,
    color: rgb(0.08, 0.12, 0.2),
  });
  y -= 18;

  // Metrics Bar (5 Columns)
  const colWidth = contentWidth / 5;
  const metrics = [
    { label: 'CRITICAL', count: result.summary.critical, color: rgb(0.93, 0.27, 0.27) },
    { label: 'HIGH', count: result.summary.high, color: rgb(0.98, 0.45, 0.1) },
    { label: 'MEDIUM', count: result.summary.medium, color: rgb(0.96, 0.62, 0.05) },
    { label: 'LOW', count: result.summary.low, color: rgb(0.23, 0.51, 0.96) },
    { label: 'VERIFIED PASS', count: result.summary.totalPassed, color: rgb(0.06, 0.72, 0.5) },
  ];

  metrics.forEach((m, idx) => {
    const cardX = margin + (idx * colWidth);
    currentPage.drawRectangle({
      x: cardX + 2,
      y: y - 44,
      width: colWidth - 4,
      height: 44,
      color: rgb(0.97, 0.98, 0.99),
      borderColor: rgb(0.88, 0.9, 0.94),
      borderWidth: 1,
    });

    currentPage.drawText(String(m.count), {
      x: cardX + 10,
      y: y - 24,
      size: 18,
      font: fontBold,
      color: m.color,
    });

    currentPage.drawText(m.label, {
      x: cardX + 10,
      y: y - 38,
      size: 7.5,
      font: fontBold,
      color: rgb(0.45, 0.5, 0.6),
    });
  });

  y -= 65;

  // --- Compliance Rates ---
  currentPage.drawText(`ASVS 5.0 Level 1 Baseline Pass Rate: ${result.asvsLevel1PassRate}%   |   ASVS 5.0 Level 2 Enterprise Pass Rate: ${result.asvsLevel2PassRate}%`, {
    x: margin,
    y: y,
    size: 9,
    font: fontBold,
    color: rgb(0.18, 0.45, 0.8),
  });
  y -= 25;

  // --- Section 2: Detailed Security Findings ---
  currentPage.drawText('2. Detailed Security Findings & Remediation', {
    x: margin,
    y: y,
    size: 13,
    font: fontBold,
    color: rgb(0.08, 0.12, 0.2),
  });
  y -= 18;

  if (result.findings.length === 0) {
    currentPage.drawText('No security vulnerabilities identified. Target endpoint passed all audited defensive checks.', {
      x: margin,
      y: y,
      size: 9,
      font: fontRegular,
      color: rgb(0.1, 0.6, 0.3),
    });
    y -= 25;
  } else {
    for (const finding of result.findings) {
      checkPageBreak(110);

      let sevColor = rgb(0.23, 0.51, 0.96);
      if (finding.severity === 'CRITICAL') sevColor = rgb(0.93, 0.27, 0.27);
      else if (finding.severity === 'HIGH') sevColor = rgb(0.98, 0.45, 0.1);
      else if (finding.severity === 'MEDIUM') sevColor = rgb(0.96, 0.62, 0.05);

      // Severity Tag
      currentPage.drawRectangle({
        x: margin,
        y: y - 14,
        width: 58,
        height: 16,
        color: sevColor,
      });

      currentPage.drawText(finding.severity, {
        x: margin + 6,
        y: y - 10,
        size: 8,
        font: fontBold,
        color: rgb(1, 1, 1),
      });

      // Title
      currentPage.drawText(finding.title, {
        x: margin + 66,
        y: y - 11,
        size: 10,
        font: fontBold,
        color: rgb(0.08, 0.12, 0.2),
      });

      y -= 24;

      // Category & CWE
      currentPage.drawText(`Standard: ${finding.owaspCategory}  |  ${finding.cwe}${finding.asvsId ? `  |  ASVS ${finding.asvsId}` : ''}`, {
        x: margin,
        y: y,
        size: 8,
        font: fontRegular,
        color: rgb(0.4, 0.45, 0.55),
      });
      y -= 14;

      // Analysis / Description
      const descLines = wrapText(finding.description, 95);
      for (const line of descLines) {
        currentPage.drawText(line, {
          x: margin,
          y: y,
          size: 8.5,
          font: fontRegular,
          color: rgb(0.2, 0.25, 0.35),
        });
        y -= 11;
      }

      // Impact
      currentPage.drawText(`Impact: ${finding.impact}`, {
        x: margin,
        y: y,
        size: 8.5,
        font: fontBold,
        color: rgb(0.8, 0.25, 0.2),
      });
      y -= 12;

      // Remediation
      const remLines = wrapText(`Remediation: ${finding.remediation}`, 95);
      for (const line of remLines) {
        currentPage.drawText(line, {
          x: margin,
          y: y,
          size: 8.5,
          font: fontRegular,
          color: rgb(0.1, 0.5, 0.3),
        });
        y -= 11;
      }

      y -= 10;
      currentPage.drawLine({
        start: { x: margin, y: y },
        end: { x: pageWidth - margin, y: y },
        thickness: 0.5,
        color: rgb(0.88, 0.9, 0.94),
      });
      y -= 14;
    }
  }

  // --- Section 3: HTTP Security Headers Evaluation ---
  checkPageBreak(120);
  currentPage.drawText('3. HTTP Security Headers Posture', {
    x: margin,
    y: y,
    size: 13,
    font: fontBold,
    color: rgb(0.08, 0.12, 0.2),
  });
  y -= 18;

  // Header Table
  const tableHeaderY = y;
  currentPage.drawRectangle({
    x: margin,
    y: tableHeaderY - 18,
    width: contentWidth,
    height: 18,
    color: rgb(0.92, 0.94, 0.97),
  });

  currentPage.drawText('Security Header', { x: margin + 8, y: tableHeaderY - 13, size: 8, font: fontBold, color: rgb(0.2, 0.25, 0.35) });
  currentPage.drawText('Status', { x: margin + 170, y: tableHeaderY - 13, size: 8, font: fontBold, color: rgb(0.2, 0.25, 0.35) });
  currentPage.drawText('Observed / Recommended Policy', { x: margin + 240, y: tableHeaderY - 13, size: 8, font: fontBold, color: rgb(0.2, 0.25, 0.35) });

  y -= 22;

  for (const h of result.headerAudits) {
    checkPageBreak(24);

    let statusColor = rgb(0.06, 0.72, 0.5);
    let statusText = 'PASSED';
    if (h.status === 'warning') {
      statusColor = rgb(0.96, 0.62, 0.05);
      statusText = 'WARNING';
    } else if (h.status === 'missing') {
      statusColor = rgb(0.93, 0.27, 0.27);
      statusText = 'MISSING';
    }

    currentPage.drawText(h.header, {
      x: margin + 8,
      y: y - 10,
      size: 8,
      font: fontBold,
      color: rgb(0.15, 0.2, 0.3),
    });

    currentPage.drawText(statusText, {
      x: margin + 170,
      y: y - 10,
      size: 7.5,
      font: fontBold,
      color: statusColor,
    });

    const valDisplay = h.currentValue ? h.currentValue.substring(0, 55) : `Recommended: ${h.recommendedValue.substring(0, 50)}`;
    currentPage.drawText(valDisplay, {
      x: margin + 240,
      y: y - 10,
      size: 7.5,
      font: fontMono,
      color: rgb(0.3, 0.35, 0.45),
    });

    y -= 18;
    currentPage.drawLine({
      start: { x: margin, y: y },
      end: { x: pageWidth - margin, y: y },
      thickness: 0.5,
      color: rgb(0.9, 0.92, 0.95),
    });
  }

  // Draw footer on all pages
  const totalPages = pdfDoc.getPageCount();
  for (let i = 0; i < totalPages; i++) {
    const page = pdfDoc.getPage(i);
    drawFooter(page, fontRegular, i + 1, totalPages, pageWidth, margin);
  }

  return await pdfDoc.save();
}

function drawHeaderChrome(page: PDFPage, fontRegular: PDFFont, fontBold: PDFFont, pageWidth: number, pageHeight: number, margin: number) {
  page.drawText('WebScan Executive Security Audit Report', {
    x: margin,
    y: pageHeight - 25,
    size: 8,
    font: fontBold,
    color: rgb(0.4, 0.45, 0.55),
  });

  page.drawText('CONFIDENTIAL & DEFENSIVE COMPLIANCE', {
    x: pageWidth - margin - 170,
    y: pageHeight - 25,
    size: 7.5,
    font: fontRegular,
    color: rgb(0.6, 0.65, 0.75),
  });

  page.drawLine({
    start: { x: margin, y: pageHeight - 30 },
    end: { x: pageWidth - margin, y: pageHeight - 30 },
    thickness: 0.5,
    color: rgb(0.85, 0.88, 0.92),
  });
}

function drawFooter(page: PDFPage, font: PDFFont, pageNum: number, totalPages: number, pageWidth: number, margin: number) {
  page.drawLine({
    start: { x: margin, y: 35 },
    end: { x: pageWidth - margin, y: 35 },
    thickness: 0.5,
    color: rgb(0.85, 0.88, 0.92),
  });

  page.drawText('WebScan • OWASP Top 10:2025 & ASVS 5.0 Automated Auditing Engine', {
    x: margin,
    y: 22,
    size: 7.5,
    font,
    color: rgb(0.5, 0.55, 0.65),
  });

  page.drawText(`Page ${pageNum} of ${totalPages}`, {
    x: pageWidth - margin - 50,
    y: 22,
    size: 7.5,
    font,
    color: rgb(0.5, 0.55, 0.65),
  });
}

function wrapText(text: string, maxCharsPerLine: number): string[] {
  const words = text.split(' ');
  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    if ((currentLine + ' ' + word).trim().length <= maxCharsPerLine) {
      currentLine = (currentLine + ' ' + word).trim();
    } else {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    }
  }
  if (currentLine) lines.push(currentLine);
  return lines;
}
