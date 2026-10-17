export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecurityFinding {
  id: string;
  title: string;
  severity: Severity;
  owaspCategory: string; // e.g. "A01:2025 - Broken Access Control & SSRF"
  asvsId?: string;       // e.g. "8.3.1"
  cwe: string;           // e.g. "CWE-918"
  description: string;
  impact: string;
  remediation: string;
  codeSnippet?: {
    vulnerable: string;
    remediated: string;
    language: string;
  };
  passed: boolean;
}

export interface HeaderAuditItem {
  header: string;
  status: 'passed' | 'warning' | 'missing';
  currentValue?: string;
  recommendedValue: string;
  importance: 'critical' | 'high' | 'medium';
  description: string;
}

export interface ScanResult {
  targetUrl: string;
  timestamp: string;
  score: number; // 0-100
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    totalPassed: number;
  };
  findings: SecurityFinding[];
  headerAudits: HeaderAuditItem[];
  owaspCompliance: {
    category: string;
    score: number; // 0-100
    status: 'compliant' | 'warning' | 'non-compliant';
  }[];
  asvsLevel1PassRate: number;
  asvsLevel2PassRate: number;
}

export interface NodeAuditAnalysis {
  id: string;
  scenarioName: string;
  framework: 'Express' | 'Fastify' | 'NestJS' | 'Node.js Core' | 'Mongoose' | 'Prisma';
  vulnerabilityName: string;
  description: string;
  rootCause: string;
  owaspId: string;
  asvsId: string;
  cwe: string;
  impact: string;
  severity: Severity;
  pocConceptual: {
    title: string;
    description: string;
    payloadExample: string;
    behaviorNote: string;
  };
  remediation: {
    guidance: string;
    vulnerableCode: string;
    remediatedCode: string;
    ecosystemPackages: {
      name: string;
      npmInstall: string;
      role: string;
    }[];
  };
}

export interface TargetPreset {
  id: string;
  name: string;
  url: string;
  category?: 'owasp' | 'enterprise';
  aliases?: string[];
  badge: string;
  description: string;
  result: ScanResult;
}
