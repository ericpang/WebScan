/**
 * SSRF Prevention Validator
 * Enforces strict input validation per OWASP A01:2025 & ASVS 5.0
 */

export interface SsrfValidationResult {
  isValid: boolean;
  sanitizedUrl?: string;
  error?: string;
  isPrivateOrInternal?: boolean;
}

const PRIVATE_IP_PATTERNS = [
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                     // 127.0.0.0/8 Loopback
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                      // 10.0.0.0/8 Private
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,          // 172.16.0.0/12 Private
  /^192\.168\.\d{1,3}\.\d{1,3}$/,                         // 192.168.0.0/16 Private
  /^169\.254\.\d{1,3}\.\d{1,3}$/,                         // 169.254.0.0/16 Link-Local / Cloud Metadata
  /^0\.0\.0\.0$/,
  /^localhost$/i,
  /^metadata\.google\.internal$/i,
  /^169\.254\.169\.254$/
];

export function validateScanTargetUrl(rawUrl: string): SsrfValidationResult {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return { isValid: false, error: 'Target URL cannot be empty.' };
  }

  // Prepend https:// if protocol omitted for convenience
  let target = trimmed;
  if (!/^https?:\/\//i.test(target)) {
    target = 'https://' + target;
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return { isValid: false, error: 'Malformed URL format. Must be a valid URI.' };
  }

  // Enforce safe scheme
  if (!['http:', 'https:'].includes(parsed.protocol.toLowerCase())) {
    return {
      isValid: false,
      error: `Disallowed protocol scheme "${parsed.protocol}". Only HTTP and HTTPS are permitted for security audits.`
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check against internal / private IP patterns
  for (const pattern of PRIVATE_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      return {
        isValid: false,
        isPrivateOrInternal: true,
        error: `SSRF Guard Blocked: Target "${hostname}" resolves to an internal, loopback, or cloud metadata address (OWASP A01:2025).`
      };
    }
  }

  // Check IPv6 loopback
  if (hostname === '[::1]' || hostname === '::1' || hostname.startsWith('fe80:') || hostname.startsWith('fc00:')) {
    return {
      isValid: false,
      isPrivateOrInternal: true,
      error: 'SSRF Guard Blocked: Target points to private/link-local IPv6 address.'
    };
  }

  // Port checks (only allow standard web ports 80, 443, 8080, 8443, 3000, 5173 for security testing)
  if (parsed.port) {
    const portNum = parseInt(parsed.port, 10);
    const ALLOWED_PORTS = [80, 443, 8000, 8080, 8443, 3000, 5000, 5173];
    if (!ALLOWED_PORTS.includes(portNum)) {
      return {
        isValid: false,
        error: `Restricted destination port ${portNum}. Audits are restricted to standard web service ports.`
      };
    }
  }

  return {
    isValid: true,
    sanitizedUrl: parsed.toString()
  };
}
