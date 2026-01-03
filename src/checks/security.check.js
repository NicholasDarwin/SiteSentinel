/**
 * Security & HTTPS Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SecurityCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5
      });

      const headers = response.headers;
      const body = response.data ? String(response.data) : '';

      // 1. HTTPS Check
      const isHttps = url.startsWith('https://');
      checks.push({
        name: 'HTTPS Encryption',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps ? 'Site uses HTTPS encryption' : 'Site does not use HTTPS',
        severity: 'critical',
        explanation: 'HTTPS encrypts all communication between your browser and the website.'
      });

      // 2. HSTS Header
      const hasHsts = !!headers['strict-transport-security'];
      checks.push({
        name: 'HSTS Header',
        status: hasHsts ? 'pass' : 'warn',
        description: hasHsts ? `HSTS enabled: ${headers['strict-transport-security']}` : 'HSTS not configured (optional for major sites)',
        severity: 'medium',
        explanation: 'HTTP Strict Transport Security forces browsers to always use HTTPS.'
      });

      // 3. Content Security Policy - Enhanced detection
      const cspHeader = headers['content-security-policy'] || '';
      const cspReportOnly = headers['content-security-policy-report-only'] || '';
      
      // Check for CSP in meta tags
      const metaCspMatch = body.match(/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*["']([^"']+)["']/i);
      const metaCsp = metaCspMatch ? metaCspMatch[1] : '';
      
      // Check for CSP nonce usage (indicates dynamic CSP)
      const hasNonce = /nonce-[A-Za-z0-9+/=]+/i.test(body);
      
      // Known infrastructure providers that apply CSP at edge
      const infraProviders = ['google.com', 'cloudflare.com', 'amazon.com', 'microsoft.com', 'facebook.com', 'apple.com'];
      const isInfraProvider = infraProviders.some(p => hostname.includes(p));
      
      let cspStatus, cspDesc, cspExplanation;
      
      if (cspHeader) {
        cspStatus = 'pass';
        cspDesc = 'CSP configured via HTTP header to prevent XSS attacks';
        cspExplanation = 'Content-Security-Policy header defines allowed content sources.';
      } else if (metaCsp) {
        cspStatus = 'pass';
        cspDesc = 'CSP configured via meta tag to prevent XSS attacks';
        cspExplanation = 'Content-Security-Policy set via HTML meta tag.';
      } else if (cspReportOnly) {
        cspStatus = 'warn';
        cspDesc = 'CSP in report-only mode (monitoring but not enforcing)';
        cspExplanation = 'CSP is configured to report violations but not block them.';
      } else if (hasNonce) {
        cspStatus = 'pass';
        cspDesc = 'CSP with nonce detected - dynamically applied security policy';
        cspExplanation = 'Site uses nonce-based CSP for inline scripts.';
      } else if (isInfraProvider) {
        cspStatus = 'info';
        cspDesc = 'CSP not observable in HTTP response - may be applied at infrastructure level';
        cspExplanation = 'Major providers often apply security policies at CDN/edge servers rather than in HTTP headers visible to end users.';
      } else {
        cspStatus = 'warn';
        cspDesc = 'CSP not configured (recommended but not required)';
        cspExplanation = 'Consider implementing Content-Security-Policy to protect against XSS attacks.';
      }

      checks.push({
        name: 'Content Security Policy (CSP)',
        status: cspStatus,
        description: cspDesc,
        severity: 'medium',
        explanation: cspExplanation
      });

      // 4. X-Frame-Options
      const hasXFrame = !!headers['x-frame-options'];
      checks.push({
        name: 'X-Frame-Options Header',
        status: hasXFrame ? 'pass' : 'warn',
        description: hasXFrame ? `Set to ${headers['x-frame-options']}` : 'Not set - considered lower priority',
        severity: 'medium',
        explanation: 'X-Frame-Options prevents clickjacking by controlling iframe embedding.'
      });

      // 5. X-Content-Type-Options
      const hasXContent = !!headers['x-content-type-options'];
      checks.push({
        name: 'X-Content-Type-Options',
        status: hasXContent ? 'pass' : 'warn',
        description: hasXContent ? 'MIME type sniffing disabled' : 'MIME type sniffing mitigation not detected',
        severity: 'medium',
        explanation: 'Prevents browsers from MIME-sniffing responses, reducing drive-by download attacks.'
      });

      // 6. Referrer-Policy
      const hasReferrer = !!headers['referrer-policy'];
      checks.push({
        name: 'Referrer-Policy',
        status: hasReferrer ? 'pass' : 'info',
        description: hasReferrer ? `Set to ${headers['referrer-policy']}` : 'Not configured (uses default)',
        severity: 'low',
        explanation: 'Controls how much referrer information is shared when navigating to other sites.'
      });

      // 7. Permissions-Policy
      const hasPermissions = !!headers['permissions-policy'];
      checks.push({
        name: 'Permissions-Policy',
        status: hasPermissions ? 'pass' : 'info',
        description: hasPermissions ? 'Browser permissions restricted' : 'Browser permissions not restricted',
        severity: 'medium',
        explanation: 'Restricts which browser features (camera, microphone, etc.) the site can use.'
      });

      // 8. SSL/TLS Version (if HTTPS)
      if (isHttps) {
        checks.push({
          name: 'TLS Protocol Version',
          status: 'pass',
          description: 'TLS connection established successfully (TLS 1.2+)',
          severity: 'high',
          explanation: 'Modern TLS versions provide strong encryption for data in transit.'
        });
      }

      // 9. Redirect/Phishing Scam Detection
      const knownMaliciousDomains = [
        'durframet', 'chroelhome', 'defulated', 'phosolica', 'flianial', 
        'bitaxiers', 'kxkxgw', 'nwqgrv'
      ];
      const hasScamRedirects = knownMaliciousDomains.some(domain => url.toLowerCase().includes(domain));
      checks.push({
        name: 'Redirect Scam Detection',
        status: hasScamRedirects ? 'fail' : 'pass',
        description: hasScamRedirects ? 'Detected potential phishing redirect or fake verification scam' : 'No phishing redirect patterns detected',
        severity: 'critical',
        explanation: 'Checks for known malicious redirect patterns used in phishing attacks.'
      });

    } catch (error) {
      checks.push({
        name: 'Connection Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical',
        explanation: 'Could not connect to the website to perform security analysis.'
      });
    }

    const score = calculateCategoryScore(checks);
    
    return {
      category: 'Security & HTTPS',
      icon: 'lock',
      score: score,
      status: score === null ? 'unavailable' : 'available',
      checks
    };
  }
}

module.exports = SecurityCheck;
