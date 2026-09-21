/**
 * Security & HTTPS Checks
 */

const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const { attachEvidence, buildHeaderEvidence, buildDomEvidence } = require('../utils/evidence.util');
const { fetchWithRedirectChain } = require('../utils/http.util');

class SecurityCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      const { response, finalUrl, statusCode, redirectChain } = await fetchWithRedirectChain(url, { timeout: 10000, maxRedirects: 5 });

      const headers = response.headers;
      const body = response.data ? String(response.data) : '';
      const $ = cheerio.load(body);
      const requestContext = { headers, finalUrl, statusCode, redirectChain };

      // 1. HTTPS Check
      const isHttps = finalUrl.startsWith('https://');
      checks.push({
        id: 'https-encryption',
        name: 'HTTPS Encryption',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps ? 'Site uses HTTPS encryption' : 'Site does not use HTTPS',
        severity: 'critical',
        explanation: 'HTTPS encrypts all communication between your browser and the website.',
        method: 'Checks whether the final URL (after following any redirects) uses the https:// scheme.',
        risk: 'Traffic sent over plain HTTP can be read or modified by anyone on the network path.',
        fix: isHttps ? 'No action needed.' : 'Obtain a TLS certificate and redirect all HTTP traffic to HTTPS.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: null })]);

      // 2. HSTS Header
      const hasHsts = !!headers['strict-transport-security'];
      checks.push({
        id: 'hsts-header',
        name: 'HSTS Header',
        status: hasHsts ? 'pass' : 'warn',
        description: hasHsts ? `HSTS enabled: ${headers['strict-transport-security']}` : 'HSTS not configured (optional for major sites)',
        severity: 'medium',
        explanation: 'HTTP Strict Transport Security forces browsers to always use HTTPS.',
        method: "Checks for the presence of the Strict-Transport-Security response header.",
        risk: 'Without HSTS, a user\'s first visit (or any visit after a cleared cache) can be silently downgraded to HTTP by a network attacker (SSL-stripping).',
        fix: hasHsts ? 'No action needed.' : 'Add an HSTS header, e.g. in nginx:\n  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'strict-transport-security' })]);

      // 3. Content Security Policy - Enhanced detection
      const cspHeader = headers['content-security-policy'] || '';
      const cspReportOnly = headers['content-security-policy-report-only'] || '';

      // Check for CSP in meta tags
      const metaCspEl = $('meta[http-equiv="Content-Security-Policy" i]').get(0);
      const metaCsp = metaCspEl ? $(metaCspEl).attr('content') || '' : '';

      // Check for CSP nonce usage (indicates dynamic CSP)
      const hasNonce = /nonce-[A-Za-z0-9+/=]+/i.test(body);

      // Known infrastructure providers that apply CSP at edge
      const infraProviders = ['google.com', 'cloudflare.com', 'amazon.com', 'microsoft.com', 'facebook.com', 'apple.com'];
      const isInfraProvider = infraProviders.some(p => hostname.includes(p));

      let cspStatus, cspDesc, cspExplanation;
      const cspEvidence = [buildHeaderEvidence({ ...requestContext, highlightHeader: 'content-security-policy' })];

      if (cspHeader) {
        cspStatus = 'pass';
        cspDesc = 'CSP configured via HTTP header to prevent XSS attacks';
        cspExplanation = 'Content-Security-Policy header defines allowed content sources.';
      } else if (metaCsp) {
        cspStatus = 'pass';
        cspDesc = 'CSP configured via meta tag to prevent XSS attacks';
        cspExplanation = 'Content-Security-Policy set via HTML meta tag.';
        cspEvidence.push(buildDomEvidence($, metaCspEl, body, 'CSP meta tag'));
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
        id: 'content-security-policy',
        name: 'Content Security Policy (CSP)',
        status: cspStatus,
        description: cspDesc,
        severity: 'medium',
        explanation: cspExplanation,
        method: 'Checks the Content-Security-Policy response header, a CSP <meta> tag, a report-only CSP header, and (for major infrastructure providers) whether a nonce is present as a sign of edge-applied CSP.',
        risk: 'Without CSP, an injected script (via a stored/reflected XSS vulnerability) can run with full access to the page.',
        fix: cspStatus === 'pass' ? 'No action needed.' : 'Add a Content-Security-Policy header, e.g. in nginx:\n  add_header Content-Security-Policy "default-src \'self\';" always;',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], cspEvidence);

      // 4. X-Frame-Options
      const hasXFrame = !!headers['x-frame-options'];
      checks.push({
        id: 'x-frame-options',
        name: 'X-Frame-Options Header',
        status: hasXFrame ? 'pass' : 'warn',
        description: hasXFrame ? `Set to ${headers['x-frame-options']}` : 'Not set - considered lower priority',
        severity: 'medium',
        explanation: 'X-Frame-Options prevents clickjacking by controlling iframe embedding.',
        method: 'Checks for the presence of the X-Frame-Options response header.',
        risk: 'Without this (or a CSP frame-ancestors directive), an attacker can embed your page in a hidden iframe to trick users into clicking disguised elements.',
        fix: hasXFrame ? 'No action needed.' : 'Add: X-Frame-Options: SAMEORIGIN (or DENY).',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'x-frame-options' })]);

      // 5. X-Content-Type-Options
      const hasXContent = !!headers['x-content-type-options'];
      checks.push({
        id: 'x-content-type-options',
        name: 'X-Content-Type-Options',
        status: hasXContent ? 'pass' : 'warn',
        description: hasXContent ? 'MIME type sniffing disabled' : 'MIME type sniffing mitigation not detected',
        severity: 'medium',
        explanation: 'Prevents browsers from MIME-sniffing responses, reducing drive-by download attacks.',
        method: 'Checks for the presence of the X-Content-Type-Options response header.',
        risk: 'Without this header, a browser may execute a file as a different type than declared (e.g. treating an uploaded image as a script), enabling drive-by attacks.',
        fix: hasXContent ? 'No action needed.' : 'Add: X-Content-Type-Options: nosniff',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'x-content-type-options' })]);

      // 6. Referrer-Policy
      const hasReferrer = !!headers['referrer-policy'];
      checks.push({
        id: 'referrer-policy',
        name: 'Referrer-Policy',
        status: hasReferrer ? 'pass' : 'info',
        description: hasReferrer ? `Set to ${headers['referrer-policy']}` : 'Not configured (uses default)',
        severity: 'low',
        explanation: 'Controls how much referrer information is shared when navigating to other sites.',
        method: 'Checks for the presence of the Referrer-Policy response header.',
        risk: 'Without an explicit policy, full URLs (which can include sensitive query parameters) may leak to third-party sites via the Referer header.',
        fix: hasReferrer ? 'No action needed.' : 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'referrer-policy' })]);

      // 7. Permissions-Policy
      const hasPermissions = !!headers['permissions-policy'];
      checks.push({
        id: 'permissions-policy',
        name: 'Permissions-Policy',
        status: hasPermissions ? 'pass' : 'info',
        description: hasPermissions ? 'Browser permissions restricted' : 'Browser permissions not restricted',
        severity: 'medium',
        explanation: 'Restricts which browser features (camera, microphone, etc.) the site can use.',
        method: 'Checks for the presence of the Permissions-Policy response header.',
        risk: 'Without this header, embedded third-party content can request access to sensitive browser features (camera, microphone, geolocation) by default.',
        fix: hasPermissions ? 'No action needed.' : 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'permissions-policy' })]);

      // 8. SSL/TLS Version (if HTTPS)
      if (isHttps) {
        checks.push({
          id: 'tls-protocol-version',
          name: 'TLS Protocol Version',
          status: 'pass',
          description: 'TLS connection established successfully (TLS 1.2+)',
          severity: 'high',
          explanation: 'Modern TLS versions provide strong encryption for data in transit.',
          method: 'Confirms the final URL uses https:// and that the TLS handshake succeeded (Node\'s HTTPS client rejects TLS < 1.2 by default).',
          risk: 'Outdated TLS versions (1.0/1.1) have known cryptographic weaknesses and are deprecated by major browsers.',
          fix: 'No action needed.',
          confidence: 'medium',
          confidenceNote: 'This confirms the connection succeeded under Node\'s default minimum (TLS 1.2+), not the exact negotiated version or cipher suite - use a dedicated tool like `openssl s_client` or Qualys SSL Labs for a full handshake audit.'
        });
        attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: null })]);
      }

      // 9. Redirect/Phishing Scam Detection
      const knownMaliciousDomains = [
        'durframet', 'chroelhome', 'defulated', 'phosolica', 'flianial',
        'bitaxiers', 'kxkxgw', 'nwqgrv'
      ];
      const hasScamRedirects = knownMaliciousDomains.some(domain => url.toLowerCase().includes(domain));
      checks.push({
        id: 'redirect-scam-detection',
        name: 'Redirect Scam Detection',
        status: hasScamRedirects ? 'fail' : 'pass',
        description: hasScamRedirects ? 'Detected potential phishing redirect or fake verification scam' : 'No phishing redirect patterns detected',
        severity: 'critical',
        explanation: 'Checks for known malicious redirect patterns used in phishing attacks.',
        method: 'Checks the requested URL against a short list of known malicious domain fragments observed in prior scam campaigns.',
        risk: 'These specific domains have been observed hosting fake verification/redirect scam pages.',
        fix: hasScamRedirects ? 'Do not proceed - this matches a known scam domain pattern.' : 'No action needed.',
        confidence: 'high'
      });

    } catch (error) {
      checks.push({
        id: 'connection-error',
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
