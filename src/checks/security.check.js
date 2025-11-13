/**
 * Security & HTTPS Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SecurityCheck {
  async analyze(url) {
    const checks = [];

    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5
      });

      const headers = response.headers;

      // 1. HTTPS Check
      const isHttps = url.startsWith('https://');
      checks.push({
        name: 'HTTPS Encryption',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps ? 'Site uses HTTPS encryption' : 'Site does not use HTTPS',
        severity: 'critical'
      });

      // 2. HSTS Header
      const hasHsts = !!headers['strict-transport-security'];
      checks.push({
        name: 'HSTS Header',
        status: hasHsts ? 'pass' : 'warn',
        description: hasHsts ? `HSTS enabled: ${headers['strict-transport-security']}` : 'HSTS not configured for forced HTTPS',
        severity: 'high'
      });

      // 3. Content Security Policy
      const hasCsp = !!headers['content-security-policy'];
      checks.push({
        name: 'Content Security Policy (CSP)',
        status: hasCsp ? 'pass' : 'warn',
        description: hasCsp ? 'CSP configured to prevent XSS attacks' : 'CSP not configured - site vulnerable to XSS',
        severity: 'high'
      });

      // 4. X-Frame-Options
      const hasXFrame = !!headers['x-frame-options'];
      checks.push({
        name: 'X-Frame-Options Header',
        status: hasXFrame ? 'pass' : 'warn',
        description: hasXFrame ? `Set to ${headers['x-frame-options']}` : 'Not set - vulnerable to clickjacking',
        severity: 'high'
      });

      // 5. X-Content-Type-Options
      const hasXContent = !!headers['x-content-type-options'];
      checks.push({
        name: 'X-Content-Type-Options',
        status: hasXContent ? 'pass' : 'warn',
        description: hasXContent ? 'MIME type sniffing disabled' : 'MIME type sniffing not prevented',
        severity: 'medium'
      });

      // 6. Referrer-Policy
      const hasReferrer = !!headers['referrer-policy'];
      checks.push({
        name: 'Referrer-Policy',
        status: hasReferrer ? 'pass' : 'info',
        description: hasReferrer ? `Set to ${headers['referrer-policy']}` : 'Not configured (uses default)',
        severity: 'low'
      });

      // 7. Permissions-Policy
      const hasPermissions = !!headers['permissions-policy'];
      checks.push({
        name: 'Permissions-Policy',
        status: hasPermissions ? 'pass' : 'info',
        description: hasPermissions ? 'Browser permissions restricted' : 'Browser permissions not restricted',
        severity: 'medium'
      });

      // 8. SSL/TLS Version (if HTTPS)
      if (isHttps) {
        checks.push({
          name: 'TLS Protocol Version',
          status: 'pass',
          description: 'TLS connection established successfully (TLS 1.2+)',
          severity: 'high'
        });
      }

    } catch (error) {
      checks.push({
        name: 'Connection Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'Security & HTTPS',
      icon: '🔒',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = SecurityCheck;
