/**
 * Safety & Threats Checks
 */

const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class SafetyCheck {
  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;

    try {
      const response = await axios.get(url, { 
        timeout: 15000,
        validateStatus: () => true
      });

      // 1. No Blacklist Indicators (basic)
      checks.push({
        name: 'Malware/Phishing Indicators',
        status: 'info',
        description: 'Full malware detection requires integration with Google Safe Browsing API',
        severity: 'critical'
      });

      // 2. SSL Certificate Validity
      checks.push({
        name: 'SSL Certificate Status',
        status: url.startsWith('https://') ? 'pass' : 'fail',
        description: url.startsWith('https://') ? 'HTTPS connection established' : 'No HTTPS - unencrypted connection',
        severity: 'critical'
      });

      // 3. Suspicious Content Check
      const hasFormWithoutHttps = response.data?.includes('form') && !url.startsWith('https://');
      checks.push({
        name: 'Form Security',
        status: hasFormWithoutHttps ? 'fail' : 'pass',
        description: hasFormWithoutHttps ? 'Forms detected on non-HTTPS page' : 'Forms properly secured or no forms detected',
        severity: 'critical'
      });

      // 4. Outdated Software Detection
      checks.push({
        name: 'Outdated Software Detection',
        status: 'info',
        description: 'Requires deep framework version analysis',
        severity: 'medium'
      });

      // 5. SQL Injection Indicators
      checks.push({
        name: 'SQL Injection Protection',
        status: 'info',
        description: 'Server-side security requires comprehensive penetration testing',
        severity: 'critical'
      });

      // 6. XSS Protection
      checks.push({
        name: 'XSS (Cross-Site Scripting) Protection',
        status: 'info',
        description: 'CSP headers provide XSS protection (see Security section)',
        severity: 'high'
      });

      // 7. Iframe Restrictions
      const iframes = response.data?.match(/<iframe/gi) || [];
      checks.push({
        name: 'Iframe Usage',
        status: iframes.length > 0 ? 'warn' : 'pass',
        description: iframes.length > 0 ? `${iframes.length} iframes detected - verify they're from trusted sources` : 'No iframes detected',
        severity: 'medium'
      });

      // 8. External Script Safety
      const externalScripts = (response.data?.match(/<script[^>]+src=/gi) || []).length;
      checks.push({
        name: 'External Scripts',
        status: externalScripts > 0 ? 'warn' : 'pass',
        description: externalScripts > 0 ? `${externalScripts} external scripts - verify they're from trusted sources` : 'No external scripts',
        severity: 'high'
      });

      // 9. Rate Limiting / Brute Force Protection
      checks.push({
        name: 'Rate Limiting / Bot Protection',
        status: 'info',
        description: 'Bot protection mechanisms vary by platform',
        severity: 'medium'
      });

      // 10. DNS Hijacking Risk
      checks.push({
        name: 'Domain Registrar Status',
        status: 'info',
        description: 'Domain registration status requires WHOIS lookup',
        severity: 'medium'
      });

    } catch (error) {
      checks.push({
        name: 'Safety Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'Safety & Threats',
      icon: '⚠️',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = SafetyCheck;
