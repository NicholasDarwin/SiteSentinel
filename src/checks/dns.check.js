/**
 * DNS & Domain Checks
 */

const dns = require('dns').promises;
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class DnsCheck {
  async analyze(url) {
    const hostname = new URL(url).hostname;
    const checks = [];

    try {
      // 1. DNS Resolution
      let addresses = [];
      try {
        addresses = await dns.resolve4(hostname);
        checks.push({
          name: 'DNS Resolution',
          status: addresses.length > 0 ? 'pass' : 'fail',
          description: `Domain resolves to: ${addresses.join(', ')}`,
          severity: 'critical'
        });
      } catch (e) {
        checks.push({
          name: 'DNS Resolution',
          status: 'fail',
          description: `Cannot resolve domain: ${e.message}`,
          severity: 'critical'
        });
      }

      // 2. IPv6 Support
      try {
        const ipv6 = await dns.resolve6(hostname);
        checks.push({
          name: 'IPv6 Support',
          status: ipv6.length > 0 ? 'pass' : 'warn',
          description: ipv6.length > 0 ? `IPv6 enabled: ${ipv6[0]}` : 'IPv6 not configured',
          severity: 'low'
        });
      } catch (e) {
        checks.push({
          name: 'IPv6 Support',
          status: 'info',
          description: 'IPv6 not available',
          severity: 'low'
        });
      }

      // 3. MX Records (Mail Exchange)
      try {
        const mxRecords = await dns.resolveMx(hostname);
        checks.push({
          name: 'MX Records (Email)',
          status: mxRecords.length > 0 ? 'pass' : 'warn',
          description: mxRecords.length > 0 ? `${mxRecords.length} mail server(s) configured` : 'No mail servers configured',
          severity: 'medium'
        });
      } catch (e) {
        checks.push({
          name: 'MX Records (Email)',
          status: 'warn',
          description: 'Unable to verify mail configuration',
          severity: 'medium'
        });
      }

      // 4. SPF Record
      try {
        const txtRecords = await dns.resolveTxt(hostname);
        const spfRecord = txtRecords.find(r => r.join('').startsWith('v=spf1'));
        checks.push({
          name: 'SPF Record (Email Security)',
          status: spfRecord ? 'pass' : 'warn',
          description: spfRecord ? 'SPF configured to prevent email spoofing' : 'SPF not configured',
          severity: 'medium'
        });
      } catch (e) {
        checks.push({
          name: 'SPF Record (Email Security)',
          status: 'warn',
          description: 'Unable to check SPF record',
          severity: 'medium'
        });
      }

      // 5. DMARC Record
      try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
        checks.push({
          name: 'DMARC Record (Email Auth)',
          status: dmarcRecords.length > 0 ? 'pass' : 'warn',
          description: dmarcRecords.length > 0 ? 'DMARC policy configured' : 'DMARC policy not configured',
          severity: 'medium'
        });
      } catch (e) {
        checks.push({
          name: 'DMARC Record (Email Auth)',
          status: 'info',
          description: 'DMARC policy not detected',
          severity: 'medium'
        });
      }

      // 6. DNSSEC
      checks.push({
        name: 'DNSSEC',
        status: 'info',
        description: 'DNSSEC verification not available in this check',
        severity: 'medium'
      });

    } catch (error) {
      checks.push({
        name: 'DNS Analysis Error',
        status: 'error',
        description: `Error: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'DNS & Domain',
      icon: '🌐',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = DnsCheck;
