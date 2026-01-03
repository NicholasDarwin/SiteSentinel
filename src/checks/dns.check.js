/**
 * DNS & Domain Checks
 */

const dns = require('dns').promises;
const { calculateCategoryScore } = require('../utils/score-calculator.util');

class DnsCheck {
  /**
   * Known IP ranges and providers for attribution
   */
  getProviderInfo(ip) {
    // Known provider IP prefixes (simplified - in production would use IP2ASN or similar)
    const providers = [
      { name: 'Google', prefixes: ['142.250.', '172.217.', '216.58.', '74.125.', '173.194.', '209.85.', '64.233.'], isAnycast: true },
      { name: 'Cloudflare', prefixes: ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '172.64.', '172.65.', '172.66.', '172.67.', '1.1.1.', '1.0.0.'], isAnycast: true },
      { name: 'Amazon AWS', prefixes: ['52.', '54.', '18.', '3.', '13.', '35.', '99.', '15.'], isAnycast: false },
      { name: 'Microsoft Azure', prefixes: ['20.', '40.', '52.', '104.40.', '104.42.', '104.43.', '13.'], isAnycast: false },
      { name: 'Fastly', prefixes: ['151.101.', '199.232.'], isAnycast: true },
      { name: 'Akamai', prefixes: ['23.', '104.', '184.'], isAnycast: true },
      { name: 'Facebook/Meta', prefixes: ['157.240.', '31.13.', '179.60.'], isAnycast: true },
      { name: 'Apple', prefixes: ['17.'], isAnycast: false },
      { name: 'GitHub', prefixes: ['140.82.', '185.199.'], isAnycast: true },
      { name: 'Vercel', prefixes: ['76.76.21.'], isAnycast: true },
      { name: 'Netlify', prefixes: ['75.2.', '99.83.'], isAnycast: true }
    ];
    
    for (const provider of providers) {
      if (provider.prefixes.some(prefix => ip.startsWith(prefix))) {
        return { name: provider.name, isAnycast: provider.isAnycast };
      }
    }
    
    return null;
  }

  async analyze(url) {
    const hostname = new URL(url).hostname;
    const checks = [];

    try {
      // 1. DNS Resolution with provider attribution
      let addresses = [];
      let providerInfo = null;
      try {
        addresses = await dns.resolve4(hostname);
        
        // Get provider info for the first IP
        if (addresses.length > 0) {
          providerInfo = this.getProviderInfo(addresses[0]);
        }
        
        let description = `Domain resolves to: ${addresses.join(', ')}`;
        if (providerInfo) {
          description += ` (${providerInfo.name}${providerInfo.isAnycast ? ' - Anycast CDN' : ''})`;
        }
        
        checks.push({
          name: 'DNS Resolution',
          status: addresses.length > 0 ? 'pass' : 'fail',
          description: description,
          severity: 'critical',
          explanation: providerInfo?.isAnycast 
            ? `This site uses ${providerInfo.name}'s Anycast network, meaning requests are routed to the nearest server for faster response times.`
            : 'DNS resolution converts domain names to IP addresses that computers can use.',
          details: {
            addresses: addresses,
            provider: providerInfo?.name || 'Unknown',
            isAnycast: providerInfo?.isAnycast || false
          }
        });
      } catch (e) {
        checks.push({
          name: 'DNS Resolution',
          status: 'fail',
          description: `Cannot resolve domain: ${e.message}`,
          severity: 'critical',
          explanation: 'The domain could not be resolved to an IP address. This may indicate the domain does not exist or DNS is misconfigured.'
        });
      }

      // 2. IPv6 Support with provider context
      try {
        const ipv6 = await dns.resolve6(hostname);
        const ipv6Provider = ipv6.length > 0 ? this.getIPv6Provider(ipv6[0]) : null;
        checks.push({
          name: 'IPv6 Support',
          status: ipv6.length > 0 ? 'pass' : 'info',
          description: ipv6.length > 0 
            ? `IPv6 enabled: ${ipv6[0]}${ipv6Provider ? ` (${ipv6Provider})` : ''}`
            : 'IPv6 not configured (not required)',
          severity: 'low',
          explanation: 'IPv6 is the latest Internet Protocol version. Having IPv6 support ensures compatibility with modern networks.'
        });
      } catch (e) {
        checks.push({
          name: 'IPv6 Support',
          status: 'info',
          description: 'IPv6 not available (not required)',
          severity: 'low',
          explanation: 'IPv6 is optional for most websites. Many sites operate fine with IPv4 only.'
        });
      }

      // 3. MX Records (Mail Exchange)
      try {
        const mxRecords = await dns.resolveMx(hostname);
        const mailProvider = mxRecords.length > 0 ? this.getMailProvider(mxRecords[0].exchange) : null;
        checks.push({
          name: 'MX Records (Email)',
          status: mxRecords.length > 0 ? 'pass' : 'info',
          description: mxRecords.length > 0 
            ? `${mxRecords.length} mail server(s)${mailProvider ? ` via ${mailProvider}` : ''}`
            : 'No mail servers configured (site may not use email)',
          severity: 'medium',
          explanation: 'MX records specify which servers handle email for the domain.'
        });
      } catch (e) {
        checks.push({
          name: 'MX Records (Email)',
          status: 'info',
          description: 'No mail servers configured',
          severity: 'medium',
          explanation: 'The domain does not have email servers configured, which is fine for sites that don\'t use email.'
        });
      }

      // 4. SPF Record
      try {
        const txtRecords = await dns.resolveTxt(hostname);
        const spfRecord = txtRecords.find(r => r.join('').startsWith('v=spf1'));
        checks.push({
          name: 'SPF Record (Email Security)',
          status: spfRecord ? 'pass' : 'info',
          description: spfRecord 
            ? 'SPF configured to prevent email spoofing'
            : 'SPF not configured (recommended for domains that send email)',
          severity: 'medium',
          explanation: 'SPF (Sender Policy Framework) helps prevent email spoofing by specifying which servers can send email for this domain.'
        });
      } catch (e) {
        checks.push({
          name: 'SPF Record (Email Security)',
          status: 'info',
          description: 'Unable to check SPF record',
          severity: 'medium',
          explanation: 'SPF record lookup could not be completed.'
        });
      }

      // 5. DMARC Record
      try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
        checks.push({
          name: 'DMARC Record (Email Auth)',
          status: dmarcRecords.length > 0 ? 'pass' : 'info',
          description: dmarcRecords.length > 0 
            ? 'DMARC policy configured'
            : 'DMARC policy not configured (recommended for email security)',
          severity: 'medium',
          explanation: 'DMARC (Domain-based Message Authentication) works with SPF and DKIM to protect against email spoofing.'
        });
      } catch (e) {
        checks.push({
          name: 'DMARC Record (Email Auth)',
          status: 'info',
          description: 'DMARC policy not detected',
          severity: 'medium',
          explanation: 'DMARC is optional but recommended for domains that send email.'
        });
      }

      // 6. Multiple A Records (Load Balancing/Redundancy)
      if (addresses.length > 1) {
        checks.push({
          name: 'DNS Redundancy',
          status: 'pass',
          description: `${addresses.length} IP addresses configured (load balancing/redundancy)`,
          severity: 'low',
          explanation: 'Multiple IP addresses provide redundancy and can improve availability and performance.'
        });
      }

      // 7. CAA Records (Certificate Authority Authorization)
      try {
        const caaRecords = await dns.resolveCaa(hostname);
        checks.push({
          name: 'CAA Records',
          status: caaRecords.length > 0 ? 'pass' : 'info',
          description: caaRecords.length > 0 
            ? `Certificate authority restrictions in place`
            : 'No CAA records (optional security enhancement)',
          severity: 'low',
          explanation: 'CAA records specify which Certificate Authorities can issue SSL certificates for this domain.'
        });
      } catch (e) {
        checks.push({
          name: 'CAA Records',
          status: 'info',
          description: 'CAA records not configured (optional)',
          severity: 'low',
          explanation: 'CAA records are optional but can add an extra layer of certificate issuance control.'
        });
      }

    } catch (error) {
      checks.push({
        name: 'DNS Analysis Error',
        status: 'error',
        description: 'DNS analysis unavailable',
        severity: 'critical',
        explanation: `An error occurred: ${error.message}`
      });
    }

    const score = calculateCategoryScore(checks);
    
    return {
      category: 'DNS & Domain',
      icon: 'globe',
      score: score,
      status: score === null ? 'unavailable' : 'available',
      checks
    };
  }

  /**
   * Get mail provider from MX exchange hostname
   */
  getMailProvider(exchange) {
    const mailProviders = {
      'google': ['google.com', 'googlemail.com', 'aspmx.l.google.com'],
      'Microsoft 365': ['outlook.com', 'microsoft.com', 'protection.outlook.com'],
      'Zoho': ['zoho.com'],
      'ProtonMail': ['protonmail.ch'],
      'Fastmail': ['fastmail.com'],
      'Amazon SES': ['amazonses.com', 'awsapps.com']
    };
    
    const exchangeLower = exchange.toLowerCase();
    for (const [provider, patterns] of Object.entries(mailProviders)) {
      if (patterns.some(p => exchangeLower.includes(p))) {
        return provider;
      }
    }
    return null;
  }

  /**
   * Get IPv6 provider hint
   */
  getIPv6Provider(ipv6) {
    // Common IPv6 prefixes for known providers
    if (ipv6.startsWith('2607:f8b0:')) return 'Google';
    if (ipv6.startsWith('2606:4700:')) return 'Cloudflare';
    if (ipv6.startsWith('2a03:2880:')) return 'Facebook/Meta';
    return null;
  }
}

module.exports = DnsCheck;
