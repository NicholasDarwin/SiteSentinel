/**
 * WHOIS Domain Information Check
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

const execPromise = promisify(exec);

class WhoisCheck {
  /**
   * Parse WHOIS output into structured data
   */
  parseWhoisData(whoisText) {
    const data = {
      registrar: null,
      creationDate: null,
      expirationDate: null,
      updatedDate: null,
      nameServers: [],
      registrantOrg: null,
      dnssec: null,
      status: []
    };

    const lines = whoisText.split('\n');
    
    for (const line of lines) {
      const lower = line.toLowerCase().trim();
      
      // Registrar
      if ((lower.startsWith('registrar:') || lower.includes('registrar name:')) && !data.registrar) {
        data.registrar = line.split(':').slice(1).join(':').trim();
      }
      
      // Creation Date
      if ((lower.startsWith('creation date:') || lower.startsWith('created:') || lower.startsWith('registered on:')) && !data.creationDate) {
        data.creationDate = line.split(':').slice(1).join(':').trim();
      }
      
      // Expiration Date
      if ((lower.startsWith('expir') || lower.startsWith('registry expiry date:')) && !data.expirationDate) {
        data.expirationDate = line.split(':').slice(1).join(':').trim();
      }
      
      // Updated Date
      if ((lower.startsWith('updated date:') || lower.startsWith('last updated:') || lower.startsWith('modified:')) && !data.updatedDate) {
        data.updatedDate = line.split(':').slice(1).join(':').trim();
      }
      
      // Name Servers
      if (lower.startsWith('name server:') || lower.startsWith('nserver:')) {
        const ns = line.split(':').slice(1).join(':').trim().toLowerCase();
        if (ns && !data.nameServers.includes(ns)) {
          data.nameServers.push(ns);
        }
      }
      
      // Registrant Organization
      if ((lower.startsWith('registrant organization:') || lower.startsWith('registrant:')) && !data.registrantOrg) {
        data.registrantOrg = line.split(':').slice(1).join(':').trim();
      }
      
      // DNSSEC
      if (lower.startsWith('dnssec:') && !data.dnssec) {
        data.dnssec = line.split(':').slice(1).join(':').trim();
      }
      
      // Domain Status
      if (lower.startsWith('domain status:') || lower.startsWith('status:')) {
        const status = line.split(':').slice(1).join(':').trim();
        if (status && !data.status.includes(status)) {
          data.status.push(status);
        }
      }
    }
    
    return data;
  }

  /**
   * Calculate days until expiration
   */
  getDaysUntilExpiration(expirationDate) {
    if (!expirationDate) return null;
    
    try {
      const expDate = new Date(expirationDate);
      const now = new Date();
      const diffTime = expDate - now;
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      return diffDays;
    } catch {
      return null;
    }
  }

  /**
   * Calculate domain age in days
   */
  getDomainAge(creationDate) {
    if (!creationDate) return null;
    
    try {
      const createDate = new Date(creationDate);
      const now = new Date();
      const diffTime = now - createDate;
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      return diffDays;
    } catch {
      return null;
    }
  }

  async analyze(url) {
    const checks = [];

    try {
      // Extract domain from URL
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Try to get WHOIS information
      let whoisData;
      let whoisText = '';
      
      try {
        // Try using PowerShell's Resolve-DnsName and whois (if available)
        // Note: Windows doesn't have built-in whois, so we'll try a workaround
        try {
          const { stdout } = await execPromise(`powershell -Command "Resolve-DnsName -Name ${domain} -Type ANY | Select-Object -First 5 | Format-List"`, {
            timeout: 10000
          });
          whoisText += stdout;
        } catch (dnsError) {
          // DNS lookup failed, continue
        }

        // Try nslookup as fallback
        try {
          const { stdout } = await execPromise(`nslookup -type=any ${domain}`, {
            timeout: 10000
          });
          whoisText += '\n' + stdout;
        } catch (nslookupError) {
          // nslookup failed, continue
        }

        whoisData = this.parseWhoisData(whoisText);

      } catch (error) {
        checks.push({
          name: 'WHOIS Lookup',
          status: 'warn',
          description: `WHOIS data unavailable: ${error.message}`,
          severity: 'medium'
        });
        
        whoisData = {};
      }

      // 1. Domain Registration Status
      checks.push({
        name: 'Domain Registration',
        status: 'info',
        description: `Domain: ${domain}`,
        severity: 'low'
      });

      // 2. Registrar Information
      if (whoisData.registrar) {
        checks.push({
          name: 'Registrar',
          status: 'pass',
          description: `Registered with: ${whoisData.registrar}`,
          severity: 'low'
        });
      } else {
        checks.push({
          name: 'Registrar',
          status: 'info',
          description: 'Registrar information not available',
          severity: 'low'
        });
      }

      // 3. Domain Age
      const domainAge = this.getDomainAge(whoisData.creationDate);
      if (domainAge !== null) {
        const years = Math.floor(domainAge / 365);
        const status = domainAge > 365 ? 'pass' : domainAge > 30 ? 'warn' : 'fail';
        checks.push({
          name: 'Domain Age',
          status: status,
          description: whoisData.creationDate ? `Created: ${whoisData.creationDate} (${years} years old)` : `Domain is ${domainAge} days old`,
          severity: 'medium'
        });
      } else {
        checks.push({
          name: 'Domain Age',
          status: 'info',
          description: 'Creation date not available',
          severity: 'low'
        });
      }

      // 4. Expiration Date
      const daysUntilExpiration = this.getDaysUntilExpiration(whoisData.expirationDate);
      if (daysUntilExpiration !== null) {
        const status = daysUntilExpiration > 90 ? 'pass' : daysUntilExpiration > 30 ? 'warn' : 'fail';
        checks.push({
          name: 'Domain Expiration',
          status: status,
          description: whoisData.expirationDate ? `Expires: ${whoisData.expirationDate} (${daysUntilExpiration} days)` : `Domain expires in ${daysUntilExpiration} days`,
          severity: daysUntilExpiration < 30 ? 'high' : 'medium'
        });
      } else {
        checks.push({
          name: 'Domain Expiration',
          status: 'info',
          description: 'Expiration date not available',
          severity: 'low'
        });
      }

      // 5. Last Updated
      if (whoisData.updatedDate) {
        checks.push({
          name: 'Last Updated',
          status: 'info',
          description: `Last modified: ${whoisData.updatedDate}`,
          severity: 'low'
        });
      }

      // 6. Name Servers
      if (whoisData.nameServers && whoisData.nameServers.length > 0) {
        checks.push({
          name: 'Name Servers',
          status: 'pass',
          description: `${whoisData.nameServers.length} name server(s): ${whoisData.nameServers.slice(0, 2).join(', ')}${whoisData.nameServers.length > 2 ? '...' : ''}`,
          severity: 'low'
        });
      } else {
        checks.push({
          name: 'Name Servers',
          status: 'info',
          description: 'Name server information not available',
          severity: 'low'
        });
      }

      // 7. DNSSEC
      if (whoisData.dnssec) {
        const isDnssecEnabled = whoisData.dnssec.toLowerCase().includes('signed') || 
                               whoisData.dnssec.toLowerCase().includes('yes');
        checks.push({
          name: 'DNSSEC',
          status: isDnssecEnabled ? 'pass' : 'warn',
          description: isDnssecEnabled ? 'DNSSEC is enabled' : `DNSSEC: ${whoisData.dnssec}`,
          severity: 'medium'
        });
      } else {
        checks.push({
          name: 'DNSSEC',
          status: 'info',
          description: 'DNSSEC status unknown',
          severity: 'low'
        });
      }

      // 8. Domain Status
      if (whoisData.status && whoisData.status.length > 0) {
        const hasLocked = whoisData.status.some(s => s.toLowerCase().includes('lock'));
        checks.push({
          name: 'Domain Status',
          status: hasLocked ? 'pass' : 'warn',
          description: `Status: ${whoisData.status[0]}${whoisData.status.length > 1 ? ` (+${whoisData.status.length - 1} more)` : ''}`,
          severity: 'low'
        });
      }

      // 9. Registrant Organization
      if (whoisData.registrantOrg) {
        checks.push({
          name: 'Registrant',
          status: 'info',
          description: `Organization: ${whoisData.registrantOrg}`,
          severity: 'low'
        });
      }

    } catch (error) {
      checks.push({
        name: 'WHOIS Analysis Error',
        status: 'error',
        description: `Unable to analyze: ${error.message}`,
        severity: 'critical'
      });
    }

    return {
      category: 'WHOIS & Domain Info',
      icon: 'file-text',
      score: calculateCategoryScore(checks),
      checks
    };
  }
}

module.exports = WhoisCheck;
