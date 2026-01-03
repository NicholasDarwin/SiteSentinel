/**
 * WHOIS Domain Information Check
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const axios = require('axios');
const { calculateCategoryScore } = require('../utils/score-calculator.util');

const execPromise = promisify(exec);

class WhoisCheck {
  /**
   * RDAP bootstrap URLs for different TLDs
   */
  getRdapUrl(domain) {
    const tld = domain.split('.').pop().toLowerCase();
    
    // RDAP servers for common TLDs
    const rdapServers = {
      'com': 'https://rdap.verisign.com/com/v1/domain/',
      'net': 'https://rdap.verisign.com/net/v1/domain/',
      'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
      'io': 'https://rdap.nic.io/domain/',
      'co': 'https://rdap.nic.co/domain/',
      'me': 'https://rdap.nic.me/domain/',
      'info': 'https://rdap.afilias.net/rdap/info/domain/',
      'biz': 'https://rdap.afilias.net/rdap/biz/domain/',
      'us': 'https://rdap.nic.us/domain/',
      'uk': 'https://rdap.nominet.uk/uk/domain/',
      'de': 'https://rdap.denic.de/domain/',
      'eu': 'https://rdap.eurid.eu/domain/',
      'au': 'https://rdap.auda.org.au/domain/',
      'ca': 'https://rdap.ca.fury.ca/rdap/domain/'
    };
    
    return rdapServers[tld] || null;
  }

  /**
   * Fetch WHOIS data via RDAP (modern REST-based protocol)
   */
  async fetchRdapData(domain) {
    const rdapBaseUrl = this.getRdapUrl(domain);
    
    if (!rdapBaseUrl) {
      // Try IANA bootstrap for unknown TLDs
      try {
        const bootstrapResp = await axios.get('https://data.iana.org/rdap/dns.json', { timeout: 5000 });
        const services = bootstrapResp.data?.services || [];
        const tld = domain.split('.').pop().toLowerCase();
        
        for (const service of services) {
          if (service[0]?.includes(tld)) {
            const rdapUrl = service[1]?.[0];
            if (rdapUrl) {
              const resp = await axios.get(`${rdapUrl}domain/${domain}`, { timeout: 10000 });
              return this.parseRdapResponse(resp.data);
            }
          }
        }
      } catch (e) {
        // Bootstrap lookup failed
      }
      return null;
    }
    
    try {
      const response = await axios.get(`${rdapBaseUrl}${domain}`, {
        timeout: 10000,
        headers: {
          'Accept': 'application/rdap+json, application/json'
        }
      });
      
      return this.parseRdapResponse(response.data);
    } catch (error) {
      if (error.response?.status === 429) {
        return { rateLimited: true, error: 'RDAP rate limit exceeded - try again later' };
      }
      if (error.response?.status === 404) {
        return { notFound: true, error: 'Domain not found in RDAP registry' };
      }
      return null;
    }
  }

  /**
   * Parse RDAP JSON response into structured data
   */
  parseRdapResponse(rdapData) {
    if (!rdapData) return null;
    
    const data = {
      registrar: null,
      creationDate: null,
      expirationDate: null,
      updatedDate: null,
      nameServers: [],
      registrantOrg: null,
      dnssec: null,
      status: [],
      source: 'RDAP'
    };
    
    // Extract events (dates)
    if (rdapData.events) {
      for (const event of rdapData.events) {
        if (event.eventAction === 'registration') {
          data.creationDate = event.eventDate;
        } else if (event.eventAction === 'expiration') {
          data.expirationDate = event.eventDate;
        } else if (event.eventAction === 'last changed' || event.eventAction === 'last update of RDAP database') {
          data.updatedDate = event.eventDate;
        }
      }
    }
    
    // Extract registrar from entities
    if (rdapData.entities) {
      for (const entity of rdapData.entities) {
        if (entity.roles?.includes('registrar')) {
          data.registrar = entity.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 
                          entity.publicIds?.[0]?.identifier ||
                          entity.handle;
        }
        if (entity.roles?.includes('registrant')) {
          data.registrantOrg = entity.vcardArray?.[1]?.find(v => v[0] === 'org')?.[3] ||
                               entity.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3];
        }
      }
    }
    
    // Extract nameservers
    if (rdapData.nameservers) {
      data.nameServers = rdapData.nameservers.map(ns => ns.ldhName?.toLowerCase()).filter(Boolean);
    }
    
    // Extract status
    if (rdapData.status) {
      data.status = rdapData.status;
    }
    
    // DNSSEC
    if (rdapData.secureDNS) {
      data.dnssec = rdapData.secureDNS.delegationSigned ? 'signed' : 'unsigned';
    }
    
    return data;
  }

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
      status: [],
      source: 'WHOIS'
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
    let whoisData = null;
    let dataSource = 'none';
    let lookupError = null;

    try {
      // Extract domain from URL
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // First, try RDAP (modern, more reliable)
      try {
        whoisData = await this.fetchRdapData(domain);
        if (whoisData) {
          if (whoisData.rateLimited) {
            lookupError = whoisData.error;
            whoisData = null;
          } else if (whoisData.notFound) {
            lookupError = whoisData.error;
            whoisData = null;
          } else {
            dataSource = 'RDAP';
          }
        }
      } catch (rdapError) {
        // RDAP failed, try WHOIS fallback
      }

      // Fallback to traditional WHOIS via system commands (Windows)
      if (!whoisData) {
        try {
          // Try PowerShell Resolve-DnsName for basic info
          let whoisText = '';
          try {
            const { stdout } = await execPromise(`powershell -Command "Resolve-DnsName -Name ${domain} -Type ANY | Select-Object -First 5 | Format-List"`, {
              timeout: 10000
            });
            whoisText += stdout;
          } catch (dnsError) {
            // DNS lookup failed, continue
          }

          // Try nslookup as additional source
          try {
            const { stdout } = await execPromise(`nslookup -type=any ${domain}`, {
              timeout: 10000
            });
            whoisText += '\n' + stdout;
          } catch (nslookupError) {
            // nslookup failed, continue
          }

          if (whoisText.trim()) {
            whoisData = this.parseWhoisData(whoisText);
            dataSource = 'DNS lookup';
          }
        } catch (error) {
          if (!lookupError) {
            lookupError = error.message;
          }
        }
      }

      // 1. Domain Registration Status with data source
      checks.push({
        name: 'Domain Registration',
        status: 'info',
        description: `Domain: ${domain}`,
        severity: 'low',
        explanation: dataSource !== 'none' 
          ? `Data retrieved via ${dataSource}`
          : lookupError 
            ? `Lookup unavailable: ${lookupError}`
            : 'Domain registration information'
      });

      // Handle case where we couldn't get any data
      if (!whoisData || (!whoisData.registrar && !whoisData.creationDate && !whoisData.nameServers?.length)) {
        checks.push({
          name: 'WHOIS Data Availability',
          status: 'warn',
          description: lookupError 
            ? `WHOIS/RDAP lookup failed: ${lookupError}`
            : 'WHOIS data not available for this domain',
          severity: 'medium',
          explanation: 'Some registrars restrict WHOIS data access, or the domain may use privacy protection services. This does not indicate a problem with the domain itself.'
        });
        
        // Still return with checks we have
        const score = calculateCategoryScore(checks);
        return {
          category: 'WHOIS & Domain Info',
          icon: 'file-text',
          score: score,
          status: score === null ? 'unavailable' : 'available',
          checks
        };
      }

      // 2. Registrar Information
      if (whoisData.registrar) {
        checks.push({
          name: 'Registrar',
          status: 'pass',
          description: `Registered with: ${whoisData.registrar}`,
          severity: 'low',
          explanation: 'The registrar is the company that manages the domain registration.'
        });
      } else {
        checks.push({
          name: 'Registrar',
          status: 'info',
          description: 'Registrar information not available (may be protected)',
          severity: 'low',
          explanation: 'Registrar info may be hidden by privacy protection services.'
        });
      }

      // 3. Domain Age
      const domainAge = this.getDomainAge(whoisData.creationDate);
      if (domainAge !== null) {
        const years = Math.floor(domainAge / 365);
        const months = Math.floor((domainAge % 365) / 30);
        const ageStr = years > 0 ? `${years} year${years !== 1 ? 's' : ''}${months > 0 ? `, ${months} month${months !== 1 ? 's' : ''}` : ''}` : `${domainAge} days`;
        const status = domainAge > 365 ? 'pass' : domainAge > 30 ? 'warn' : 'fail';
        checks.push({
          name: 'Domain Age',
          status: status,
          description: `Domain is ${ageStr} old (created: ${new Date(whoisData.creationDate).toLocaleDateString()})`,
          severity: 'medium',
          explanation: 'Older domains are generally more trustworthy. Very new domains (< 30 days) may warrant caution.'
        });
      } else {
        checks.push({
          name: 'Domain Age',
          status: 'info',
          description: 'Creation date not available',
          severity: 'low',
          explanation: 'Domain age could not be determined from available data.'
        });
      }

      // 4. Expiration Date
      const daysUntilExpiration = this.getDaysUntilExpiration(whoisData.expirationDate);
      if (daysUntilExpiration !== null) {
        const status = daysUntilExpiration > 90 ? 'pass' : daysUntilExpiration > 30 ? 'warn' : 'fail';
        checks.push({
          name: 'Domain Expiration',
          status: status,
          description: `Expires: ${new Date(whoisData.expirationDate).toLocaleDateString()} (${daysUntilExpiration} days)`,
          severity: daysUntilExpiration < 30 ? 'high' : 'medium',
          explanation: 'Domains near expiration may indicate abandoned or suspicious sites.'
        });
      } else {
        checks.push({
          name: 'Domain Expiration',
          status: 'info',
          description: 'Expiration date not available',
          severity: 'low',
          explanation: 'Expiration date could not be determined from available data.'
        });
      }

      // 5. Last Updated
      if (whoisData.updatedDate) {
        checks.push({
          name: 'Last Updated',
          status: 'info',
          description: `Last modified: ${new Date(whoisData.updatedDate).toLocaleDateString()}`,
          severity: 'low',
          explanation: 'Shows when the domain registration was last updated.'
        });
      }

      // 6. Name Servers
      if (whoisData.nameServers && whoisData.nameServers.length > 0) {
        // Identify known infrastructure providers
        const knownProviders = {
          'google': ['google.com', 'googledomains.com'],
          'cloudflare': ['cloudflare.com', 'ns.cloudflare.com'],
          'aws': ['awsdns', 'amazonaws.com'],
          'azure': ['azure-dns', 'microsoft.com'],
          'godaddy': ['domaincontrol.com', 'godaddy.com'],
          'namecheap': ['registrar-servers.com', 'namecheap.com']
        };
        
        let provider = null;
        for (const [name, patterns] of Object.entries(knownProviders)) {
          if (whoisData.nameServers.some(ns => patterns.some(p => ns.includes(p)))) {
            provider = name.charAt(0).toUpperCase() + name.slice(1);
            break;
          }
        }
        
        checks.push({
          name: 'Name Servers',
          status: 'pass',
          description: provider 
            ? `${whoisData.nameServers.length} name server(s) via ${provider}`
            : `${whoisData.nameServers.length} name server(s): ${whoisData.nameServers.slice(0, 2).join(', ')}${whoisData.nameServers.length > 2 ? '...' : ''}`,
          severity: 'low',
          explanation: 'Name servers handle DNS resolution for the domain.'
        });
      } else {
        checks.push({
          name: 'Name Servers',
          status: 'info',
          description: 'Name server information not available',
          severity: 'low',
          explanation: 'Name server information could not be retrieved.'
        });
      }

      // 7. DNSSEC
      if (whoisData.dnssec) {
        const isDnssecEnabled = whoisData.dnssec.toLowerCase().includes('signed') || 
                               whoisData.dnssec.toLowerCase().includes('yes');
        checks.push({
          name: 'DNSSEC',
          status: isDnssecEnabled ? 'pass' : 'info',
          description: isDnssecEnabled ? 'DNSSEC is enabled' : `DNSSEC: ${whoisData.dnssec}`,
          severity: 'medium',
          explanation: 'DNSSEC adds cryptographic signatures to DNS records to prevent spoofing.'
        });
      } else {
        checks.push({
          name: 'DNSSEC',
          status: 'info',
          description: 'DNSSEC status unknown',
          severity: 'low',
          explanation: 'DNSSEC status could not be determined.'
        });
      }

      // 8. Domain Status
      if (whoisData.status && whoisData.status.length > 0) {
        const hasLocked = whoisData.status.some(s => s.toLowerCase().includes('lock'));
        checks.push({
          name: 'Domain Status',
          status: hasLocked ? 'pass' : 'info',
          description: hasLocked 
            ? 'Domain is locked (protected from unauthorized transfers)'
            : `Status: ${whoisData.status[0]}${whoisData.status.length > 1 ? ` (+${whoisData.status.length - 1} more)` : ''}`,
          severity: 'low',
          explanation: 'Locked domains are protected against unauthorized changes or transfers.'
        });
      }

      // 9. Registrant Organization
      if (whoisData.registrantOrg) {
        checks.push({
          name: 'Registrant',
          status: 'info',
          description: `Organization: ${whoisData.registrantOrg}`,
          severity: 'low',
          explanation: 'The organization that owns the domain registration.'
        });
      }

    } catch (error) {
      checks.push({
        name: 'WHOIS Analysis Error',
        status: 'error',
        description: 'WHOIS analysis unavailable',
        severity: 'critical',
        explanation: `An error occurred: ${error.message}. This category will not contribute to the overall score.`
      });
    }

    const score = calculateCategoryScore(checks);
    
    return {
      category: 'WHOIS & Domain Info',
      icon: 'file-text',
      score: score,
      status: score === null ? 'unavailable' : 'available',
      checks
    };
  }
}

module.exports = WhoisCheck;
