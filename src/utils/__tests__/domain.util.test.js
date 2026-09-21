const {
  getRegistrableDomain,
  isSameSite,
  isValidHostname,
  classifyDomain
} = require('../domain.util');

describe('getRegistrableDomain', () => {
  test('strips subdomains down to the registrable domain', () => {
    expect(getRegistrableDomain('i5.walmartimages.com')).toBe('walmartimages.com');
    expect(getRegistrableDomain('www.walmart.com')).toBe('walmart.com');
    expect(getRegistrableDomain('sub.example.co.uk')).toBe('example.co.uk');
  });

  test('returns null for bare IPs', () => {
    expect(getRegistrableDomain('192.168.1.1')).toBeNull();
  });
});

describe('isSameSite', () => {
  test('treats www/subdomains of the same registrable domain as the same site', () => {
    expect(isSameSite('www.walmart.com', 'walmart.com')).toBe(true);
    expect(isSameSite('corporate.walmart.com', 'walmart.com')).toBe(true);
    expect(isSameSite('careers.walmart.com', 'walmart.com')).toBe(true);
  });

  test('does not treat a different registrable domain as the same site', () => {
    expect(isSameSite('walmartimages.com', 'walmart.com')).toBe(false);
    expect(isSameSite('evil-walmart-login.com', 'walmart.com')).toBe(false);
  });

  test('handles multi-part TLDs correctly', () => {
    expect(isSameSite('shop.example.co.uk', 'example.co.uk')).toBe(true);
    expect(isSameSite('example.co.uk', 'example.com')).toBe(false);
  });
});

describe('classifyDomain', () => {
  test('classifies same-site and subdomains as first-party', () => {
    expect(classifyDomain('www.walmart.com', 'walmart.com').tier).toBe('first-party');
    expect(classifyDomain('careers.walmart.com', 'walmart.com').tier).toBe('first-party');
  });

  test('classifies a brand-owned asset domain (narrow suffix match) as first-party', () => {
    expect(classifyDomain('i5.walmartimages.com', 'walmart.com').tier).toBe('first-party');
  });

  test('does NOT classify a domain that merely contains the brand name as first-party (phishing bypass check)', () => {
    expect(classifyDomain('evil-walmart-login.com', 'walmart.com').tier).toBe('unknown');
    expect(classifyDomain('walmart-security-alert.com', 'walmart.com').tier).toBe('unknown');
    expect(classifyDomain('walmartimages-secure-login.com', 'walmart.com').tier).toBe('unknown');
  });

  test('classifies known CDNs and vendors', () => {
    expect(classifyDomain('cdn.jsdelivr.net', 'walmart.com').tier).toBe('known-cdn');
    expect(classifyDomain('www.paypalobjects.com', 'walmart.com').tier).toBe('known-vendor');
  });

  test('classifies a genuinely unrelated domain as unknown', () => {
    expect(classifyDomain('totally-unrecognized-vendor-xyz123.net', 'walmart.com').tier).toBe('unknown');
  });

  test('does not false-positive on unrelated words containing a brand as a substring', () => {
    // "grapple"/"pineapple" contain "apple" but aren't Apple Inc infrastructure
    expect(classifyDomain('grapple.com', 'apple.com').tier).toBe('unknown');
    expect(classifyDomain('pineapple.com', 'apple.com').tier).toBe('unknown');
  });
});

describe('isValidHostname', () => {
  test('accepts real domains and IPs', () => {
    expect(isValidHostname('walmart.com')).toBe(true);
    expect(isValidHostname('192.168.1.1')).toBe(true);
    expect(isValidHostname('localhost')).toBe(true);
  });

  test('rejects malformed/placeholder hostnames', () => {
    expect(isValidHostname('')).toBe(false);
    expect(isValidHostname(null)).toBe(false);
  });
});
