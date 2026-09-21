jest.mock('../../checks/security.check');
jest.mock('../../checks/dns.check');
jest.mock('../../checks/performance.check');
jest.mock('../../checks/seo.check');
jest.mock('../../checks/accessibility.check');
jest.mock('../../checks/safety.check');
jest.mock('../../checks/link-analysis.check');
jest.mock('../../checks/external-links.check');
jest.mock('../../checks/whois.check');

const express = require('express');
const axios = require('axios');

const SecurityCheck = require('../../checks/security.check');
const DnsCheck = require('../../checks/dns.check');
const PerformanceCheck = require('../../checks/performance.check');
const SeoCheck = require('../../checks/seo.check');
const AccessibilityCheck = require('../../checks/accessibility.check');
const SafetyCheck = require('../../checks/safety.check');
const LinkAnalysisCheck = require('../../checks/link-analysis.check');
const ExternalLinksCheck = require('../../checks/external-links.check');
const WhoisCheck = require('../../checks/whois.check');

const analyzeRoute = require('../analyze.route');

function okCategory(name, score, extra = {}) {
  return {
    category: name,
    icon: 'x',
    score,
    status: 'available',
    checks: [{ name: 'Some Check', status: 'pass', severity: 'medium', description: 'ok' }],
    ...extra
  };
}

function unavailableCategory(name) {
  return { category: name, icon: 'x', score: null, status: 'unavailable', checks: [{ name: 'Fetch Error', status: 'error', severity: 'critical', description: 'unable to determine' }] };
}

function mockAllChecksAvailable() {
  SecurityCheck.mockImplementation(() => ({ analyze: async () => okCategory('Security & HTTPS', 90) }));
  DnsCheck.mockImplementation(() => ({ analyze: async () => okCategory('DNS & Domain', 90) }));
  PerformanceCheck.mockImplementation(() => ({ analyze: async () => okCategory('Performance', 90) }));
  SeoCheck.mockImplementation(() => ({ analyze: async () => okCategory('SEO & Meta', 90) }));
  AccessibilityCheck.mockImplementation(() => ({ analyze: async () => okCategory('Accessibility', 90) }));
  SafetyCheck.mockImplementation(() => ({ analyze: async () => okCategory('Safety & Threats', 90) }));
  LinkAnalysisCheck.mockImplementation(() => ({ analyze: async () => okCategory('Link Analysis', 90) }));
  ExternalLinksCheck.mockImplementation(() => ({ analyze: async () => okCategory('External Links', 90) }));
  WhoisCheck.mockImplementation(() => ({ analyze: async () => okCategory('WHOIS & Domain Info', 90) }));
}

let server;
let baseUrl;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', analyzeRoute);
  server = app.listen(0);
  await new Promise(resolve => server.on('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterAll(() => new Promise(resolve => server.close(resolve)));

beforeEach(() => {
  jest.clearAllMocks();
  mockAllChecksAvailable();
});

describe('POST /api/analyze - SSRF pre-check', () => {
  test('rejects a private-IP target with 400, without dispatching any checks', async () => {
    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'http://127.0.0.1/' }, { validateStatus: () => true });
    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toMatch(/restricted or private/i);
    expect(SecurityCheck).not.toHaveBeenCalled();
  });

  test('rejects a cloud-metadata target with 400', async () => {
    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'http://169.254.169.254/latest/meta-data/' }, { validateStatus: () => true });
    expect(res.status).toBe(400);
    expect(res.data.error).toMatch(/restricted or private/i);
  });

  test('a normal public URL proceeds to analysis (200)', async () => {
    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'https://example.com' }, { validateStatus: () => true });
    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
  });
});

describe('POST /api/analyze - confirmed-threat scoring override', () => {
  test('a confirmed malware detection forces the overall score to 0, regardless of other categories', async () => {
    SafetyCheck.mockImplementation(() => ({
      analyze: async () => okCategory('Safety & Threats', 0, { malwareDetected: true })
    }));

    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'https://example.com' });
    expect(res.data.overall.score).toBe(0);
    expect(res.data.overall.unableToAnalyze).toBe(false);
  });
});

describe('POST /api/analyze - "unable to analyze" guard', () => {
  test('when most categories are unavailable, overall.label is "Unable to Analyze", not a normal rating', async () => {
    SecurityCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('Security & HTTPS') }));
    PerformanceCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('Performance') }));
    SeoCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('SEO & Meta') }));
    AccessibilityCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('Accessibility') }));
    SafetyCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('Safety & Threats') }));
    LinkAnalysisCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('Link Analysis') }));
    ExternalLinksCheck.mockImplementation(() => ({ analyze: async () => unavailableCategory('External Links') }));
    // DNS & WHOIS still return real scores (they don't require fetching the page)
    DnsCheck.mockImplementation(() => ({ analyze: async () => okCategory('DNS & Domain', 65) }));
    WhoisCheck.mockImplementation(() => ({ analyze: async () => okCategory('WHOIS & Domain Info', 95) }));

    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'https://example.com' });
    expect(res.data.overall.unableToAnalyze).toBe(true);
    expect(res.data.overall.label).toBe('Unable to Analyze');
    expect(res.data.overall.color).toBe('#6b7280');
    expect(res.data.overall.note).toMatch(/2 of 9/i);
  });

  test('when most categories ARE available, overall.label is a normal rating', async () => {
    const res = await axios.post(`${baseUrl}/api/analyze`, { url: 'https://example.com' });
    expect(res.data.overall.unableToAnalyze).toBe(false);
    expect(res.data.overall.label).not.toBe('Unable to Analyze');
  });
});
