jest.mock('axios');
const axios = require('axios');
const SafetyCheck = require('../safety.check');

function mockResponse({ headers = {}, data = '' }) {
  axios.get.mockResolvedValue({
    status: 200,
    headers,
    data
  });
}

describe('SafetyCheck - walmart.com-like regression (Goal 2 false-positive fixes)', () => {
  const walmartLikeHtml = `
    <!doctype html>
    <html>
    <head><title>Rollback Deals</title></head>
    <body>
      <h1>Rollback Deals</h1>
      <p>Hurry! This deal ends in 2 hours 15 minutes. Shop rollback prices now.</p>
      <p>Claim your Walmart+ rewards today.</p>
      <script src="https://cdn.jsdelivr.net/npm/some-lib.js"></script>
      <script src="/assets/app.js"></script>
      <script src="https://i5.walmartimages.com/asr/logo.js"></script>
    </body>
    </html>
  `;

  beforeEach(() => {
    jest.clearAllMocks();
    mockResponse({
      headers: {
        'content-security-policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://i5.walmartimages.com"
      },
      data: walmartLikeHtml
    });
  });

  test('is not flagged as malware/phishing', async () => {
    const result = await new SafetyCheck().analyze('https://www.walmart.com/');
    expect(result.malwareDetected).toBe(false);
    const malwareCheck = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(malwareCheck.status).toBe('pass');
  });

  test('does not score the category as 0', async () => {
    const result = await new SafetyCheck().analyze('https://www.walmart.com/');
    expect(result.score).not.toBe(0);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('a deal countdown timer alone does not trigger scam detection', async () => {
    const check = new SafetyCheck();
    const scamResult = check.detectScamContent(walmartLikeHtml.toLowerCase(), 'https://www.walmart.com/');
    expect(scamResult.isScam).toBe(false);
  });

  test('a valid CSP satisfies the XSS Protection check (X-XSS-Protection is deprecated)', async () => {
    const result = await new SafetyCheck().analyze('https://www.walmart.com/');
    const xssCheck = result.checks.find(c => c.id === 'xss-protection');
    expect(xssCheck.status).toBe('pass');
  });

  test('first-party/known-CDN scripts do not fail the External Scripts check', async () => {
    const result = await new SafetyCheck().analyze('https://www.walmart.com/');
    const scriptsCheck = result.checks.find(c => c.id === 'external-scripts');
    expect(scriptsCheck.status).not.toBe('fail');
    expect(scriptsCheck.severity).not.toBe('critical');
  });
});

describe('SafetyCheck - true positives still work (regression must not neuter detection)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('a fake virus alert combined with a countdown timer IS flagged', () => {
    const check = new SafetyCheck();
    const bodyLower = `
      warning! your computer has been infected with a virus.
      do not close your computer or restart your device.
      call 1-800-555-0199 immediately for support.
      your download is ready in 5 seconds...
    `.toLowerCase();
    const result = check.detectScamContent(bodyLower, 'https://scam-example.com/');
    expect(result.isScam).toBe(true);
  });

  test('a credit-card input field on an untrusted non-retail domain still fails', () => {
    const check = new SafetyCheck();
    const html = '<input type="text" name="credit_card_number" placeholder="Card Number">'.toLowerCase();
    const result = check.detectCredentialHarvesting(html, 'totally-sketchy-freebies.xyz');
    expect(result.isHarvesting).toBe(true);
  });

  test('mentioning "expires" in ordinary page text does not trigger credential harvesting', () => {
    const check = new SafetyCheck();
    const html = 'your session expires in 5 minutes. this offer expires soon.'.toLowerCase();
    const result = check.detectCredentialHarvesting(html, 'example.com');
    expect(result.isHarvesting).toBe(false);
  });

  test('typosquatted brand domains are still detected', () => {
    const check = new SafetyCheck();
    expect(check.detectPhishingIndicators('https://gooogle.com/', 'gooogle.com')).toBe(true);
    expect(check.detectPhishingIndicators('https://amaz0n.com/', 'amaz0n.com')).toBe(true);
  });

  test('unrelated domains that merely contain a brand substring are not flagged as typosquats', () => {
    const check = new SafetyCheck();
    expect(check.detectPhishingIndicators('https://grapple.com/', 'grapple.com')).toBe(false);
    expect(check.detectPhishingIndicators('https://google.de/', 'google.de')).toBe(false);
  });
});
