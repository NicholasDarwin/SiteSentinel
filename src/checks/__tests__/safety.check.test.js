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

describe('SafetyCheck - security-test signature recognition (detection AND scoring)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('Google Safe Browsing malware test URL is recognized, scored 0, and clearly labeled', async () => {
    mockResponse({
      data: '<html><body>Malware Page Example.<a href="https://testsafebrowsing.appspot.com/s/double_zipped.zip">Malware download</a></body></html>'
    });
    const result = await new SafetyCheck().analyze('https://testsafebrowsing.appspot.com/s/malware.html');

    expect(result.malwareDetected).toBe(true);
    expect(result.score).toBe(0); // confirmed threat -> full category penalty

    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(check.status).toBe('fail');
    expect(check.verdict).toBe('security-test');
    expect(check.threatCategory).toBe('malware');
    expect(check.description).toMatch(/not evidence that Google/i);
    expect(check.description).toMatch(/security test/i);
  });

  test('Google Safe Browsing phishing test URL is recognized, scored 0, and clearly labeled', async () => {
    mockResponse({
      data: `<html><body>
        <h1>Phishing Page Example.</h1>
        <div><label>Username:</label><input type="text"/></div>
        <div><label>Password:</label><input type="password"/></div>
      </body></html>`
    });
    const result = await new SafetyCheck().analyze('https://testsafebrowsing.appspot.com/s/phishing.html');

    expect(result.malwareDetected).toBe(true);
    expect(result.score).toBe(0);

    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(check.status).toBe('fail');
    expect(check.verdict).toBe('security-test');
    expect(check.threatCategory).toBe('phishing');
    expect(check.description).toMatch(/not evidence that Google/i);
  });
});

describe('SafetyCheck - scanner errors are never reported as "safe" (detection AND scoring)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('an unreachable domain (DNS failure) is "unable to determine", never "no indicators detected"', async () => {
    const dnsError = new Error('getaddrinfo ENOTFOUND does-not-exist.invalid');
    dnsError.code = 'ENOTFOUND';
    axios.get.mockRejectedValue(dnsError);

    const result = await new SafetyCheck().analyze('https://does-not-exist.invalid/');

    expect(result.score).toBeNull();
    expect(result.status).toBe('unavailable');
    expect(result.malwareDetected).toBe(false); // not a confirmed threat - just unreachable

    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(check.status).toBe('error');
    expect(check.verdict).toBe('unable-to-determine');
    expect(check.description).toMatch(/unable to determine/i);
    expect(check.description).not.toMatch(/no malware or phishing indicators detected/i);
  });

  test('a connection timeout is "unable to determine", never "no indicators detected"', async () => {
    const timeoutError = new Error('timeout of 15000ms exceeded');
    timeoutError.code = 'ECONNABORTED';
    axios.get.mockRejectedValue(timeoutError);

    const result = await new SafetyCheck().analyze('https://slow-server-example.test/');

    expect(result.score).toBeNull();
    expect(result.status).toBe('unavailable');

    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(check.status).toBe('error');
    expect(check.verdict).toBe('unable-to-determine');
    expect(check.description).toMatch(/unable to determine/i);
    expect(check.method).toMatch(/timeout/i);
  });

  test('a DNS failure on the known legacy Google test domain still surfaces the security-test context', async () => {
    const dnsError = new Error('getaddrinfo ENOTFOUND malware.testing.google.test');
    dnsError.code = 'ENOTFOUND';
    axios.get.mockRejectedValue(dnsError);

    const result = await new SafetyCheck().analyze('http://malware.testing.google.test/testing/malware/');

    expect(result.status).toBe('unavailable');
    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');
    expect(check.verdict).toBe('unable-to-determine');
    expect(check.description).toMatch(/unable to determine/i);
    expect(check.description).toMatch(/security-test signature/i);
  });

  test('Google Safe Browsing API failure does not silently become a confident "safe" verdict', async () => {
    mockResponse({ data: '<html><body>An ordinary page with nothing suspicious.</body></html>' });
    const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-key';
    axios.post.mockRejectedValue(new Error('network error reaching Google'));

    const result = await new SafetyCheck().analyze('https://ordinary-site.example/');
    const check = result.checks.find(c => c.id === 'malware-phishing-indicators');

    expect(check.status).toBe('pass'); // no local indicators either, so still a pass...
    expect(check.confidence).toBe('medium'); // ...but confidence is downgraded, not a confident "high"
    expect(check.description).toMatch(/could not be reached/i);

    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
  });
});

describe('SafetyCheck - suspicious redirect chain', () => {
  beforeEach(() => jest.clearAllMocks());

  test('a redirect chain through a disposable-TLD domain is flagged as suspicious (warn, not fail)', async () => {
    axios.get.mockImplementation((requestUrl) => {
      if (requestUrl.includes('start.example.com')) {
        return Promise.resolve({ status: 302, headers: { location: 'https://step2.xyz/go' }, data: '' });
      }
      if (requestUrl.includes('step2.xyz')) {
        return Promise.resolve({ status: 302, headers: { location: 'https://final-destination.example.net/' }, data: '' });
      }
      return Promise.resolve({ status: 200, headers: {}, data: '<html><body>Final landing page.</body></html>' });
    });

    const result = await new SafetyCheck().analyze('https://start.example.com/');
    const redirectCheck = result.checks.find(c => c.id === 'suspicious-redirect-chain');

    expect(redirectCheck).toBeDefined();
    expect(redirectCheck.status).toBe('warn');
    expect(result.malwareDetected).toBe(false); // suspicious alone never forces a fail
    expect(result.score).toBeGreaterThan(0); // and never zeroes the category on its own
  });

  test('a normal single redirect (e.g. http -> https) is not flagged', async () => {
    axios.get.mockImplementation((requestUrl) => {
      if (requestUrl.startsWith('http://plain-site.example/')) {
        return Promise.resolve({ status: 301, headers: { location: 'https://plain-site.example/' }, data: '' });
      }
      return Promise.resolve({ status: 200, headers: {}, data: '<html><body>Hello.</body></html>' });
    });

    const result = await new SafetyCheck().analyze('http://plain-site.example/');
    const redirectCheck = result.checks.find(c => c.id === 'suspicious-redirect-chain');
    expect(redirectCheck).toBeUndefined();
  });
});

describe('SafetyCheck - suspicious credential form (generic, non-brand phishing page)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('a bare login form combined with self-describing phishing text is flagged (Goal: generic-form gap)', async () => {
    mockResponse({
      data: `<html><body>
        <h1>Phishing Page Example.</h1>
        <p>This is an example of a phishing page used for social engineering testing.</p>
        <div><input type="text" name="username"/></div>
        <div><input type="password" name="password"/></div>
      </body></html>`
    });

    const result = await new SafetyCheck().analyze('https://some-untrusted-test-host.example/');
    const credCheck = result.checks.find(c => c.id === 'credential-harvesting');

    expect(credCheck.status).toBe('fail');
    expect(credCheck.description).toMatch(/untrusted login form/i);
  });

  test('a bare login form with NO corroborating signal is NOT flagged (avoids false positives on ordinary sites)', async () => {
    mockResponse({
      data: `<html><body>
        <h1>Welcome back</h1>
        <div><input type="text" name="username"/></div>
        <div><input type="password" name="password"/></div>
      </body></html>`
    });

    const result = await new SafetyCheck().analyze('https://some-ordinary-saas-app.example/');
    const credCheck = result.checks.find(c => c.id === 'credential-harvesting');
    expect(credCheck.status).toBe('pass');
  });
});
