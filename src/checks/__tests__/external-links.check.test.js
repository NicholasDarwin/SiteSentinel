jest.mock('axios');
jest.mock('puppeteer', () => ({
  launch: jest.fn().mockRejectedValue(new Error('puppeteer not available in test env'))
}), { virtual: true });

const axios = require('axios');
const ExternalLinksCheck = require('../external-links.check');

describe('ExternalLinksCheck - registrable-domain comparison and script URL validation (Goal 2.5/2.6)', () => {
  const encodedRealUrl = Buffer.from('https://real-external.com/secret').toString('base64');

  beforeEach(() => {
    jest.clearAllMocks();
    axios.get.mockResolvedValue({
      status: 200,
      headers: {},
      data: `
        <html><body>
          <a href="https://www.walmart.com/store">Store</a>
          <a href="https://corporate.walmart.com/about">About</a>
          <a href="https://real-external.com/page">External</a>
          <script>
            var junk = "kiosco.www.walmart.com.mx,https//broken";
            var placeholder = "{search_term_string}";
            location.href = atob("${encodedRealUrl}");
          </script>
        </body></html>
      `
    });
  });

  test('www/corporate subdomains of the same site are not counted as external page links', async () => {
    const result = await new ExternalLinksCheck().analyze('https://www.walmart.com/');
    expect(result.externalLinks).toEqual(['https://real-external.com/page']);
  });

  test('malformed script fragments and template placeholders are rejected, not surfaced as links', async () => {
    const result = await new ExternalLinksCheck().analyze('https://www.walmart.com/');
    const allLinks = [...result.externalLinks, ...(result.scriptExtractedLinks || [])];
    expect(allLinks.some(u => u.includes('kiosco') || u.includes('broken'))).toBe(false);
    expect(allLinks.some(u => u.includes('{search_term_string}'))).toBe(false);
  });

  test('a valid atob()-decoded redirect URL is captured and labeled as script-extracted', async () => {
    const result = await new ExternalLinksCheck().analyze('https://www.walmart.com/');
    expect(result.scriptExtractedLinks).toContain('https://real-external.com/secret');
    // Not mixed into the primary (scored) page-link count
    expect(result.externalLinks).not.toContain('https://real-external.com/secret');
  });

  test('remaining/unscored links explain why they were not scored', async () => {
    const manyLinksHtml = Array.from({ length: 55 }, (_, i) => `<a href="https://external-${i}.example.com/">link ${i}</a>`).join('\n');
    axios.get.mockResolvedValue({ status: 200, headers: {}, data: `<html><body>${manyLinksHtml}</body></html>` });
    const result = await new ExternalLinksCheck().analyze('https://www.walmart.com/');
    const notScored = result.scoredLinks.filter(l => l.status === 'Not Scored');
    expect(notScored.length).toBeGreaterThan(0);
    expect(notScored[0].notScoredReason).toMatch(/evaluation limit/i);
  }, 20000);
});
