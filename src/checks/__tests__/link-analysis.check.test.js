jest.mock('axios');
const axios = require('axios');
const LinkAnalysisCheck = require('../link-analysis.check');

describe('LinkAnalysisCheck - registrable-domain comparison (Goal 2.5)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    axios.get.mockResolvedValue({
      status: 200,
      headers: {},
      data: `
        <html><body>
          <a href="https://www.walmart.com/store">Store</a>
          <a href="https://corporate.walmart.com/about">About</a>
          <a href="https://careers.walmart.com/jobs">Careers</a>
          <a href="https://totally-different-site.com/page">External</a>
        </body></html>
      `
    });
  });

  test('www/corporate/careers subdomains of the same site are not counted as external', async () => {
    const result = await new LinkAnalysisCheck().analyze('https://www.walmart.com/');
    const externalCheck = result.checks.find(c => c.id === 'external-links-found');
    // Only the genuinely different domain should count as external
    expect(externalCheck.description).toContain('1 external');
  });
});
