/**
 * Test legitimate sites for false positives
 */

const axios = require('axios');

const legitimateSites = [
  'https://www.google.com',
  'https://www.amazon.com',
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://www.facebook.com',
  'https://www.github.com',
  'https://www.stackoverflow.com',
  'https://www.wikipedia.org',
  'https://www.reddit.com',
  'https://www.twitter.com',
  'https://www.youtube.com',
  'https://www.linkedin.com',
  'https://www.walmart.com',
  'https://www.ebay.com',
  'https://www.target.com',
  'https://www.bestbuy.com'
];

async function testSites() {
  console.log('Testing legitimate sites for false positives...\n');
  
  for (const site of legitimateSites) {
    try {
      const response = await axios.post('http://localhost:3000/api/analyze', { url: site }, {
        timeout: 30000
      });
      
      const score = response.data.overall.score;
      const label = response.data.overall.label;
      
      if (score < 60) {
        console.log(`⚠️  FALSE POSITIVE: ${site} - Score: ${score}/100 (${label})`);
      } else {
        console.log(`✅ ${site} - Score: ${score}/100 (${label})`);
      }
    } catch (error) {
      console.log(`❌ ERROR analyzing ${site}: ${error.message}`);
    }
  }
}

testSites();
