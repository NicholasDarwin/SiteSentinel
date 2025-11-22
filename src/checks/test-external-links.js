const ExternalLinksCheck = require('./external-links.check');

(async () => {
  const url = process.argv[2] || 'https://ww7.123moviesfree.net/home/';
  const checker = new ExternalLinksCheck();
  console.log('Analyzing:', url);
  const result = await checker.analyze(url);
  console.log('Category Score:', result.score);
  console.log('External Links Count:', result.externalLinks.length);
  console.log('External Domains:', result.externalDomains);
  console.log('First 20 Links:', result.externalLinks.slice(0,20));
  const redirectCheck = result.checks.find(c => c.name.includes('Redirect'));
  if (redirectCheck) console.log('Redirect Check:', redirectCheck.description);
  console.log('Scored Links (sample):', result.scoredLinks.slice(0,5));
})();
