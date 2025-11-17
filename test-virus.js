const SafetyCheck = require('./src/checks/safety.check');
const LinkAnalysisCheck = require('./src/checks/link-analysis.check');

async function testUrl(url) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Testing: ${url}`);
  console.log('='.repeat(80));
  
  try {
    console.log('\n--- SAFETY CHECK ---');
    const safetyCheck = new SafetyCheck();
    const safetyResult = await safetyCheck.analyze(url);
    console.log(`Score: ${safetyResult.score}/100`);
    console.log(`Malware Detected: ${safetyResult.malwareDetected ? 'YES' : 'NO'}`);
    safetyResult.checks.forEach(c => {
      if (c.status === 'fail' || c.status === 'warn') {
        console.log(`[${c.status.toUpperCase()}] ${c.name}: ${c.description}`);
      }
    });

    console.log('\n--- LINK ANALYSIS ---');
    const linkCheck = new LinkAnalysisCheck();
    const linkResult = await linkCheck.analyze(url);
    console.log(`Score: ${linkResult.score}/100`);
    console.log(`Suspicious Redirects: ${linkResult.suspiciousRedirectsDetected ? 'YES' : 'NO'}`);
    linkResult.checks.forEach(c => {
      console.log(`[${c.status.toUpperCase()}] ${c.name}: ${c.description}`);
    });
  } catch (error) {
    console.error('Error:', error.message);
  }
}

testUrl('https://hk.jayantwhaling.shop/iV4w2ggznMEm24XVr/vLlnm?param_4=894697&param_5=5084572210725997861');
