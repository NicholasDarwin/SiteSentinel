/**
 * Security-Test Signature Registry
 *
 * A single, maintainable table of known security-test URLs/domains -
 * resources that are INTENTIONALLY designed to look like malware/phishing so
 * that security products (like this scanner) can verify their own detection
 * works. Google's Safe Browsing test pages are the canonical example: they
 * are not malicious, but a security scanner that reports them as a clean
 * "Good" site has a real gap in its detection, which is exactly the bug this
 * registry exists to close.
 *
 * Add new entries here - never scatter ad-hoc URL string checks through the
 * detection logic. Each signature matches by hostname + a path pattern
 * (rather than a single exact URL) so reasonable variants under the same
 * test host are still recognized.
 *
 * IMPORTANT: a signature match means "this is a recognized test target",
 * not "Google/the host provider is malicious". The `message` for each
 * signature is written to make that distinction explicit, since it ends up
 * directly in the report's evidence.
 */

const SECURITY_TEST_SIGNATURES = [
  {
    id: 'google-safebrowsing-test-malware',
    provider: 'Google Safe Browsing test suite (testsafebrowsing.appspot.com)',
    threatCategory: 'malware',
    hostnames: ['testsafebrowsing.appspot.com'],
    pathPattern: /^\/s\/malware(_[a-z0-9_]+)?\.html$/i,
    message: 'Known Google Safe Browsing malware test URL detected. This URL is intentionally provided by Google for testing security products and is not evidence that Google\'s own infrastructure is malicious.'
  },
  {
    id: 'google-safebrowsing-test-phishing',
    provider: 'Google Safe Browsing test suite (testsafebrowsing.appspot.com)',
    threatCategory: 'phishing',
    hostnames: ['testsafebrowsing.appspot.com'],
    pathPattern: /^\/s\/phishing(_[a-z0-9_]+)?\.html$/i,
    message: 'Known Google Safe Browsing phishing test URL detected. This URL is intentionally provided by Google for testing phishing detection and is not evidence that Google\'s own infrastructure is malicious.'
  },
  {
    id: 'google-safebrowsing-test-unwanted-software',
    provider: 'Google Safe Browsing test suite (testsafebrowsing.appspot.com)',
    threatCategory: 'unwanted-software',
    hostnames: ['testsafebrowsing.appspot.com'],
    pathPattern: /^\/s\/(unwanted|harmful)(_[a-z0-9_]+)?\.html$/i,
    message: 'Known Google Safe Browsing unwanted-software test URL detected. This URL is intentionally provided by Google for testing and is not evidence that Google\'s own infrastructure is malicious.'
  },
  {
    id: 'google-legacy-test-malware-domain',
    provider: 'Google legacy Safe Browsing test domain (malware.testing.google.test)',
    threatCategory: 'malware',
    hostnames: ['malware.testing.google.test'],
    pathPattern: /^\/testing\/malware\/?/i,
    message: 'Known Google Safe Browsing legacy malware-test domain detected. This hostname is intentionally reserved by Google for testing malware-detection products and is not evidence that Google\'s own infrastructure is malicious. Note: this legacy test domain does not always resolve via public DNS - an unreachable/NXDOMAIN result for it should be reported as "unable to determine", not as "safe".'
  },
  {
    id: 'google-legacy-test-phishing-domain',
    provider: 'Google legacy Safe Browsing test domain (malware.testing.google.test)',
    threatCategory: 'phishing',
    hostnames: ['malware.testing.google.test'],
    pathPattern: /^\/testing\/phishing\/?/i,
    message: 'Known Google Safe Browsing legacy phishing-test domain detected. This hostname is intentionally reserved by Google for testing phishing-detection products and is not evidence that Google\'s own infrastructure is malicious. Note: this legacy test domain does not always resolve via public DNS - an unreachable/NXDOMAIN result for it should be reported as "unable to determine", not as "safe".'
  }
];

/**
 * Matches a URL against the registry by hostname + path pattern. Works on
 * the URL alone (no network access needed), so a target can be recognized as
 * a security-test resource even if the live fetch subsequently fails (e.g.
 * malware.testing.google.test's DNS record can be flaky/retired) - being a
 * known test target and being currently reachable are independent facts.
 * Returns the matched signature, or null.
 */
function matchSecurityTestSignature(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname || '/';

  for (const signature of SECURITY_TEST_SIGNATURES) {
    if (signature.hostnames.includes(hostname) && signature.pathPattern.test(path)) {
      return signature;
    }
  }
  return null;
}

module.exports = {
  SECURITY_TEST_SIGNATURES,
  matchSecurityTestSignature
};
