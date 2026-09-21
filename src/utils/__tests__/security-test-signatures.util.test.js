const { matchSecurityTestSignature, SECURITY_TEST_SIGNATURES } = require('../security-test-signatures.util');

describe('matchSecurityTestSignature', () => {
  test('matches the Google Safe Browsing malware test URL', () => {
    const sig = matchSecurityTestSignature('https://testsafebrowsing.appspot.com/s/malware.html');
    expect(sig).not.toBeNull();
    expect(sig.threatCategory).toBe('malware');
    expect(sig.message).toMatch(/not evidence that Google/i);
  });

  test('matches the Google Safe Browsing phishing test URL', () => {
    const sig = matchSecurityTestSignature('https://testsafebrowsing.appspot.com/s/phishing.html');
    expect(sig).not.toBeNull();
    expect(sig.threatCategory).toBe('phishing');
    expect(sig.message).toMatch(/not evidence that Google/i);
  });

  test('matches the legacy malware.testing.google.test domain', () => {
    const sig = matchSecurityTestSignature('http://malware.testing.google.test/testing/malware/');
    expect(sig).not.toBeNull();
    expect(sig.threatCategory).toBe('malware');
  });

  test('does not match an ordinary site', () => {
    expect(matchSecurityTestSignature('https://example.com/')).toBeNull();
  });

  test('does not match a lookalike/spoofed hostname (substring trick)', () => {
    expect(matchSecurityTestSignature('https://testsafebrowsing.appspot.com.evil.com/s/malware.html')).toBeNull();
  });

  test('does not match the test host on an unrelated path', () => {
    expect(matchSecurityTestSignature('https://testsafebrowsing.appspot.com/unrelated-page.html')).toBeNull();
  });

  test('handles invalid URLs without throwing', () => {
    expect(matchSecurityTestSignature('not a url')).toBeNull();
  });

  test('every signature has a message that avoids accusing the provider itself', () => {
    for (const sig of SECURITY_TEST_SIGNATURES) {
      expect(sig.message.toLowerCase()).toContain('not evidence');
    }
  });
});
