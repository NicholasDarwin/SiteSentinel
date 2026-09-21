const http = require('http');
const axios = require('axios');
const {
  isBlockedIp,
  assertHostnameIsSafe,
  assertUrlIsSafe,
  createSafeAgents,
  SsrfBlockedError
} = require('../ssrf-guard.util');

describe('isBlockedIp', () => {
  test('blocks loopback, private, link-local, and cloud-metadata IPv4 addresses', () => {
    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('10.0.0.5')).toBe(true);
    expect(isBlockedIp('172.16.0.1')).toBe(true);
    expect(isBlockedIp('192.168.1.1')).toBe(true);
    expect(isBlockedIp('169.254.169.254')).toBe(true); // cloud metadata endpoint
  });

  test('allows public IPv4 addresses', () => {
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('172.32.0.1')).toBe(false); // just outside the 172.16-31 private range
  });

  test('blocks loopback and unique-local IPv6 addresses', () => {
    expect(isBlockedIp('::1')).toBe(true);
    expect(isBlockedIp('fd00::1')).toBe(true);
    expect(isBlockedIp('fe80::1')).toBe(true);
  });

  test('allows public IPv6 addresses', () => {
    expect(isBlockedIp('2001:4860:4860::8888')).toBe(false);
  });
});

describe('assertUrlIsSafe', () => {
  test('blocks literal-IP URLs directly (bypassing DNS resolution)', () => {
    expect(() => assertUrlIsSafe('http://127.0.0.1/')).toThrow(SsrfBlockedError);
    expect(() => assertUrlIsSafe('http://169.254.169.254/latest/meta-data/')).toThrow(SsrfBlockedError);
  });

  test('blocks "localhost" by name', () => {
    expect(() => assertUrlIsSafe('http://localhost/')).toThrow(SsrfBlockedError);
  });

  test('blocks non-http(s) protocols (redirect-smuggling guard)', () => {
    expect(() => assertUrlIsSafe('file:///etc/passwd')).toThrow(SsrfBlockedError);
  });

  test('allows a normal public URL', () => {
    expect(() => assertUrlIsSafe('https://example.com/')).not.toThrow();
  });
});

describe('assertHostnameIsSafe', () => {
  test('rejects localhost', async () => {
    await expect(assertHostnameIsSafe('localhost')).rejects.toThrow();
  });

  test('resolves for a normal public hostname', async () => {
    await expect(assertHostnameIsSafe('example.com')).resolves.toBeUndefined();
  });
});

describe('createSafeAgents (end-to-end connection blocking)', () => {
  test('a request to a private-IP target is actually refused at connect time', async () => {
    const server = http.createServer((req, res) => res.end('internal'));
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    const { httpAgent } = createSafeAgents();
    await expect(
      axios.get(`http://127.0.0.1:${port}/`, { httpAgent, timeout: 3000 })
    ).rejects.toThrow();

    server.close();
  });

  test('a request to a normal public target still succeeds', async () => {
    const { httpAgent, httpsAgent } = createSafeAgents();
    const res = await axios.get('https://example.com/', { httpAgent, httpsAgent, timeout: 10000 });
    expect(res.status).toBe(200);
  }, 15000);
});
