# SiteSentinel

Check a website before you trust it. SiteSentinel inspects any public URL across nine categories, from HTTPS and security headers to phishing signals, DNS and WHOIS age, and shows the evidence behind every verdict.

Each finding records what was actually observed (the response headers, the HTML snippet and line, the script and where it loads from), how many points it cost, why it matters, how to fix it, and a note when the result could be a false positive.

## Run it locally

Requires Node.js 18 or newer.

```bash
npm install
cp .env.example .env   # optional settings, see below
npm start              # http://localhost:3000
npm test               # Jest test suite
```

The Express server serves the interface from `docs/` and the API from `/api`. `docs/` is also what GitHub Pages publishes, but the static site can't run scans on its own; it needs the server.

### Environment

| Variable | Purpose |
| --- | --- |
| `PORT` | Port to listen on (default `3000`). |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Enables Safe Browsing lookups in the Safety & Threats check. Without it, that check relies on local heuristics and says so in its evidence. |
| `ENABLE_AI` | Turns on the optional AI assessment and "Ask about this report" panel. |

## What it checks

| Category | Weight | Looks at |
| --- | --- | --- |
| Security & HTTPS | 3 | HTTPS, TLS version, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer- and Permissions-Policy, scam redirects |
| Safety & Threats | 3 | Safe Browsing, phishing and typosquat patterns, credential harvesting forms, obfuscated JavaScript, deceptive downloads, mixed content, iframes, external scripts |
| DNS & Domain | 2 | Resolution, redundancy, IPv6, CAA, SPF, DMARC, MX |
| Link Analysis | 2 | Outbound link density and suspicious redirects |
| External Links | 1.5 | Every outbound link and script-embedded URL, scored safe / warning / unsafe / broken |
| Performance | 1.5 | Load time, response size, compression, caching, HTTP version, keep-alive, redirect hops |
| Accessibility (WCAG 2.1) | 1.5 | Alt text, form labels, contrast, heading order, landmarks, language, skip links, keyboard access |
| SEO & Metadata | 1 | Title, description, H1, canonical, Open Graph, structured data, viewport, robots, favicon |
| WHOIS & Domain Info | 1 | Registrar, domain age, expiry, status, name servers, DNSSEC |

## How scores are calculated

All weights live in [`src/utils/score-calculator.util.js`](src/utils/score-calculator.util.js).

- Every category starts at **100**. A failed check deducts its full severity weight and a warning deducts half: critical 35, high 20, medium 10, low 5, info 0.
- A category never drops below **15** from ordinary deductions, so one or two findings can't read as total failure. The one exception is a confirmed, high-confidence malware or phishing match, which sets Safety & Threats to 0.
- The overall score is the weighted average of the categories that could be analyzed, using the weights in the table above. Categories that errored are left out rather than counted as zero.

## API

`POST /api/analyze` with `{ "url": "example.com" }` returns:

```json
{
  "success": true,
  "url": "https://example.com/",
  "timestamp": "2026-10-14T12:00:00.000Z",
  "overall": { "score": 82, "label": "Good" },
  "categories": [
    {
      "category": "Security & HTTPS",
      "score": 90,
      "checks": [
        {
          "name": "Content Security Policy (CSP)",
          "status": "warn",
          "severity": "medium",
          "maxPoints": 10,
          "pointsDeducted": 5,
          "confidence": "high",
          "description": "CSP not configured (recommended but not required)",
          "evidence": [{ "type": "headers", "highlightHeader": "content-security-policy", "present": false }],
          "fix": "Add a Content-Security-Policy header, e.g. in nginx: ..."
        }
      ]
    }
  ]
}
```

`GET /api/health` and `GET /health` report server status.

## Project layout

```
src/
  server.js                 Express app: static files, API routes
  routes/                   /api/analyze and the optional /api/ai routes
  checks/                   One module per category, plus Jest tests
  utils/                    Scoring, evidence helpers, SSRF guard, HTTP client
docs/
  index.html, app.js        The interface and results view
  js/seal.js                Draws the guilloche seal for a hostname
  js/site.js                Hero seal, sample links, scroll reveals
  agents/, safety/          How each inspector and safety check works
  styles.css                The whole design system
```

## Scope

SiteSentinel only makes requests a normal browser would: it fetches public pages, reads headers, and queries DNS, WHOIS and (optionally) Safe Browsing. It doesn't scan ports, try credentials, submit forms or send attack payloads, and it refuses addresses on private networks or cloud metadata endpoints before making any request. Only inspect sites you're allowed to.

## License

MIT
