# 🔐 SiteSentinel - Comprehensive Website Security Analysis Tool

A powerful, open-source web application that performs comprehensive security, performance, SEO, and best practices analysis on any public website. Perfect for your personal website or resume portfolio to demonstrate cybersecurity expertise.

## Features

### 📊 50+ Security & Web Analysis Checks

SiteSentinel performs comprehensive checks across six major categories:

1. **Security & HTTPS (15+ checks)**
   - SSL/TLS certificate validation and expiration
   - HTTPS enforcement and HTTP redirects
   - Security headers (CSP, X-Frame-Options, X-XSS-Protection, etc.)
   - HSTS enablement
   - Mixed content detection
   - Certificate chain validation

2. **Domain & DNS (10+ checks)**
   - Domain registration verification
   - DNS resolution (IPv4 & IPv6)
   - MX records configuration
   - SPF, DKIM, and DMARC email authentication records
   - DNSSEC status

3. **Web Performance (7+ checks)**
   - Page load time analysis
   - Page size optimization
   - Resource count and HTTP requests
   - Content compression (gzip/brotli)
   - HTTP/2 support
   - Caching headers configuration
   - Image optimization (lazy-loading, alt text)

4. **SEO & Analytics (10+ checks)**
   - Meta title and description optimization
   - H1 tag presence and count
   - Robots.txt configuration
   - Sitemap.xml presence
   - Canonical URL setup
   - Favicon configuration
   - Open Graph tags
   - Structured data (Schema.org)
   - Mobile viewport configuration

5. **Accessibility & Privacy (8+ checks)**
   - Image alt text coverage
   - ARIA labels for accessibility
   - Semantic HTML5 usage
   - Cookie security (Secure, HttpOnly flags)
   - Tracking scripts detection
   - Privacy policy links
   - Language declaration
   - Form labels

6. **Safety & Verification (6+ checks)**
   - HTTP status code validation
   - Broken links detection
   - Redirect chain analysis
   - Server information exposure
   - Safe browsing verification
   - Security misconfiguration detection

### 🎨 Beautiful, Responsive Interface

- Modern, professional UI with gradient headers
- Real-time analysis progress
- Color-coded status indicators (✅ Pass, ⚠️ Warning, ❌ Fail)
- Collapsible category sections for easy navigation
- Overall security score (0-100)
- Statistics dashboard
- Export report functionality

### ⚡ Safe & Legal

- **No hacking or unauthorized access**
- Uses only public APIs and safe HTTP/HTTPS requests
- No port scanning or network probing
- No credential testing
- No malware injection
- Fully compliant with website ToS

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn

### Setup

1. **Clone or download the repository**
```bash
cd Sitesentinel
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the server**
```bash
npm start
```

4. **Open in browser**
Navigate to `http://localhost:3000`

### Development Mode

For development with auto-reload:
```bash
npm run dev
```

## Usage

1. **Enter a URL** in the input field (e.g., `example.com` or `https://example.com`)
2. **Click "Analyze"** to start the comprehensive analysis
3. **Review Results**:
   - Overall security score appears at the top
   - Detailed results organized by category
   - Color-coded status indicators show the result of each check
   - Recommendations provided for warnings and failures
4. **Export Report** as a text file for documentation

## Project Structure

```
Sitesentinel/
├── package.json           # Node.js dependencies
├── server.js              # Express server setup
├── analyzer.js            # Core analysis engine (50+ checks)
├── public/
│   ├── index.html         # Main interface
│   ├── styles.css         # Styling and responsive design
│   └── app.js             # Frontend logic
└── README.md              # This file
```

## API Endpoints

### POST /api/analyze
Performs comprehensive analysis on a URL.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "summary": {
    "total_checks": 58,
    "passed": 45,
    "warnings": 10,
    "failed": 3,
    "score": 82
  },
  "categories": [
    {
      "name": "Security & HTTPS",
      "checks": [
        {
          "name": "HTTPS Protocol Used",
          "status": "pass",
          "details": "Site uses HTTPS",
          "recommendations": []
        }
        // ... more checks
      ]
    }
    // ... more categories
  ]
}
```

### GET /api/health
Health check endpoint.

```bash
curl http://localhost:3000/api/health
```

## Understanding the Score

The overall security score is calculated based on:
- **100 points available** from all checks
- **Pass**: Full points earned
- **Warning**: 50% of available points
- **Fail**: 0 points

**Score Ratings:**
- 80-100: 🟢 Excellent security posture
- 60-79: 🔵 Good security with some improvements needed
- 40-59: 🟡 Fair security with multiple issues
- 0-39: 🔴 Poor security requiring immediate attention

## Check Categories Detailed

### Security & HTTPS Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | HTTPS Protocol Used | Ensures encrypted communication |
| 2 | HTTP to HTTPS Redirect | Verifies automatic HTTPS enforcement |
| 3 | SSL Certificate Expiration | Checks certificate validity period |
| 4 | Certificate Issuer | Verifies legitimate certificate authority |
| 5 | Subject Alternative Names | Validates certificate domain coverage |
| 6 | Certificate Chain Valid | Ensures proper certificate chain |
| 7 | Security Headers Coverage | Checks for critical HTTP security headers |
| 8 | HSTS Enabled | Verifies Strict-Transport-Security header |
| 9 | Content Security Policy (CSP) | Checks CSP header for XSS protection |
| 10 | X-Frame-Options Header | Prevents clickjacking attacks |
| 11 | X-XSS-Protection Header | Legacy XSS protection |
| 12 | X-Content-Type-Options Header | Prevents MIME-sniffing |
| 13 | Referrer-Policy Header | Controls referrer information |
| 14 | Permissions-Policy Header | Controls browser feature access |
| 15 | Mixed Content Detection | Identifies HTTP resources on HTTPS pages |

### Domain & DNS Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | Domain Registration Info | Verifies domain is active |
| 2 | Domain Resolvable | Confirms DNS resolution works |
| 3 | DNSSEC Enabled | Checks DNS security extensions |
| 4 | MX Records Configured | Verifies email server configuration |
| 5 | Mail Server Configuration | Lists mail server details |
| 6 | SPF Record Present | Checks Sender Policy Framework |
| 7 | DKIM Record Present | Verifies DomainKeys Identified Mail |
| 8 | DMARC Record Present | Checks Domain-based Message Auth |
| 9 | DNS Resolution (IPv4) | Confirms IPv4 address resolution |
| 10 | IPv6 Support | Checks modern IPv6 support |

### Web Performance Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | Page Load Time | Measures initial page load speed |
| 2 | Page Size | Analyzes total page weight |
| 3 | Resource Count | Counts HTTP requests |
| 4 | Content Compression | Verifies gzip/brotli compression |
| 5 | HTTP/2 Support | Checks modern HTTP protocol |
| 6 | Cache Control Header | Verifies browser caching setup |
| 7 | ETag Header | Checks cache validation |
| 8 | Image Optimization | Analyzes image loading strategies |
| 9 | Lazy Loading | Verifies lazy-loading implementation |

### SEO & Analytics Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | Meta Title | Ensures proper page title |
| 2 | Meta Description | Verifies search snippet text |
| 3 | H1 Tags | Checks primary heading |
| 4 | Robots.txt Exists | Verifies crawler directives |
| 5 | Sitemap.xml Exists | Checks site map configuration |
| 6 | Canonical URL | Prevents duplicate content |
| 7 | Favicon | Verifies site icon |
| 8 | Open Graph Tags | Checks social sharing metadata |
| 9 | Structured Data | Verifies Schema.org markup |
| 10 | Viewport Meta Tag | Ensures mobile responsiveness |

### Accessibility & Privacy Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | Image Alt Text | Ensures alt text for screen readers |
| 2 | ARIA Labels | Checks accessibility labels |
| 3 | Semantic HTML | Verifies semantic HTML5 elements |
| 4 | Cookie Security | Checks Secure and HttpOnly flags |
| 5 | Cookies | Detects cookie usage |
| 6 | Tracking Scripts | Identifies analytics & tracking tools |
| 7 | Privacy Policy Link | Verifies privacy policy accessibility |
| 8 | Language Declaration | Checks HTML lang attribute |
| 9 | Form Labels | Verifies form input labels |

### Safety & Verification Checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | HTTP Status Code | Verifies successful page load |
| 2 | Links Found | Counts internal links |
| 3 | External Links | Counts external resources |
| 4 | Redirect Chain | Analyzes redirect efficiency |
| 5 | Server Information | Checks for info disclosure |
| 6 | X-Powered-By Header | Verifies tech stack hiding |
| 7 | Common Misconfigurations | Detects obvious security issues |

## Recommendations & Best Practices

### For Each Check Type:

**🟢 PASS - No Action Needed**
- All best practices are followed
- Security is properly configured
- Performance is optimized

**🟡 WARNING - Consider Improvement**
- Non-critical issues found
- Recommended improvements available
- Follow suggestions for optimization

**🔴 FAIL - Immediate Action Required**
- Critical security/functionality issues
- Must address before production
- Follow detailed recommendations

## Use Cases

1. **Portfolio Project** - Showcase cybersecurity skills on your resume
2. **Website Audit** - Quick security assessment of any public site
3. **Client Reports** - Generate professional security reports
4. **Education** - Learn about web security best practices
5. **Website Monitoring** - Track security posture changes over time
6. **Competitive Analysis** - Compare website security with competitors

## Limitations

- **Analysis only applies to public, legal websites**
- Cannot scan private/internal networks
- No port scanning or network probing
- Cannot perform vulnerability exploitation testing
- Does not test for zero-day vulnerabilities
- Some checks require external APIs (marked as such)
- DNS checks limited to public DNS records
- Performance metrics are from single request (not averaged)

## Security & Privacy

- **Your input URLs are never logged**
- **No data collection or tracking**
- **All analysis performed locally**
- **Results never stored**
- **No third-party data sharing**
- **GDPR compliant**

## Technologies Used

- **Backend**: Node.js, Express.js
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Analysis**: Native Node.js modules (https, dns, url)
- **HTTP Client**: Axios
- **Additional**: Lighthouse (for advanced metrics), Puppeteer (optional for JavaScript rendering)

## Contributing

Feel free to:
- Report bugs
- Suggest new checks
- Improve existing checks
- Optimize performance
- Enhance UI/UX

## License

MIT License - Free to use and modify for personal and commercial projects

## Disclaimer

This tool is designed for educational and authorized security testing purposes only. Users are responsible for ensuring they have permission to analyze any website. The developers are not responsible for misuse of this tool.

## Troubleshooting

### Port 3000 Already in Use
```bash
# Use a different port
PORT=3001 npm start
```

### Timeout Errors
- Check internet connection
- Website may be slow or unreachable
- Try again after a few seconds

### SSL Certificate Errors
- Some self-signed certificates may be flagged
- This is correct security behavior

### DNS Lookup Failures
- Domain may not exist
- DNS server may be unreachable
- Try a different domain

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review detailed check documentation
3. Ensure website is publicly accessible
4. Verify URL format is correct

## Roadmap

Future enhancements:
- [ ] Historical report tracking
- [ ] Batch URL analysis
- [ ] Advanced vulnerability scanning
- [ ] Real user monitoring metrics
- [ ] Lighthouse integration for detailed performance
- [ ] Automated scheduling and alerts
- [ ] Database for storing reports
- [ ] API key authentication
- [ ] Advanced filtering and sorting
- [ ] Comparison reports between URLs

## Resources

- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Google Safe Browsing](https://safebrowsing.google.com/)
- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Web.dev Performance](https://web.dev/performance/)

---

**Made with ❤️ for cybersecurity professionals and web developers**

SiteSentinel - Your Website's Security Sentinel

## UI Updates
- New "Brillance" inspired design
- Serif typography for headings
- Floating pill navigation
