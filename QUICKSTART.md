# Quick Start Guide - SiteSentinel

## 30-Second Setup

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start

# 3. Open browser
http://localhost:3000

# 4. Enter a URL and analyze!
```

## What You Get

A professional website security analysis tool with:
- ✅ 50+ automated security checks
- 📊 Beautiful interactive dashboard
- 🎯 Color-coded results (pass/warning/fail)
- 💯 Overall security score (0-100)
- 📥 Export reports as text files
- 📱 Fully responsive design

## Key Features

### Security Analysis
- SSL/TLS certificate validation
- Security headers verification (CSP, X-Frame-Options, etc.)
- HTTPS enforcement checking
- Mixed content detection
- Certificate expiration alerts

### Domain & DNS
- DNS resolution verification
- MX, SPF, DKIM, DMARC records
- IPv4/IPv6 support checking
- Domain registration validation

### Performance
- Page load time measurement
- Page size analysis
- Resource count optimization
- Compression detection
- Caching configuration

### SEO
- Meta title/description validation
- H1 tag presence
- Robots.txt and Sitemap verification
- Structured data checking
- Mobile viewport validation

### Accessibility & Privacy
- Image alt text coverage
- ARIA labels verification
- Semantic HTML checking
- Cookie security analysis
- Tracking script detection
- Privacy policy verification

### Safety
- HTTP status code validation
- Redirect chain analysis
- Server information exposure
- Common misconfiguration detection

## Useful Commands

```bash
# Development (with auto-reload)
npm run dev

# Use different port
PORT=3001 npm start

# Install new package
npm install package-name
```

## Features Explained

### Overall Score (0-100)
- **80-100**: 🟢 Excellent security posture
- **60-79**: 🔵 Good, some improvements needed
- **40-59**: 🟡 Fair, multiple issues found
- **0-39**: 🔴 Poor, requires attention

### Status Indicators
- ✅ **Pass** - Best practice implemented
- ⚠️ **Warning** - Non-critical issues found
- ❌ **Fail** - Critical issue requiring attention

### Result Categories
All checks are organized into 6 categories:
1. Security & HTTPS
2. Domain & DNS
3. Web Performance
4. SEO & Analytics
5. Accessibility & Privacy
6. Safety & Verification

Each category can be expanded/collapsed for easy navigation.

## How to Use on Your Website

1. **Type any URL** (examples):
   - `example.com`
   - `https://example.com`
   - `www.example.com`

2. **Click "Analyze"** - Wait 10-30 seconds for comprehensive results

3. **Review Results** - See detailed findings for each check

4. **Export Report** - Download results as text file for documentation

## Best Practices

### Security
- ✅ Always use HTTPS
- ✅ Enable security headers
- ✅ Keep certificates updated
- ✅ Implement CSP and HSTS

### Performance
- ✅ Optimize and compress images
- ✅ Minify CSS/JavaScript
- ✅ Enable compression
- ✅ Implement caching

### SEO
- ✅ Write compelling titles (30-60 chars)
- ✅ Add descriptions (120-160 chars)
- ✅ Use one H1 per page
- ✅ Create sitemap and robots.txt

### Accessibility
- ✅ Add alt text to images
- ✅ Use semantic HTML
- ✅ Include ARIA labels
- ✅ Add language declaration

## Troubleshooting

### "Port 3000 is already in use"
```bash
PORT=3001 npm start
```

### "Cannot find module"
```bash
npm install
```

### "Network timeout"
- Check if website is online
- Website might be slow
- Try again after 30 seconds

### SSL Certificate Error
- Some self-signed certs will be flagged (correct)
- This is expected security behavior

## Project Structure

```
Sitesentinel/
├── package.json              # Dependencies
├── server.js                 # Express server
├── analyzer.js               # Analysis engine (50+ checks)
├── public/
│   ├── index.html           # Main interface
│   ├── styles.css           # Styling
│   └── app.js               # Frontend logic
├── README.md                # Full documentation
└── CHECKS_DOCUMENTATION.md  # Detailed check info
```

## What's Safe & Legal

✅ **Safe to use on:**
- Public websites
- Your own websites
- Educational purposes
- Professional audits

✅ **Only uses:**
- Public APIs
- HTTPS requests
- Standard HTTP methods
- No authentication breaking

❌ **Never performs:**
- Port scanning
- Network probing
- Vulnerability exploitation
- Credential testing
- Malware injection

## Next Steps

1. **Analyze your website** to get baseline score
2. **Review failed/warning items** and recommendations
3. **Fix critical issues** (security checks)
4. **Improve performance** (load time, page size)
5. **Optimize SEO** (meta tags, structure)
6. **Re-analyze** to verify improvements

## Tips for Improvement

### Quick Wins
- Enable HSTS header
- Add Cache-Control header
- Set canonical URL
- Add viewport meta tag

### Medium Effort
- Implement CSP header
- Optimize images
- Enable compression
- Add robots.txt/sitemap

### Longer Term
- Improve page load time
- Comprehensive SEO audit
- Full accessibility review
- Performance optimization

## Support

For each check result:
1. Read the explanation
2. Follow the recommendations
3. Check documentation
4. Test implementation
5. Re-analyze to verify

## Educational Value

Perfect for:
- Learning web security
- Understanding SEO basics
- Accessibility best practices
- Performance optimization
- Professional development

## Disclaimer

This tool is designed for authorized analysis of public websites only. Always ensure you have permission to analyze any website.

---

**Ready to start?** → Run `npm install && npm start` then open http://localhost:3000

**Questions?** → Check README.md or CHECKS_DOCUMENTATION.md for detailed information
