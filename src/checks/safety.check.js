/**
 * Safety & Threats Checks
 *
 * Every check below returns the "classic" fields (name, status, description,
 * severity, explanation) for backward compatibility with anything that only
 * reads those, PLUS a structured-evidence shape consumed by the frontend
 * evidence panel and the export report:
 *   id, method, risk, fix, confidence, evidence[] (full list; evidenceTotal is its length - the UI caps display, not the payload)
 * pointsDeducted/maxPoints are added afterwards by
 * score-calculator.util.js#annotateCheckPoints (called from analyze.route.js
 * for every category), not here.
 *
 * THREAT VERDICT TAXONOMY
 * ------------------------
 * The Malware/Phishing Indicators check (and a few related ones) also carry
 * a `verdict` field - a richer classification than the 5-value `status` used
 * for scoring - so the report can distinguish:
 *   - 'confirmed'            a trusted source (Google Safe Browsing) or a
 *                            high-confidence local content analysis found a
 *                            real threat.
 *   - 'security-test'        the URL matches a known security-test
 *                            signature (see security-test-signatures.util.js)
 *                            - e.g. Google's own Safe Browsing test pages.
 *                            Scored exactly like 'confirmed' (a scanner that
 *                            can't recognize its own vendor's test target
 *                            has a real gap), but labeled distinctly so the
 *                            report never reads as an accusation against the
 *                            test provider's real infrastructure.
 *   - 'suspicious'           weaker/heuristic signals, individually or in
 *                            combination, that fall short of confirmation.
 *   - 'none'                 no indicators found.
 *   - 'unable-to-determine'  the live fetch (or, narrowly, a specific data
 *                            source like Google Safe Browsing) could not be
 *                            completed - this is NEVER reported as "safe".
 * `verdict` maps onto the existing `status` (pass/warn/fail/info/error) for
 * scoring purposes: confirmed/security-test -> fail, suspicious -> warn,
 * none -> pass, unable-to-determine -> error (excluded from scoring, same as
 * any other 'error' check - see score-calculator.util.js).
 */

const cheerio = require('cheerio');
const { calculateCategoryScore } = require('../utils/score-calculator.util');
const { classifyDomain } = require('../utils/domain.util');
const {
  attachEvidence,
  buildHeaderEvidence,
  buildDomEvidence,
  buildPatternEvidence,
  buildScriptEvidence,
  buildMixedContentEvidence
} = require('../utils/evidence.util');
const { fetchWithRedirectChain, classifyFetchError } = require('../utils/http.util');
const { matchSecurityTestSignature } = require('../utils/security-test-signatures.util');
const logger = require('../utils/logger.util');

// A plain "note" evidence item for signals that aren't a regex match against
// page text (e.g. "no publisher info found", "suspicious TLD") - keeps every
// contributing signal visible in the evidence list even when there's no
// literal matched string to show.
function noteEvidence(context, matchedRule) {
  return { type: 'note', matchedText: null, context, matchedRule: matchedRule || null };
}

// Shared burner/disposable-domain TLD list used by several heuristics below.
const BURNER_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.icu', '.buzz', '.fun', '.click', '.download', '.loan', '.win'];

class SafetyCheck {
  /**
   * Detect deceptive download page patterns (malware distribution)
   * @param {string} bodyLower - Lowercase page content
   * @param {string} url - The URL being analyzed
   * @param {string} hostname - The hostname
   * @returns {{ isDeceptive: boolean, reason: string, riskScore: number, signals: string[], evidence: object[] }}
   */
  detectDeceptiveDownload(bodyLower, url, hostname) {
    try {
      const signals = [];
      const evidence = [];
      let riskScore = 0;

      // === HIGH-RISK DOWNLOAD LANGUAGE PATTERNS ===
      // Weights are intentionally modest for phrases that also appear on legitimate
      // software/download pages (browsers, open-source releases, CDN mirrors, etc).
      // No single common phrase should be able to push riskScore near the fail
      // threshold on its own - only combinations of several signals should.
      const deceptiveDownloadPhrases = [
        { pattern: /your\s+(free\s+)?download\s+is\s+ready/i, weight: 20, signal: 'Deceptive "download ready" messaging' },
        { pattern: /complete\s+download/i, weight: 15, signal: 'Generic "complete download" prompt' },
        { pattern: /download\s+now/i, weight: 6, signal: '"Download Now" call-to-action' },
        { pattern: /setup\s+file/i, weight: 12, signal: 'Generic "setup file" reference' },
        { pattern: /click\s+(here\s+)?to\s+download/i, weight: 10, signal: 'Click-to-download prompt' },
        { pattern: /start\s+download/i, weight: 8, signal: '"Start download" button' },
        { pattern: /downloading\s+will\s+start/i, weight: 18, signal: 'Auto-download messaging' },
        { pattern: /file\s+is\s+ready/i, weight: 15, signal: 'Generic "file ready" messaging' },
        { pattern: /install(er)?\s+file/i, weight: 10, signal: 'Generic "installer" reference' },
        { pattern: /free\s+installer/i, weight: 20, signal: 'Free installer claim' },
        { pattern: /get\s+your\s+(free\s+)?file/i, weight: 15, signal: 'Generic file delivery language' },
        { pattern: /download\s+manager/i, weight: 10, signal: 'Download manager reference' },
        { pattern: /fast(er)?\s+download/i, weight: 6, signal: 'Fast download claim' },
        { pattern: /secure\s+download/i, weight: 6, signal: 'False security claim on download' },
        { pattern: /direct\s+download/i, weight: 6, signal: 'Direct download claim' },
        { pattern: /one\s+click\s+download/i, weight: 10, signal: 'One-click download claim' }
      ];

      for (const { pattern, weight, signal } of deceptiveDownloadPhrases) {
        const match = pattern.exec(bodyLower);
        if (match) {
          riskScore += weight;
          signals.push(signal);
          evidence.push(buildPatternEvidence(bodyLower, match, {
            contextChars: 150,
            matchedRule: `${signal} — /${pattern.source}/${pattern.flags}`
          }));
        }
      }

      // === MISSING SOFTWARE METADATA (legitimate software always has this) ===
      const hasPublisher = /publisher|developed\s+by|created\s+by|made\s+by|by\s+[A-Z][a-z]+\s+(Inc|LLC|Ltd|Corp)/i.test(bodyLower);
      const hasVersion = /version\s*[\d.]+|v[\d.]+|release\s+[\d.]+/i.test(bodyLower);
      const hasLicense = /(license|eula|terms\s+of\s+(service|use)|privacy\s+policy|copyright)/i.test(bodyLower);

      if (!hasPublisher && signals.length > 0) {
        riskScore += 20;
        signals.push('No software publisher/vendor identified');
        evidence.push(noteEvidence('No publisher/developer attribution found anywhere on the page', 'missing publisher check'));
      }
      if (!hasVersion && signals.length > 0) {
        riskScore += 15;
        signals.push('No software version information');
        evidence.push(noteEvidence('No version number found anywhere on the page', 'missing version check'));
      }
      if (!hasLicense && signals.length > 0) {
        riskScore += 15;
        signals.push('No license or legal information');
        evidence.push(noteEvidence('No license/EULA/terms/privacy-policy text found anywhere on the page', 'missing license check'));
      }

      // === URL PATH ANALYSIS ===
      const urlPath = new URL(url).pathname;

      // Long hex/hash-like paths are extremely suspicious
      const hashPattern = /\/[a-f0-9]{24,}$/i;
      const longRandomPath = /\/[a-zA-Z0-9]{32,}$/;

      const hashMatch = hashPattern.exec(urlPath);
      const longRandomMatch = !hashMatch ? longRandomPath.exec(urlPath) : null;
      if (hashMatch) {
        riskScore += 35;
        signals.push('Hash-like obfuscated URL path (high risk)');
        evidence.push(buildPatternEvidence(urlPath, hashMatch, { matchedRule: 'hash-like URL path /\\/[a-f0-9]{24,}$/' }));
      } else if (longRandomMatch) {
        riskScore += 30;
        signals.push('Long random/obfuscated URL path');
        evidence.push(buildPatternEvidence(urlPath, longRandomMatch, { matchedRule: 'long random URL path /\\/[a-zA-Z0-9]{32,}$/' }));
      }

      // Short UUID-like paths also suspicious in download context
      const uuidPattern = /\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i;
      const uuidMatch = uuidPattern.exec(urlPath);
      if (uuidMatch && signals.length > 0) {
        riskScore += 15;
        signals.push('UUID-based tracking URL');
        evidence.push(buildPatternEvidence(urlPath, uuidMatch, { matchedRule: 'UUID in URL path' }));
      }

      // === DOMAIN ANALYSIS ===
      // Only single-purpose file-sharing/dropper domains here - deliberately excludes
      // generic dictionary words like "get"/"file"/"soft"/"setup" which appear in the
      // names of countless legitimate sites (getpocket.com, filezilla.org, etc) and
      // were previously causing false positives on unrelated domains.
      const suspiciousDownloadDomains = [
        'getflux', 'dlfile', 'filehost', 'uploadhaven',
        'mediafire', '4shared', 'zippyshare'
      ];

      const domainLower = hostname.toLowerCase();
      // Only count a domain-name match as a signal if we already have other
      // page-content evidence - the domain name alone is too weak on its own.
      if (signals.length > 0) {
        for (const keyword of suspiciousDownloadDomains) {
          if (domainLower.includes(keyword)) {
            riskScore += 15;
            signals.push(`Domain contains "${keyword}" - common in file-dropper networks`);
            evidence.push(noteEvidence(`Hostname "${hostname}" contains "${keyword}"`, 'file-dropper domain keyword list'));
            break;
          }
        }
      }

      // Short-lived/burner domain patterns
      for (const tld of BURNER_TLDS) {
        if (hostname.endsWith(tld)) {
          riskScore += 15;
          signals.push(`Suspicious TLD "${tld}" common with disposable domains`);
          evidence.push(noteEvidence(`Hostname "${hostname}" ends with "${tld}"`, 'burner TLD list'));
          break;
        }
      }

      // === EXECUTABLE DOWNLOAD DETECTION ===
      // Only match executables referenced by actual href/download attributes - a bare
      // ".exe" mention anywhere in the page text (e.g. a tech article, changelog, or
      // system-requirements blurb) is not evidence of an executable being served.
      const executablePatterns = [
        /href\s*=\s*["'][^"']*\.(exe|msi|dmg|pkg|deb|rpm|appimage|bat|cmd|ps1|vbs|js)["']/i,
        /download\s*=\s*["'][^"']*\.(exe|msi|dmg|pkg|bat|cmd)["']/i
      ];

      let hasExecutable = false;
      for (const pattern of executablePatterns) {
        const match = pattern.exec(bodyLower);
        if (match) {
          hasExecutable = true;
          evidence.push(buildPatternEvidence(bodyLower, match, { matchedRule: 'executable file reference in href/download attribute' }));
          break;
        }
      }

      if (hasExecutable && signals.length > 0) {
        riskScore += 25;
        signals.push('Executable file download detected');
      }

      // === FAKE DOWNLOAD GATING PATTERNS ===
      // Bounded proximity (.{0,N}) instead of unbounded .* - an unbounded wildcard
      // can bridge two unrelated words anywhere on a large page (e.g. "waiting" in
      // one section and "download" in an unrelated app-store badge much later),
      // producing false matches on long, content-rich pages.
      const gatingPatterns = [
        { pattern: /step\s*1[\s\S]{0,200}step\s*2/i, signal: 'Fake multi-step download process' },
        { pattern: /waiting.{0,20}seconds?.{0,40}download/i, signal: 'Fake countdown timer' },
        { pattern: /please\s+wait.{0,40}download/i, signal: 'Fake waiting prompt' },
        { pattern: /generating.{0,20}link/i, signal: 'Fake link generation' },
        { pattern: /preparing.{0,20}download/i, signal: 'Fake preparation message' }
      ];

      for (const { pattern, signal } of gatingPatterns) {
        const match = pattern.exec(bodyLower);
        if (match) {
          riskScore += 20;
          signals.push(signal);
          evidence.push(buildPatternEvidence(bodyLower, match, { contextChars: 150, matchedRule: `${signal} — /${pattern.source}/` }));
        }
      }

      // === PAGE CONTENT ANALYSIS ===
      // Check for minimal page content (malware pages are often sparse)
      const textContent = bodyLower.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      const wordCount = textContent.split(' ').filter(w => w.length > 2).length;

      if (wordCount < 50 && signals.length >= 2) {
        riskScore += 15;
        signals.push('Sparse page content typical of malware distribution');
        evidence.push(noteEvidence(`Page has only ~${wordCount} words of text content`, 'sparse content check (<50 words)'));
      }

      // === DETERMINE FINAL CLASSIFICATION ===
      const isDeceptive = riskScore >= 50;

      let reason = '';
      if (isDeceptive) {
        if (riskScore >= 80) {
          reason = 'DANGER: High-confidence malware distribution page detected';
        } else if (riskScore >= 65) {
          reason = 'WARNING: Likely deceptive download page - exercise extreme caution';
        } else {
          reason = 'WARNING: Suspicious download page with multiple red flags';
        }
      }

      return { isDeceptive, reason, riskScore, signals, evidence };
    } catch (err) {
      logger.error('Error in detectDeceptiveDownload:', err.message);
      return { isDeceptive: false, reason: '', riskScore: 0, signals: [], evidence: [] };
    }
  }

  /**
   * Detect scam/phishing content patterns in page body.
   *
   * Weighted and combined, like detectDeceptiveDownload: no single pattern
   * match is enough on its own (e.g. a "claim your reward" loyalty-program
   * phrase, or a sale countdown timer) - only a combination that adds up to
   * SCAM_THRESHOLD, such as a fake-virus alert plus a tech-support phone
   * number, is treated as a real signal. All proximity checks are bounded
   * (`.{0,N}` instead of an unbounded `.*`) so two words can't be matched
   * together just because they both happen to appear somewhere on a large page.
   *
   * @param {string} bodyLower - Lowercase page content
   * @param {string} url - The URL being analyzed
   * @returns {{ isScam: boolean, reason: string, score: number, evidence: object[] }}
   */
  detectScamContent(bodyLower, url) {
    try {
      const SCAM_THRESHOLD = 45;

      const scamSignals = [
        // Fake virus/security alerts and tech-support scams - high confidence on their own
        { pattern: /your.{0,30}(account|computer|device).{0,30}(has been|is).{0,20}(compromised|hacked|infected)/i, weight: 50, signal: 'Fake security warning ("your ... has been compromised/hacked/infected")' },
        { pattern: /(virus|malware).{0,20}detected.{0,30}(computer|device|system)/i, weight: 50, signal: 'Fake virus-detected alert' },
        { pattern: /call.{0,15}\d{3}[-.\s]?\d{3}[-.\s]?\d{4}.{0,20}immediately/i, weight: 45, signal: 'Tech-support scam phone number with urgency' },
        { pattern: /microsoft.{0,20}support.{0,20}call/i, weight: 45, signal: 'Fake Microsoft support call prompt' },
        { pattern: /apple.{0,20}support.{0,20}call/i, weight: 45, signal: 'Fake Apple support call prompt' },
        { pattern: /do\s+not\s+(close|restart|turn\s+off).{0,30}(computer|device|browser)/i, weight: 35, signal: 'Fake "do not close your computer" warning' },
        // Software-update social-engineering (fake update prompts used to trick users
        // into installing something) - a real, common phishing/malvertising pattern.
        { pattern: /software.{0,15}(is\s+)?out.?of.?date/i, weight: 30, signal: 'Fake "software is out of date" social-engineering prompt' },
        { pattern: /(update|upgrade).{0,15}(is\s+)?required.{0,20}(to\s+)?continue/i, weight: 25, signal: 'Fake "update required to continue" prompt' },
        { pattern: /does\s+not\s+(actually\s+)?originate\s+from/i, weight: 15, signal: 'Text disclaiming a fake vendor dialogue (social-engineering description)' },
        // Prize / financial urgency - weaker alone, since similar phrasing shows up
        // in legitimate marketing and loyalty programs
        { pattern: /congratulations.{0,20}you.{0,20}(won|winner|selected)/i, weight: 25, signal: 'Prize/lottery-style congratulations message' },
        { pattern: /claim.{0,15}your.{0,15}(prize|reward|gift)/i, weight: 12, signal: '"Claim your prize/reward" language (common in legitimate loyalty programs too)' },
        { pattern: /verify.{0,15}your.{0,15}(identity|account).{0,20}immediately/i, weight: 30, signal: 'Urgent identity/account verification demand' },
        { pattern: /your.{0,15}password.{0,10}expired/i, weight: 20, signal: 'Password-expired phishing language' },
        { pattern: /unusual.{0,15}activity.{0,15}your.{0,15}account/i, weight: 20, signal: 'Account activity phishing language' },
        { pattern: /suspended.{0,15}account.{0,15}verify/i, weight: 25, signal: 'Account suspension phishing language' },
        { pattern: /bitcoin.{0,15}double|double.{0,15}bitcoin/i, weight: 40, signal: 'Cryptocurrency-doubling scam language' },
        { pattern: /send.{0,15}btc.{0,15}receive.{0,15}double/i, weight: 45, signal: 'Cryptocurrency-doubling scam instructions' },
        { pattern: /click.{0,15}here.{0,15}verify.{0,15}identity/i, weight: 20, signal: 'Click-to-verify-identity phishing prompt' },
        // Countdown/urgency timers alone are near-zero weight - routine e-commerce
        // "deal ends in" widgets should never be able to trigger this on their own.
        { pattern: /(offer|deal|sale|price).{0,10}ends?.{0,15}in.{0,20}(\d+|hours?|minutes?)/i, weight: 5, signal: 'Countdown/urgency timer (routine e-commerce pattern, not inherently suspicious on its own)' }
      ];

      const matchedSignals = [];
      const evidence = [];
      let score = 0;

      for (const { pattern, weight, signal } of scamSignals) {
        const match = pattern.exec(bodyLower);
        if (match) {
          score += weight;
          matchedSignals.push(signal);
          evidence.push(buildPatternEvidence(bodyLower, match, {
            contextChars: 150,
            matchedRule: `${signal} (weight ${weight}) — /${pattern.source}/`
          }));
        }
      }

      const isScam = score >= SCAM_THRESHOLD;
      const reason = isScam
        ? `WARNING: Combined scam/phishing signals (score ${score}/${SCAM_THRESHOLD} threshold): ${matchedSignals.join('; ')}`
        : '';

      return { isScam, reason, score, evidence, matchedSignals };
    } catch (err) {
      logger.error('Error in detectScamContent:', err.message);
      return { isScam: false, reason: '', score: 0, evidence: [], matchedSignals: [] };
    }
  }

  /**
   * Scans inline <script> bodies for common obfuscation/packer patterns used
   * to hide malicious payloads from casual inspection (and from simple
   * text-based scanners). Weighted/combined like the other detectors above -
   * eval() alone is far too common in legitimate code to mean anything by
   * itself; it's the COMBINATION with unescape/fromCharCode/atob, or a dense
   * run of hex/unicode escapes, that's the real signal.
   */
  detectObfuscatedScripts($, rawHtml) {
    try {
      const evidence = [];
      const signals = [];
      let score = 0;

      const inlineScripts = $('script:not([src])').toArray();
      for (const el of inlineScripts) {
        const content = $(el).html() || '';
        if (!content.trim()) continue;

        const hasEval = /\beval\s*\(/i.test(content);
        const hasUnescape = /\bunescape\s*\(/i.test(content);
        const hasFromCharCode = /String\.fromCharCode\s*\(/i.test(content);
        const hasAtob = /\batob\s*\(/i.test(content);
        const hasDocWriteUnescape = /document\.write\s*\(\s*unescape\s*\(/i.test(content);
        const hexEscapeCount = (content.match(/\\x[0-9a-f]{2}/gi) || []).length;
        const unicodeEscapeCount = (content.match(/\\u[0-9a-f]{4}/gi) || []).length;
        const isDenseSingleLine = content.length > 400 && content.split('\n').length <= 2;

        let scriptScore = 0;
        const scriptSignals = [];

        if (hasDocWriteUnescape) {
          scriptScore += 50;
          scriptSignals.push('document.write(unescape(...)) - classic exploit-kit injection pattern');
        }
        if (hasEval && (hasUnescape || hasFromCharCode || hasAtob)) {
          scriptScore += 40;
          scriptSignals.push('eval() combined with unescape/String.fromCharCode/atob - common JS packer/deobfuscation pattern');
        } else if (hasEval) {
          scriptScore += 8;
          scriptSignals.push('eval() present (weak signal alone - used by some legitimate bundlers/libraries)');
        }
        if (hexEscapeCount > 20) {
          scriptScore += 25;
          scriptSignals.push(`${hexEscapeCount} "\\x" hex-escape sequences - typical of obfuscated payloads`);
        }
        if (unicodeEscapeCount > 20) {
          scriptScore += 20;
          scriptSignals.push(`${unicodeEscapeCount} "\\u" unicode-escape sequences - typical of obfuscated payloads`);
        }
        if (isDenseSingleLine && (hasEval || hexEscapeCount > 5 || unicodeEscapeCount > 5)) {
          scriptScore += 15;
          scriptSignals.push('dense single-line script combined with escape sequences/eval');
        }

        if (scriptScore > 0) {
          score += scriptScore;
          signals.push(...scriptSignals);
          const domEvidence = buildDomEvidence($, el, rawHtml, 'inline script with obfuscation indicators');
          evidence.push({ ...domEvidence, matchedRule: scriptSignals.join('; ') });
        }
      }

      return { isObfuscated: score >= 40, score, signals, evidence };
    } catch (err) {
      logger.error('Error in detectObfuscatedScripts:', err.message);
      return { isObfuscated: false, score: 0, signals: [], evidence: [] };
    }
  }

  /**
   * Flags external iframes that are hidden (zero-size or display:none/
   * visibility:hidden) or point at a suspicious-TLD domain - both classic
   * drive-by/clickjacking patterns, and a meaningfully stronger signal than
   * "an external iframe exists" (which the separate Iframe Usage check
   * already reports as routine and low-severity).
   */
  detectSuspiciousIframes($, finalUrl, hostname, rawHtml) {
    try {
      const evidence = [];
      const signals = [];
      let score = 0;

      $('iframe').each((i, el) => {
        const $el = $(el);
        const src = $el.attr('src');
        if (!src) return;
        let iframeHostname;
        try {
          iframeHostname = new URL(src, finalUrl).hostname;
        } catch (e) {
          return;
        }
        if (iframeHostname === hostname) return; // same-site, not external

        const width = ($el.attr('width') || '').replace(/px/i, '').trim();
        const height = ($el.attr('height') || '').replace(/px/i, '').trim();
        const style = ($el.attr('style') || '').toLowerCase();
        const isHidden = width === '0' || height === '0' ||
          /display\s*:\s*none/.test(style) || /visibility\s*:\s*hidden/.test(style) ||
          /width\s*:\s*0/.test(style) || /height\s*:\s*0/.test(style);
        const hasSuspiciousTld = BURNER_TLDS.some(tld => iframeHostname.endsWith(tld));

        if (isHidden) {
          score += 35;
          signals.push(`Hidden/zero-size external iframe pointing to ${iframeHostname} - a common clickjacking/drive-by pattern`);
          evidence.push({ ...buildDomEvidence($, el, rawHtml, `hidden external iframe (${iframeHostname})`), matchedRule: 'hidden/zero-size iframe' });
        } else if (hasSuspiciousTld) {
          score += 15;
          signals.push(`External iframe pointing to a suspicious-TLD domain (${iframeHostname})`);
          evidence.push({ ...buildDomEvidence($, el, rawHtml, `iframe with suspicious-TLD src (${iframeHostname})`), matchedRule: 'suspicious-TLD iframe src' });
        }
      });

      return { isSuspicious: score >= 30, score, signals, evidence };
    } catch (err) {
      logger.error('Error in detectSuspiciousIframes:', err.message);
      return { isSuspicious: false, score: 0, signals: [], evidence: [] };
    }
  }

  /**
   * Looks for suspicious patterns in the redirect chain actually followed to
   * reach the final page (captured by http.util.js#fetchWithRedirectChain):
   * an unusually long chain, a hop through a suspicious-TLD domain, or a
   * chain that crosses multiple different domains before landing somewhere
   * different from where it started. Any one of these alone is fairly weak
   * (legitimate URL shorteners and domain migrations do this too), which is
   * why this only becomes a signal in combination (see scoring below).
   */
  analyzeRedirectChain(redirectChain, originalHostname, finalHostname) {
    try {
      if (!redirectChain || redirectChain.length === 0) {
        return { isSuspicious: false, score: 0, signals: [], evidence: [] };
      }

      let score = 0;
      const signals = [];
      const evidence = redirectChain.map(hop => noteEvidence(`${hop.url} → HTTP ${hop.status}`, 'redirect hop'));

      if (redirectChain.length >= 3) {
        score += 20;
        signals.push(`Long redirect chain (${redirectChain.length} hops) - can be used to obscure the true destination`);
      }

      const hopHostnames = redirectChain
        .map(hop => { try { return new URL(hop.url).hostname; } catch { return null; } })
        .filter(Boolean);
      const suspiciousHop = hopHostnames.find(h => BURNER_TLDS.some(tld => h.endsWith(tld)));
      if (suspiciousHop) {
        score += 30;
        signals.push(`Redirect chain passes through a suspicious-TLD domain (${suspiciousHop})`);
      }

      if (originalHostname !== finalHostname && redirectChain.length >= 2) {
        score += 10;
        signals.push(`Redirect chain crosses multiple domains before landing on a different final domain (${originalHostname} → ${finalHostname})`);
      }

      return { isSuspicious: score >= 30, score, signals, evidence };
    } catch (err) {
      logger.error('Error in analyzeRedirectChain:', err.message);
      return { isSuspicious: false, score: 0, signals: [], evidence: [] };
    }
  }

  /**
   * Detect credential harvesting patterns.
   *
   * Two tiers:
   *  - Strong/standalone signals (brand-impersonation login text, or a form
   *    field explicitly asking for a card/CVV/SSN) still trigger on their
   *    own, as before.
   *  - A bare login form on a domain outside the small known-brand allowlist
   *    is, BY ITSELF, only a very weak signal - most legitimate websites
   *    have their own login form. It's only escalated to a real finding when
   *    combined with corroborating signals (self-describing phishing/
   *    social-engineering text, obfuscated JS elsewhere on the page, a
   *    hidden iframe, or a suspicious-TLD domain) - see extraSignals.
   *
   * @param {string} bodyLower - Lowercase page content
   * @param {string} hostname - The hostname being analyzed
   * @param {{ obfuscatedJs?: boolean, hiddenIframe?: boolean, suspiciousTld?: boolean }} extraSignals
   * @returns {{ isHarvesting: boolean, reason: string, evidence: object[] }}
   */
  detectCredentialHarvesting(bodyLower, hostname, extraSignals = {}) {
    try {
      const evidence = [];
      const hasLoginForm = /type\s*=\s*["']?password/i.test(bodyLower);
      // Only flag "sensitive fields" when there's an actual <input> element whose
      // name/id/placeholder/autocomplete attribute references a card number, CVV, or
      // SSN - not just those words appearing anywhere in the page text. An earlier
      // version matched bare "expir" against any page mentioning "expires"/
      // "expiration" (session timeouts, sale countdowns, subscription notices, etc.),
      // which made this fire on a huge fraction of ordinary websites.
      const sensitiveFieldPattern = /<input[^>]*(?:name|id|placeholder|autocomplete)\s*=\s*["'][^"']*(social.?security|ssn|credit.?card|card.?number|cc.?number|cvv|cvc|card.?cvc)[^"']*["']/i;
      const sensitiveFieldMatch = sensitiveFieldPattern.exec(bodyLower);
      const hasSensitiveFields = !!sensitiveFieldMatch;

      // Known legitimate login domains
      const legitimateLoginDomains = [
        'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'paypal.com', 'github.com', 'twitter.com', 'linkedin.com',
        'accounts.google.com', 'login.microsoft.com', 'appleid.apple.com'
      ];

      const isLegitDomain = legitimateLoginDomains.some(d => hostname.includes(d));

      if (hasLoginForm && !isLegitDomain) {
        // Strong signal: explicit brand impersonation
        const brandPatterns = [
          { brand: 'google', pattern: /google.*sign.*in|sign.*in.*google/i },
          { brand: 'facebook', pattern: /facebook.*log.*in|log.*in.*facebook/i },
          { brand: 'microsoft', pattern: /microsoft.*sign.*in|outlook.*sign.*in/i },
          { brand: 'apple', pattern: /apple.*id.*sign|icloud.*sign/i },
          { brand: 'paypal', pattern: /paypal.*log.*in/i },
          { brand: 'amazon', pattern: /amazon.*sign.*in/i }
        ];

        for (const { brand, pattern } of brandPatterns) {
          const brandMatch = pattern.exec(bodyLower);
          if (brandMatch && !hostname.includes(brand)) {
            evidence.push(buildPatternEvidence(bodyLower, brandMatch, { matchedRule: `${brand} brand-impersonation text on non-${brand} domain` }));
            return {
              isHarvesting: true,
              reason: `DANGER: Potential ${brand.charAt(0).toUpperCase() + brand.slice(1)} credential phishing - login form on non-${brand} domain`,
              evidence,
              tier: 'brand-impersonation'
            };
          }
        }
      }

      if (hasSensitiveFields && !isLegitDomain) {
        evidence.push(buildPatternEvidence(bodyLower, sensitiveFieldMatch, { matchedRule: 'sensitive <input> field (card/CVV/SSN) via name/id/placeholder/autocomplete' }));

        // If it's a known e-commerce/retail domain, treat as notice not fail
        const knownRetailDomains = [
          'walmart.com', 'target.com', 'bestbuy.com', 'amazon.com', 'costco.com', 'homedepot.com', 'lowes.com', 'macys.com', 'kohls.com', 'wayfair.com', 'ebay.com', 'apple.com', 'nike.com', 'adidas.com', 'sephora.com', 'ulta.com', 'walgreens.com', 'cvs.com', 'samsclub.com', 'bjs.com', 'staples.com', 'officedepot.com', 'gamestop.com', 'bedbathandbeyond.com', 'bloomingdales.com', 'nordstrom.com', 'jcpenney.com', 'dickssportinggoods.com', 'petco.com', 'petsmart.com', 'chewy.com', 'guitarcenter.com', 'rei.com', 'zappos.com', 'overstock.com', 'newegg.com', 'bhphotovideo.com', 'microcenter.com', 'barnesandnoble.com', 'verizon.com', 'att.com', 't-mobile.com', 'sprint.com', 'boostmobile.com', 'cricketwireless.com', 'dish.com', 'directv.com', 'xfinity.com', 'spectrum.com', 'comcast.com', 'hulu.com', 'netflix.com', 'disneyplus.com', 'hbomax.com', 'paramountplus.com', 'peacocktv.com', 'sling.com', 'fubo.tv', 'philo.com', 'youtube.com', 'roku.com', 'playstation.com', 'xbox.com', 'nintendo.com', 'steam.com', 'epicgames.com', 'target.com', 'instacart.com', 'shipt.com', 'doordash.com', 'ubereats.com', 'grubhub.com', 'opentable.com', 'expedia.com', 'booking.com', 'hotels.com', 'airbnb.com', 'vrbo.com', 'marriott.com', 'hilton.com', 'hyatt.com'
        ];
        const isRetail = knownRetailDomains.some(d => hostname.endsWith(d));
        if (isRetail) {
          return {
            isHarvesting: false,
            reason: 'NOTICE: Page requests sensitive information (SSN/credit card) on a known retail or e-commerce domain.',
            evidence
          };
        }
        return {
          isHarvesting: true,
          reason: 'WARNING: Page requests sensitive information (SSN/credit card) on untrusted domain',
          evidence,
          tier: 'sensitive-fields'
        };
      }

      // Weak/generic tier: a bare login form outside the known-brand allowlist is
      // NOT suspicious on its own (most real sites have one) - only escalate when
      // combined with corroborating signals found elsewhere on the page.
      if (hasLoginForm && !isLegitDomain) {
        let score = 15;
        const signals = ['Login form present on a domain outside the known major-brand allowlist (weak alone - most legitimate sites have their own login form)'];

        const selfDescribingPattern = /\b(phishing|social engineering)\b[\s\S]{0,60}\b(example|test|demo)\b|\b(example|test|demo)\b[\s\S]{0,60}\b(phishing|social engineering)\b/i;
        const selfDescribingMatch = selfDescribingPattern.exec(bodyLower);
        if (selfDescribingMatch) {
          score += 50;
          signals.push('Page text explicitly describes itself as a phishing/social-engineering example');
          evidence.push(buildPatternEvidence(bodyLower, selfDescribingMatch, { matchedRule: 'self-describing phishing/social-engineering example text' }));
        }
        if (extraSignals.obfuscatedJs) {
          score += 20;
          signals.push('Obfuscated JavaScript present alongside an untrusted login form');
        }
        if (extraSignals.hiddenIframe) {
          score += 20;
          signals.push('Hidden/suspicious iframe present alongside an untrusted login form');
        }
        if (extraSignals.suspiciousTld) {
          score += 15;
          signals.push('Untrusted login form on a domain with a suspicious TLD');
        }

        if (score >= 50) {
          evidence.push(noteEvidence(`Combined credential-harvesting signal score: ${score}/100`, 'weighted generic-login-form scoring'));
          return {
            isHarvesting: true,
            reason: `WARNING: Untrusted login form combined with corroborating signals: ${signals.join('; ')}`,
            evidence,
            tier: 'generic-login-form'
          };
        }
      }

      return { isHarvesting: false, reason: '', evidence: [] };
    } catch (err) {
      logger.error('Error in detectCredentialHarvesting:', err.message);
      return { isHarvesting: false, reason: '', evidence: [] };
    }
  }

  async analyze(url) {
    const checks = [];
    const hostname = new URL(url).hostname;
    let analysisError = null;

    // Security-test signature matching works on the URL alone - independent of
    // whether the live fetch below succeeds. This is deliberate: a known test
    // domain like malware.testing.google.test can fail to resolve via public DNS
    // while still being a recognized test target - those are separate facts, and
    // conflating "couldn't fetch it" with "not a test target" would be wrong.
    const securityTestMatch = matchSecurityTestSignature(url);

    try {
      const { response, finalUrl, statusCode, redirectChain } = await fetchWithRedirectChain(url, { timeout: 15000, maxRedirects: 5 });

      const headers = response.headers;
      const body = response.data ? String(response.data) : '';
      const bodyLower = body.toLowerCase();
      const isHttps = finalUrl.startsWith('https://');
      const $ = cheerio.load(body);
      const finalHostname = (() => { try { return new URL(finalUrl).hostname; } catch { return hostname; } })();

      const requestContext = { headers, finalUrl, statusCode, redirectChain };

      // 1. Deceptive Download / Malware Distribution Detection (HIGHEST PRIORITY)
      let deceptiveDownload = { isDeceptive: false, reason: '', riskScore: 0, signals: [], evidence: [] };
      try {
        deceptiveDownload = this.detectDeceptiveDownload(bodyLower, url, hostname);
      } catch (ddErr) {
        logger.error('Deceptive download detection failed:', ddErr.message);
      }

      // 2. Scam/Phishing Content Detection - Isolated with try/catch
      let scamDetection = { isScam: false, reason: '', evidence: [] };
      try {
        scamDetection = this.detectScamContent(bodyLower, url);
      } catch (scamErr) {
        logger.error('Scam detection failed:', scamErr.message);
      }

      // 2b. Obfuscated inline JavaScript
      let obfuscatedScripts = { isObfuscated: false, score: 0, signals: [], evidence: [] };
      try {
        obfuscatedScripts = this.detectObfuscatedScripts($, body);
      } catch (obErr) {
        logger.error('Obfuscated script detection failed:', obErr.message);
      }

      // 2c. Suspicious (hidden/suspicious-TLD) iframes
      let suspiciousIframesResult = { isSuspicious: false, score: 0, signals: [], evidence: [] };
      try {
        suspiciousIframesResult = this.detectSuspiciousIframes($, finalUrl, hostname, body);
      } catch (ifErr) {
        logger.error('Suspicious iframe detection failed:', ifErr.message);
      }

      // 2d. Redirect chain analysis
      let redirectChainResult = { isSuspicious: false, score: 0, signals: [], evidence: [] };
      try {
        redirectChainResult = this.analyzeRedirectChain(redirectChain, hostname, finalHostname);
      } catch (rcErr) {
        logger.error('Redirect chain analysis failed:', rcErr.message);
      }

      // === 3. COMBINE EVERYTHING INTO ONE THREAT VERDICT ===
      // Priority order (highest first): security-test signature > confirmed
      // (Google Safe Browsing or high-confidence local content) > suspicious
      // (weighted combination of weaker signals) > none.
      let verdict, malwareCheckStatus, threatCategory, detectionSource;
      let detectionDetails = '';
      let detectionMethod = '';
      let detectionEvidence = [];
      let confidenceLevel = 'high';
      let confidenceNote;
      let gsbStatus = 'not-attempted'; // 'not-configured' | 'error' | 'clean' | 'flagged'

      if (securityTestMatch) {
        verdict = 'security-test';
        malwareCheckStatus = 'fail';
        threatCategory = securityTestMatch.threatCategory;
        detectionSource = securityTestMatch.provider;
        detectionDetails = `SECURITY TEST TARGET: ${securityTestMatch.message}`;
        detectionMethod = 'Matched against the security-test signature registry (security-test-signatures.util.js) - a maintained table of known Safe Browsing test URLs/domains, matched by hostname + path pattern.';
        detectionEvidence = [noteEvidence(`Matched signature "${securityTestMatch.id}" (${securityTestMatch.provider})`, 'security-test-signatures.util.js')];
        confidenceLevel = 'high';
      } else {
        let highConfidence = deceptiveDownload.isDeceptive || scamDetection.isScam;
        let malwareDetected = highConfidence;
        detectionDetails = deceptiveDownload.reason || scamDetection.reason;
        detectionEvidence = [...(deceptiveDownload.evidence || []), ...(scamDetection.evidence || [])];
        detectionMethod = 'Content pattern analysis (deceptive-download scoring + weighted scam-content matching)';
        detectionSource = 'Local Content Analysis';
        threatCategory = deceptiveDownload.isDeceptive ? 'malware' : (scamDetection.isScam ? 'phishing' : 'none');

        // Google Safe Browsing API, if configured - an independent, authoritative
        // signal checked regardless of what local analysis already found (unless a
        // security-test signature already matched above, which takes priority for
        // labeling purposes and makes an extra API round-trip unnecessary).
        const gsApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
        if (!gsApiKey) {
          gsbStatus = 'not-configured';
        } else {
          try {
            const axios = require('axios');
            const gsPayload = {
              client: { clientId: 'sitesentinel', clientVersion: '2.0.0' },
              threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
              }
            };
            const gsUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsApiKey}`;
            const gsResp = await axios.post(gsUrl, gsPayload, { timeout: 10000 });
            if (gsResp.data && Object.keys(gsResp.data).length > 0) {
              gsbStatus = 'flagged';
              malwareDetected = true;
              highConfidence = true;
              detectionDetails = 'DANGER: Google Safe Browsing flagged this site for malware or phishing';
              detectionMethod = 'Google Safe Browsing API (threatMatches:find)';
              detectionSource = 'Google Safe Browsing';
              detectionEvidence = [noteEvidence(JSON.stringify(gsResp.data).slice(0, 300), 'Google Safe Browsing threatMatches response')];
              threatCategory = (gsResp.data.matches?.[0]?.threatType || 'malware').toLowerCase();
            } else {
              gsbStatus = 'clean';
            }
          } catch (err) {
            gsbStatus = 'error';
            logger.warn('Google Safe Browsing API call failed:', err.message);
          }
        }

        // Local heuristic layers - weaker signals, never allowed to fail this check
        // on their own (only warn), since they're the most false-positive-prone.
        let lowConfidenceDetected = false;
        const lowConfidenceSignals = [];

        if (!malwareDetected) {
          try {
            if (this.detectPhishingIndicators(url, hostname)) {
              lowConfidenceDetected = true;
              lowConfidenceSignals.push('Local heuristic: URL-shape analysis (obfuscated paths) and Levenshtein-distance typosquat detection against known brand domains');
            }
          } catch (phishErr) {
            logger.error('Phishing detection failed:', phishErr.message);
          }
        }
        if (!malwareDetected) {
          try {
            const domainCheck = this.checkDomainReputation(hostname, url);
            if (domainCheck.isSuspicious) {
              lowConfidenceDetected = true;
              lowConfidenceSignals.push(`Local heuristic: domain-name pattern matching - ${domainCheck.reason}`);
            }
          } catch (domainErr) {
            logger.error('Domain reputation check failed:', domainErr.message);
          }
        }
        if (!malwareDetected && obfuscatedScripts.isObfuscated) {
          lowConfidenceDetected = true;
          lowConfidenceSignals.push(`Obfuscated JavaScript: ${obfuscatedScripts.signals.join('; ')}`);
          detectionEvidence.push(...obfuscatedScripts.evidence);
        }
        if (!malwareDetected && suspiciousIframesResult.isSuspicious) {
          lowConfidenceDetected = true;
          lowConfidenceSignals.push(`Suspicious iframe: ${suspiciousIframesResult.signals.join('; ')}`);
          detectionEvidence.push(...suspiciousIframesResult.evidence);
        }
        if (!malwareDetected && redirectChainResult.isSuspicious) {
          lowConfidenceDetected = true;
          lowConfidenceSignals.push(`Redirect chain: ${redirectChainResult.signals.join('; ')}`);
          detectionEvidence.push(...redirectChainResult.evidence);
        }

        if (highConfidence) {
          verdict = 'confirmed';
          malwareCheckStatus = 'fail';
          confidenceLevel = 'high';
        } else if (lowConfidenceDetected) {
          verdict = 'suspicious';
          malwareCheckStatus = 'warn';
          confidenceLevel = 'low';
          detectionDetails = `WARNING: Suspicious indicators detected (not confirmed): ${lowConfidenceSignals.join(' | ')}`;
          detectionMethod = 'Weighted combination of local heuristics: URL-shape/typosquat analysis, domain-name pattern matching, inline-script obfuscation, hidden/suspicious iframes, and redirect-chain analysis. None of these can fail this check alone.';
          threatCategory = 'suspicious';
          confidenceNote = 'These are local heuristic matches, not a confirmed detection from a trusted threat-intelligence source - they can occasionally match unrelated legitimate sites. Treat this as worth a manual look, not a confirmed verdict.';
        } else {
          verdict = 'none';
          malwareCheckStatus = 'pass';
          threatCategory = 'none';
          if (gsbStatus === 'error') {
            confidenceLevel = 'medium';
            detectionDetails = 'No malware or phishing indicators found by local analysis. Google Safe Browsing could not be reached, so this is not a complete threat-intelligence check.';
            confidenceNote = 'The Google Safe Browsing API call failed (network/API error) - this result reflects local analysis only, not a full threat-intelligence check. Treat as informative, not authoritative.';
          } else if (gsbStatus === 'not-configured') {
            confidenceLevel = 'medium';
            detectionDetails = 'No malware or phishing indicators found by local analysis. Google Safe Browsing is not configured in this deployment (GOOGLE_SAFE_BROWSING_API_KEY unset), so this is not a complete threat-intelligence check.';
          } else {
            detectionDetails = 'No malware or phishing indicators detected by local analysis or Google Safe Browsing.';
          }
        }
      }

      checks.push({
        id: 'malware-phishing-indicators',
        name: 'Malware/Phishing Indicators',
        status: malwareCheckStatus,
        verdict,
        threatCategory,
        source: detectionSource,
        description: detectionDetails,
        severity: 'critical',
        explanation: 'This check combines the security-test signature registry, Google Safe Browsing (when configured), content pattern analysis (deceptive-download scoring, weighted scam-content matching), inline-script obfuscation detection, hidden/suspicious iframe detection, redirect-chain analysis, and local URL/domain-reputation heuristics. Only the security-test registry and Google Safe Browsing (or very high-confidence local content analysis) can fail this check outright - weaker local heuristics can only produce a warning.',
        method: detectionMethod,
        risk: verdict === 'security-test'
          ? 'This is a recognized security-test resource, not a real threat - but a scanner that can\'t recognize it has a real detection gap, which is why it\'s still treated as a severe finding for scoring purposes.'
          : 'A confirmed malicious or phishing site can steal credentials, install malware, or trick users into fraudulent payments.',
        fix: malwareCheckStatus === 'pass'
          ? 'No action needed.'
          : verdict === 'security-test'
            ? 'No action needed on the target itself (it is an intentional test page) - this result confirms the scanner correctly recognizes known threat-test resources.'
            : 'Do not enter credentials, payment details, or download files from this site until the flagged signals are manually reviewed. If this is your own site and you believe this is a false positive, review the evidence below and adjust the content or URL pattern that triggered it.',
        confidence: confidenceLevel,
        confidenceNote
      });
      attachEvidence(checks[checks.length - 1], detectionEvidence);

      // 3b. Obfuscated JavaScript (separate detailed check, shown whenever detected -
      // whether or not it also contributed to the combined verdict above)
      if (obfuscatedScripts.isObfuscated) {
        checks.push({
          id: 'obfuscated-javascript',
          name: 'Obfuscated JavaScript',
          status: 'warn',
          verdict: 'suspicious',
          description: `Inline script(s) with obfuscation indicators detected (score ${obfuscatedScripts.score}): ${obfuscatedScripts.signals.slice(0, 3).join('; ')}`,
          severity: 'high',
          explanation: 'Obfuscated JavaScript (packed with eval/unescape/atob, or dense escape-sequence encoding) is a common technique for hiding malicious payloads from both users and simple scanners.',
          method: 'Scans inline <script> bodies for eval() combined with unescape/String.fromCharCode/atob, document.write(unescape(...)) injection patterns, and dense runs of \\x/\\u escape sequences.',
          risk: 'Obfuscated scripts can hide credential-stealing code, drive-by download triggers, or redirect logic from casual inspection.',
          fix: 'Review the flagged inline script(s) below. If this is your own site, avoid obfuscating first-party code - it also defeats CSP nonce/hash allowlisting and makes security review harder.',
          confidence: 'medium',
          confidenceNote: 'Some legitimate bundlers/minifiers and analytics snippets use eval() or escape sequences; review the evidence rather than treating a match as automatically malicious.'
        });
        attachEvidence(checks[checks.length - 1], obfuscatedScripts.evidence);
      }

      // 3c. Suspicious redirect chain (separate detailed check)
      if (redirectChainResult.isSuspicious) {
        checks.push({
          id: 'suspicious-redirect-chain',
          name: 'Suspicious Redirect Chain',
          status: 'warn',
          verdict: 'suspicious',
          description: `Suspicious redirect chain to reach this page: ${redirectChainResult.signals.join('; ')}`,
          severity: 'medium',
          explanation: 'Long or cross-domain redirect chains, especially through disposable-TLD domains, can be used to obscure a page\'s true origin or evade simple URL-based filtering.',
          method: 'Analyzes the actual redirect chain followed to reach the final page (hop count, TLDs of intermediate hosts, and whether the final domain differs from the original).',
          risk: 'Cloaked/obfuscated redirect chains are a common technique in malvertising and phishing campaigns to hide the real destination until the last hop.',
          fix: 'Review the redirect chain evidence below. If this is your own site, minimize unnecessary redirect hops.',
          confidence: 'low',
          confidenceNote: 'Redirect chains are also used for entirely legitimate reasons (URL shorteners, A/B testing, domain migrations) - this is a weak signal on its own.'
        });
        attachEvidence(checks[checks.length - 1], redirectChainResult.evidence);
      }

      // 4. Deceptive Download Page (separate detailed check)
      if (deceptiveDownload.isDeceptive) {
        const classification = deceptiveDownload.riskScore >= 80 ? 'Malicious' : 'Highly Suspicious';
        checks.push({
          id: 'deceptive-download-page',
          name: 'Deceptive Download Page',
          status: 'fail',
          verdict: 'confirmed',
          description: `MALWARE DISTRIBUTION: This page exhibits ${deceptiveDownload.signals.length} suspicious signals typical of malware/PUP distribution (risk score ${deceptiveDownload.riskScore}/100)`,
          severity: 'critical',
          explanation: 'This check detects pages that use social engineering to trick users into downloading malicious software. Common indicators include: generic download prompts, missing publisher info, obfuscated URLs, and executable delivery without transparency.',
          method: `Weighted point system across download-language phrases, missing publisher/version/license metadata, obfuscated URL paths, suspicious domain keywords/TLDs, executable delivery, and fake gating language (countdown timers, "generating link", etc). Flagged at riskScore >= 50 (currently ${deceptiveDownload.riskScore}).`,
          risk: 'Deceptive download pages are used to distribute malware, adware, and potentially-unwanted-programs (PUPs) by disguising them as legitimate software downloads.',
          fix: 'Avoid downloading anything from this page. If this is your own site, add clear publisher/version/license information and remove countdown or "preparing download" gating language.',
          confidence: deceptiveDownload.riskScore >= 80 ? 'high' : deceptiveDownload.riskScore >= 65 ? 'medium' : 'low',
          confidenceNote: deceptiveDownload.riskScore < 65
            ? 'Risk score is just over the flagging threshold - review the evidence below, as legitimate download pages can occasionally trip a few of these signals.'
            : undefined,
          riskScore: deceptiveDownload.riskScore,
          signals: deceptiveDownload.signals,
          classification
        });
        attachEvidence(checks[checks.length - 1], deceptiveDownload.evidence);
      }

      // 5. Credential Harvesting Detection - Isolated with try/catch
      let credentialHarvesting = { isHarvesting: false, reason: '', evidence: [] };
      try {
        const suspiciousTld = BURNER_TLDS.some(tld => hostname.endsWith(tld));
        credentialHarvesting = this.detectCredentialHarvesting(bodyLower, hostname, {
          obfuscatedJs: obfuscatedScripts.isObfuscated,
          hiddenIframe: suspiciousIframesResult.isSuspicious,
          suspiciousTld
        });
      } catch (credErr) {
        logger.error('Credential harvesting detection failed:', credErr.message);
      }
      checks.push({
        id: 'credential-harvesting',
        name: 'Credential Harvesting',
        status: credentialHarvesting.isHarvesting ? 'fail' : 'pass',
        verdict: credentialHarvesting.isHarvesting ? 'confirmed' : 'none',
        description: credentialHarvesting.isHarvesting
          ? credentialHarvesting.reason
          : (credentialHarvesting.reason || 'No credential harvesting patterns detected'),
        severity: 'critical',
        explanation: 'Detects fake login forms and pages that attempt to steal passwords or sensitive information like credit cards and SSNs.',
        method: 'Looks for <input> fields whose name/id/placeholder/autocomplete attribute references a card number, CVV, or SSN, and for login forms whose page text impersonates a named brand different from the page\'s own domain. A bare login form with no brand text is only flagged when combined with corroborating signals (self-describing phishing/social-engineering text, obfuscated JS, a hidden iframe, or a suspicious-TLD domain) - see evidence for the exact combination.',
        risk: 'Fake login and payment forms are used to steal usernames, passwords, card numbers, and SSNs directly from users who believe they\'re on a legitimate site.',
        fix: credentialHarvesting.isHarvesting
          ? 'Do not submit any information into this form. If this is your own site, ensure the checkout/login flow is served from a domain your users can visually verify, and consider adding EV/OV certificate indicators.'
          : 'No action needed.',
        confidence: credentialHarvesting.tier === 'generic-login-form' ? 'medium' : 'high',
        confidenceNote: credentialHarvesting.reason && credentialHarvesting.reason.startsWith('NOTICE:')
          ? 'This domain is on a known retail/e-commerce allowlist, so the sensitive-field match is shown as a notice rather than a failure and does not affect the score.'
          : credentialHarvesting.tier === 'generic-login-form'
            ? 'This is a combination of weaker signals (no explicit brand impersonation) - review the evidence before treating this as confirmed.'
            : undefined
      });
      attachEvidence(checks[checks.length - 1], credentialHarvesting.evidence);

      // 6. SSL Certificate Status
      checks.push({
        id: 'ssl-certificate-status',
        name: 'SSL Certificate Status',
        status: isHttps ? 'pass' : 'fail',
        description: isHttps
          ? 'Site uses HTTPS encryption - your connection is secure'
          : 'Site uses HTTP (unencrypted) - data can be intercepted by attackers',
        severity: 'critical',
        explanation: 'HTTPS encrypts all data between your browser and the website, protecting sensitive information from interception.',
        method: 'Checks whether the final URL (after following any redirects) uses the https:// scheme.',
        risk: 'Traffic sent over plain HTTP can be intercepted or modified in transit, e.g. on public Wi-Fi or by a malicious network operator.',
        fix: isHttps ? 'No action needed.' : 'Redirect all HTTP traffic to HTTPS and obtain a TLS certificate (e.g. a free one via Let\'s Encrypt):\n  server {\n    listen 80;\n    return 301 https://$host$request_uri;\n  }',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: null })]);

      // 7. Form Security
      const hasForms = $('form').length > 0;
      const passwordFields = $('input[type="password"], input[type=password]').toArray();
      const hasPasswordField = passwordFields.length > 0;

      let formStatus = 'pass';
      let formDesc = 'No forms detected, or all forms are on secure HTTPS';
      const formEvidence = [];

      if (hasPasswordField && !isHttps) {
        formStatus = 'fail';
        formDesc = 'CRITICAL: Password field on non-HTTPS page - login credentials can be stolen';
        passwordFields.forEach(el => formEvidence.push(buildDomEvidence($, el, body, 'password field on HTTP page')));
      } else if (hasForms && !isHttps) {
        formStatus = 'warn';
        formDesc = 'Forms detected on non-HTTPS page - submitted data is not encrypted';
        $('form').toArray().forEach(el => formEvidence.push(buildDomEvidence($, el, body, 'form on HTTP page')));
      } else if (hasForms && isHttps) {
        formDesc = 'Forms are protected by HTTPS encryption';
      }

      checks.push({
        id: 'form-security',
        name: 'Form Security',
        status: formStatus,
        description: formDesc,
        severity: 'critical',
        explanation: 'Password and form fields should always be on HTTPS pages to prevent credentials from being intercepted.',
        method: 'Finds <form> elements and password <input> fields in the fetched HTML and checks whether the page was served over HTTPS.',
        risk: 'Form data (including passwords) submitted over an unencrypted HTTP connection is sent in plaintext and can be intercepted by anyone on the network path.',
        fix: formStatus === 'pass' ? 'No action needed.' : 'Serve this page (and its form submission endpoint) over HTTPS.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], formEvidence);

      // 8. XSS Protection - CSP is the modern replacement for X-XSS-Protection, which
      // is deprecated and ignored by all current browsers. A missing legacy header
      // should never carry a heavy penalty when a CSP is already doing the real work.
      const csp = headers['content-security-policy'] || '';
      const cspReportOnly = headers['content-security-policy-report-only'] || '';
      const xssHeader = headers['x-xss-protection'] || '';

      // Also check for CSP in meta tags (common for static sites)
      const metaCspEl = $('meta[http-equiv="Content-Security-Policy" i]').get(0);
      const metaCsp = metaCspEl ? $(metaCspEl).attr('content') || '' : '';
      const effectiveCsp = csp || metaCsp;

      let xssStatus, xssDesc, xssExplanation, xssSeverity = 'low';
      const xssEvidence = [buildHeaderEvidence({ ...requestContext, highlightHeader: 'content-security-policy' })];

      if (effectiveCsp) {
        xssStatus = 'pass';
        xssDesc = csp
          ? 'Content Security Policy (CSP) is configured via HTTP header - this is the modern XSS mitigation (X-XSS-Protection is deprecated and ignored by current browsers)'
          : 'Content Security Policy (CSP) is configured via a meta tag - this is the modern XSS mitigation';
        xssExplanation = 'CSP restricts which scripts can run on the page, preventing malicious code injection. It has superseded X-XSS-Protection, which modern browsers no longer honor.';
        if (metaCspEl) xssEvidence.push(buildDomEvidence($, metaCspEl, body, 'CSP meta tag'));
      } else if (cspReportOnly) {
        xssStatus = 'pass';
        xssDesc = 'CSP is configured in report-only mode - monitoring script activity, though not yet blocking';
        xssExplanation = 'A report-only CSP still indicates active XSS mitigation work in progress; consider moving to full enforcement when ready.';
      } else if (xssHeader === '1; mode=block') {
        xssStatus = 'pass';
        xssDesc = 'X-XSS-Protection header enabled in blocking mode (legacy, but functional as a secondary signal)';
        xssExplanation = 'This deprecated header is ignored by current browsers, but doesn\'t hurt as a secondary signal for older clients.';
      } else {
        // No CSP and no legacy header. Per policy, this is at most informational -
        // never a heavy penalty - since a missing *deprecated* header shouldn't be
        // treated the same as a missing modern one.
        xssStatus = 'info';
        xssDesc = 'No Content-Security-Policy and no legacy X-XSS-Protection header detected';
        xssExplanation = 'X-XSS-Protection is deprecated and ignored by modern browsers, so its absence alone isn\'t a real risk. Consider adding a Content-Security-Policy header, which is the actual modern XSS mitigation.';
      }

      checks.push({
        id: 'xss-protection',
        name: 'XSS (Cross-Site Scripting) Protection',
        status: xssStatus,
        description: xssDesc,
        severity: xssSeverity,
        explanation: xssExplanation,
        method: 'Checks for a Content-Security-Policy header or meta tag first (the modern mitigation); only falls back to the deprecated X-XSS-Protection header as a secondary, informational signal.',
        risk: 'Without CSP, a script injected via a stored or reflected XSS vulnerability elsewhere on the site can run with full access to the page (read cookies, submit forms, etc).',
        fix: xssStatus === 'pass' ? 'No action needed.' : 'Add a Content-Security-Policy header, e.g. in Express:\n  app.use((req, res, next) => {\n    res.setHeader("Content-Security-Policy", "default-src \'self\'");\n    next();\n  });\nor in nginx:\n  add_header Content-Security-Policy "default-src \'self\';" always;',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], xssEvidence);

      // 9. External Scripts - classify each by registrable domain (PSL-based) against
      // the page's own domain, known CDNs, and known vendors. Only genuinely
      // unrecognized domains count toward "unknown", and the penalty scales with the
      // proportion of unknown scripts rather than firing at a flat severity regardless
      // of how many scripts (or how large a fraction) are actually unrecognized.
      const scriptElements = $('script[src]').toArray();
      const inlineScriptElements = $('script:not([src])').toArray().filter(el => {
        const html = $(el).html();
        return html && html.trim().length > 0;
      });

      const scriptEvidence = [];
      let externalScriptCount = 0;
      let unknownCount = 0, firstPartyCount = 0, knownCdnCount = 0, knownVendorCount = 0;

      for (const el of scriptElements) {
        const $el = $(el);
        const src = $el.attr('src');
        if (!src) continue;
        let absoluteUrl, scriptHostname;
        try {
          absoluteUrl = new URL(src, finalUrl).href;
          scriptHostname = new URL(absoluteUrl).hostname;
        } catch (e) {
          continue;
        }
        externalScriptCount++;
        const attributes = {
          async: $el.attr('async') !== undefined,
          defer: $el.attr('defer') !== undefined,
          integrity: $el.attr('integrity') || null,
          crossorigin: $el.attr('crossorigin') || null,
          type: $el.attr('type') || null
        };
        const classification = classifyDomain(scriptHostname, hostname);
        if (classification.tier === 'unknown') unknownCount++;
        else if (classification.tier === 'first-party') firstPartyCount++;
        else if (classification.tier === 'known-cdn') knownCdnCount++;
        else if (classification.tier === 'known-vendor') knownVendorCount++;

        scriptEvidence.push(buildScriptEvidence({ src: absoluteUrl, isInline: false, hostname: scriptHostname, pageHostname: hostname, attributes }));
      }

      for (const el of inlineScriptElements) {
        scriptEvidence.push(buildScriptEvidence({ isInline: true, inlineSnippet: $(el).html() }));
      }

      let scriptStatus, scriptSeverity, scriptDesc;
      if (externalScriptCount === 0) {
        scriptStatus = 'pass';
        scriptSeverity = 'low';
        scriptDesc = inlineScriptElements.length > 0
          ? `${inlineScriptElements.length} inline script(s), no external scripts`
          : 'No scripts detected';
      } else if (unknownCount === 0) {
        scriptStatus = 'pass';
        scriptSeverity = 'low';
        scriptDesc = `${externalScriptCount} external script(s), all from first-party, known-CDN, or known-vendor domains (${firstPartyCount} first-party, ${knownCdnCount} known CDN, ${knownVendorCount} known vendor)`;
      } else {
        const unknownRatio = unknownCount / externalScriptCount;
        if (unknownRatio <= 0.15) {
          scriptStatus = 'info';
          scriptSeverity = 'low';
        } else if (unknownRatio <= 0.5) {
          scriptStatus = 'warn';
          scriptSeverity = 'medium';
        } else {
          // Deliberately still 'warn'/'medium', not 'fail'/'critical': an unrecognized
          // script source alone is not proof of malicious intent, and previously this
          // could contribute to zeroing out the whole category - see Goal 2.2.
          scriptStatus = 'warn';
          scriptSeverity = 'medium';
        }
        scriptDesc = `${unknownCount}/${externalScriptCount} script(s) from unrecognized domains (${firstPartyCount} first-party, ${knownCdnCount} known CDN, ${knownVendorCount} known vendor) - verify they're legitimate`;
      }

      checks.push({
        id: 'external-scripts',
        name: 'External Scripts',
        status: scriptStatus,
        description: scriptDesc,
        severity: scriptSeverity,
        explanation: 'External scripts from unknown sources could potentially contain malicious code or tracking. First-party subdomains, well-known CDNs, and well-known vendors (payments, analytics, support widgets, etc) are not "unknown".',
        method: 'Every <script src> is resolved to an absolute URL and classified by registrable domain (Public Suffix List, via tldts) against the page\'s own domain (first-party/subdomain), a maintained list of CDNs, and a maintained list of common vendors. Only domains matching none of those count as "unknown". The penalty scales with the proportion of scripts that are unknown, capped at a medium-severity warning - it can never fail this check outright.',
        risk: 'A compromised or malicious third-party script executes with the same privileges as the page itself and can steal data, hijack sessions, or inject content (a supply-chain attack).',
        fix: scriptStatus === 'pass' ? 'No action needed.' : 'Add a Subresource Integrity (integrity="sha384-...") attribute to third-party <script> tags where possible, or self-host critical scripts.',
        confidence: 'medium',
        confidenceNote: 'Domain reputation is a heuristic: brand-owned asset/CDN domains that don\'t share a registrable domain or a recognizable name pattern with the main site (e.g. a dedicated short-link domain) will still show as "unknown" even when they\'re legitimate.'
      });
      attachEvidence(checks[checks.length - 1], scriptEvidence);

      // 10. Iframe Usage
      const iframeElements = $('iframe').toArray();
      const externalIframes = [];
      for (const el of iframeElements) {
        const src = $(el).attr('src');
        if (!src) continue;
        try {
          const iframeHostname = new URL(src, finalUrl).hostname;
          if (iframeHostname !== hostname) externalIframes.push(el);
        } catch (e) { /* relative/invalid src, ignore */ }
      }

      let iframeStatus = 'pass';
      let iframeDesc = 'No iframes detected on page';

      if (suspiciousIframesResult.isSuspicious) {
        iframeStatus = 'warn';
        iframeDesc = `${externalIframes.length} external iframe(s) detected, including one or more with suspicious characteristics - see the Suspicious Redirect Chain / Malware indicators above and the evidence below`;
      } else if (externalIframes.length > 0) {
        iframeStatus = 'warn';
        iframeDesc = `${externalIframes.length} external iframe(s) detected - verify they're from trusted sources`;
      } else if (iframeElements.length > 0) {
        iframeDesc = `${iframeElements.length} iframe(s) detected, all from same domain`;
      }

      checks.push({
        id: 'iframe-usage',
        name: 'Iframe Usage',
        status: iframeStatus,
        description: iframeDesc,
        severity: suspiciousIframesResult.isSuspicious ? 'high' : 'medium',
        explanation: 'Iframes can embed content from other websites. External iframes should be from trusted sources only; hidden/zero-size external iframes are a stronger warning sign (see method).',
        method: 'Finds <iframe> elements whose resolved src hostname differs from the page\'s own hostname, and separately flags any that are hidden (zero-size or display:none/visibility:hidden) or point at a suspicious-TLD domain.',
        risk: 'Malicious iframes can be used for clickjacking or to load phishing content inside an otherwise-trusted page; hidden iframes are a classic drive-by/clickjacking delivery mechanism.',
        fix: iframeStatus === 'pass' ? 'No action needed.' : 'Add a sandbox attribute to third-party iframes and verify each source is trusted. Remove any hidden/zero-size iframes you did not intentionally add.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [
        ...externalIframes.map(el => buildDomEvidence($, el, body, 'external iframe')),
        ...suspiciousIframesResult.evidence
      ]);

      // 11. Clickjacking Protection
      const xFrameOptions = (headers['x-frame-options'] || '').toUpperCase();
      const hasFrameAncestors = effectiveCsp.includes('frame-ancestors');

      let clickjackStatus = 'warn';
      let clickjackDesc = 'No clickjacking protection - site can be embedded in malicious iframes';

      if (xFrameOptions === 'DENY' || hasFrameAncestors) {
        clickjackStatus = 'pass';
        clickjackDesc = 'Clickjacking protection enabled - site cannot be embedded in iframes';
      } else if (xFrameOptions === 'SAMEORIGIN') {
        clickjackStatus = 'pass';
        clickjackDesc = 'Clickjacking protection enabled - only same-origin embedding allowed';
      }

      checks.push({
        id: 'clickjacking-protection',
        name: 'Clickjacking Protection',
        status: clickjackStatus,
        description: clickjackDesc,
        severity: 'medium',
        explanation: 'Clickjacking protection prevents attackers from overlaying invisible elements on your site to trick users into clicking malicious links.',
        method: 'Checks the X-Frame-Options response header and the frame-ancestors CSP directive.',
        risk: 'Without this protection, an attacker can overlay your page in an invisible iframe to trick users into clicking hidden elements ("clickjacking").',
        fix: clickjackStatus === 'pass' ? 'No action needed.' : 'Add an X-Frame-Options header, e.g. in nginx:\n  add_header X-Frame-Options "SAMEORIGIN" always;\nor a CSP frame-ancestors directive.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], [buildHeaderEvidence({ ...requestContext, highlightHeader: 'x-frame-options' })]);

      // 12. Mixed Content (HTTPS loading HTTP resources)
      const mixedContentEvidence = [];
      if (isHttps) {
        $('[src], [href]').each((i, el) => {
          const $el = $(el);
          for (const attr of ['src', 'href']) {
            const val = $el.attr(attr);
            if (val && /^http:\/\//i.test(val)) {
              mixedContentEvidence.push({
                ...buildMixedContentEvidence({ url: val, tag: el.name, attribute: attr }),
                selector: undefined
              });
            }
          }
        });
      }

      let mixedStatus = 'pass';
      let mixedDesc = 'No mixed content issues';
      let mixedSeverity = 'medium';

      if (mixedContentEvidence.length > 0) {
        const activeCount = mixedContentEvidence.filter(m => m.activity === 'active').length;
        mixedStatus = 'warn';
        mixedSeverity = activeCount > 0 ? 'high' : 'medium';
        mixedDesc = `${mixedContentEvidence.length} insecure HTTP resource(s) on HTTPS page (${activeCount} active, ${mixedContentEvidence.length - activeCount} passive) - may cause security warnings`;
      }

      checks.push({
        id: 'mixed-content',
        name: 'Mixed Content',
        status: mixedStatus,
        description: mixedDesc,
        severity: mixedSeverity,
        explanation: 'Mixed content occurs when an HTTPS page loads resources over HTTP, potentially exposing sensitive data.',
        method: 'On HTTPS pages, scans every src/href attribute for http:// URLs and classifies each as active (script/iframe/embed/object/stylesheet link - can execute or alter behavior) or passive (e.g. an image - can only be spoofed or tracked).',
        risk: 'Active mixed content can be used to inject scripts even on an otherwise-secure page; passive mixed content can be tampered with in transit or used to track users.',
        fix: mixedStatus === 'pass' ? 'No action needed.' : 'Change each flagged resource URL to https://, or use a protocol-relative/relative URL.',
        confidence: 'high'
      });
      attachEvidence(checks[checks.length - 1], mixedContentEvidence);

    } catch (error) {
      // A live-fetch failure (DNS, timeout, connection refused, TLS, SSRF-block,
      // etc) means NONE of the content-based or network-dependent checks above
      // could run. This must never be reported as "no indicators found" - that
      // would be indistinguishable from a genuinely clean result. Every check
      // below is explicitly 'error' status (excluded from scoring, same as any
      // other 'error' check - see score-calculator.util.js) with an
      // 'unable-to-determine' verdict and a description that says so plainly.
      const errorInfo = classifyFetchError(error);
      logger.error('Safety analysis error:', errorInfo);
      analysisError = error;

      const testNote = securityTestMatch
        ? ` Note: this URL matches a known security-test signature (${securityTestMatch.provider}) - ${securityTestMatch.message} Being a known test target and being currently reachable are independent facts; this failure does not mean the target is safe.`
        : '';

      checks.push({
        id: 'malware-phishing-indicators',
        name: 'Malware/Phishing Indicators',
        status: 'error',
        verdict: 'unable-to-determine',
        threatCategory: securityTestMatch ? securityTestMatch.threatCategory : 'unknown',
        source: 'N/A (fetch failed)',
        description: `Unable to determine — threat analysis could not be completed (${errorInfo.label}).${testNote}`,
        severity: 'critical',
        explanation: 'The live fetch of this URL failed before any content-based or threat-intelligence checks could run. This is explicitly reported as "unable to determine", not as a clean/safe result, and does not contribute to the category score.',
        method: `Fetch attempt classified as: ${errorInfo.type} (${errorInfo.detail})`,
        risk: 'An unreachable target cannot be assessed - treat it with the same caution as an unknown site until it can be reached and analyzed.',
        fix: 'Retry the analysis once the target is reachable. If this failure persists for a URL you expect to be reachable, check DNS configuration, firewall rules, or TLS certificate validity.',
        confidence: 'low',
        confidenceNote: 'This result reflects a failed connection attempt, not a security assessment of the target\'s content.'
      });
      checks.push({
        id: 'safety-analysis-error',
        name: 'Safety Analysis Error',
        status: 'error',
        description: `Unable to determine — Safety & Threats analysis could not be completed (${errorInfo.label}: ${errorInfo.detail})`,
        severity: 'critical',
        explanation: 'An error occurred before the page could be fetched, so no safety checks could run. This category will not contribute to the overall score.'
      });
    }

    // Calculate score - if there was an analysis error, mark category as unavailable
    let score;
    let categoryStatus = 'available';

    if (analysisError) {
      score = null;
      categoryStatus = 'unavailable';
    } else {
      score = calculateCategoryScore(checks);
      const malwareCheck = checks.find(c => c.name === 'Malware/Phishing Indicators');
      const malwareFlag = !!(malwareCheck && (malwareCheck.status === 'fail' || malwareCheck.status === 'error'));
      if (malwareFlag) {
        score = 0;
      }
    }

    return {
      category: 'Safety & Threats',
      icon: 'shield-alert',
      score,
      status: categoryStatus,
      checks,
      malwareDetected: checks.some(c => c.name === 'Malware/Phishing Indicators' && c.status === 'fail')
    };
  }

  detectPhishingIndicators(url, hostname) {
    try {
      const urlLower = url.toLowerCase();

      // These "obfuscated URL" heuristics are individually weak - legitimate sites
      // routinely use long opaque tokens (signed URLs, JWTs, unsubscribe links) and
      // 24-char hex IDs (MongoDB ObjectIds are everywhere on e-commerce/blog URLs).
      // Require at least two of them together before treating it as a real signal,
      // instead of letting any single match zero out the whole report.
      let weakSignals = 0;

      // Obfuscated payload (long base64-like path segment)
      if (/\/[A-Za-z0-9+/]{80,}={0,2}($|\?|\/)/i.test(urlLower)) weakSignals++;

      // Long hex string in URL path (raised from 24+ to 32+ to avoid matching
      // common legitimate identifiers like MongoDB ObjectIds)
      if (/\/[a-f0-9]{32,}($|\?|\/)/i.test(urlLower)) weakSignals++;

      // Site hosted directly off a bare IP address rather than a domain name
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) weakSignals++;

      if (weakSignals >= 2) return true;

      // Typosquatting detection - compare the registrable domain label against known
      // brands using edit distance rather than a raw substring test. The previous
      // substring approach flagged unrelated domains that merely contain a brand name
      // (e.g. "grapple.com"/"pineapple.com" for "apple") and legitimate country-code
      // variants of the real brand (e.g. "google.de", "amazon.co.uk").
      const labels = hostname.split('.');
      const secondLevelTlds = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']);
      let sld = labels.length >= 2 ? labels[labels.length - 2] : hostname;
      if (labels.length >= 3 && secondLevelTlds.has(sld)) {
        sld = labels[labels.length - 3];
      }

      const brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple'];
      for (const brand of brands) {
        if (sld === brand) continue; // exact brand match on any TLD - legitimate
        const lengthDiff = Math.abs(sld.length - brand.length);
        // Length must be within 1 character of the brand name. This is what keeps
        // real (if coincidental) words that merely contain a brand as a substring -
        // "grapple"/"pineapple" contain "apple" but are 2-4 chars longer - from being
        // misclassified.
        if (lengthDiff > 1) continue;
        const distance = this.levenshteinDistance(sld, brand);
        // Same length: allow up to 2 character substitutions (e.g. "g00gle",
        // "amaz0n"). One character longer/shorter: only a single insertion/deletion
        // (e.g. "gooogle") - a distance of 2 at that length starts overlapping with
        // coincidental unrelated words.
        const maxDistance = lengthDiff === 0 ? 2 : 1;
        if (distance > 0 && distance <= maxDistance) return true;
      }

      return false;
    } catch (err) {
      logger.error('Error in detectPhishingIndicators:', err.message);
      return false;
    }
  }

  /**
   * Standard Levenshtein edit distance between two strings.
   * Used to detect typosquatted domains (e.g. "gooogle" vs "google")
   * without falsely matching unrelated words that merely contain a brand
   * name as a substring.
   */
  levenshteinDistance(a, b) {
    const m = a.length;
    const n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;

    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (a[i - 1] === b[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
        }
      }
    }
    return dp[m][n];
  }

  checkDomainReputation(hostname, url) {
    try {
      const hostLower = hostname.toLowerCase();

      // Suspicious TLDs commonly used for scams and malware
      const suspiciousTLDs = [
        '.click', '.download', '.tk', '.ml', '.ga', '.cf', '.top',
        '.xyz', '.icu', '.buzz', '.fun', '.monster', '.cam', '.loan',
        '.work', '.date', '.racing', '.win', '.stream', '.gdn'
      ];

      for (const tld of suspiciousTLDs) {
        if (hostLower.endsWith(tld)) {
          return { isSuspicious: true, reason: `Suspicious ${tld} domain - commonly used for scams/malware` };
        }
      }

      // Known file-dropper / malware distribution domain patterns.
      // NOTE: previously included `^(get|grab|fetch|dl|download|file|soft|free)[a-z]*\.`
      // and `\d{2,}[a-z]*\.(com|net|org)$`, which matched huge numbers of legitimate
      // domains by coincidence (freecodecamp.org, filezilla.org, getpocket.com,
      // office365.com, 37signals.com, download.com, ...) and forced the whole report
      // to a 0/100 "malware detected" score. Removed in favor of narrower, still
      // high-signal patterns that require crack/keygen/patch-style keywords with an
      // explicit separator, which are far less likely to appear by coincidence.
      const malwareDistributionPatterns = [
        { pattern: /getflux/i, reason: 'Domain associated with software bundling/PUP distribution' },
        { pattern: /(free)?(setup|patch|crack|keygen|serial|activator)[.-]/i, reason: 'Potentially unwanted software distribution domain' }
      ];

      for (const { pattern, reason } of malwareDistributionPatterns) {
        if (pattern.test(hostLower)) {
          return { isSuspicious: true, reason };
        }
      }

      // Check URL path for suspicious patterns
      try {
        const urlPath = new URL(url).pathname;
        // Long random/hash paths are suspicious. Restricted to hex-only paths of at
        // least 32 chars to avoid matching common legitimate identifiers like 24-char
        // MongoDB ObjectIds used throughout e-commerce/blog URLs.
        if (/\/[a-f0-9]{32,}$/i.test(urlPath)) {
          return { isSuspicious: true, reason: 'Hash-like URL path typical of malware distribution tracking' };
        }
      } catch (e) {
        // Ignore URL parsing errors
      }

      return { isSuspicious: false };
    } catch (err) {
      logger.error('Error in checkDomainReputation:', err.message);
      return { isSuspicious: false };
    }
  }
}

module.exports = SafetyCheck;
