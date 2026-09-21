/**
 * Evidence Builder Utilities
 *
 * Shared helpers for building the structured `evidence` array each check can
 * attach to its result, so the frontend evidence panel (and the exported
 * report) can show exactly what was found - the raw header, the exact DOM
 * element, the matched pattern with surrounding context, etc - without
 * needing to re-scan the site.
 *
 * All evidence is computed once, during the original scan, from data already
 * in memory (the response object, the parsed DOM, the raw HTML string).
 */

const { classifyDomain } = require('./domain.util');

/**
 * Caps a list of evidence items for the UI (which should stay fast even on
 * pages with hundreds of matches) while preserving the true total count so
 * the UI can show "showing 20 of 143 - show all".
 */
function capEvidence(list, max = 20) {
  const items = Array.isArray(list) ? list : [];
  return {
    items: items.slice(0, max),
    total: items.length,
    truncated: items.length > max
  };
}

/**
 * Finds the line/column of the first occurrence of `needle` inside `rawHtml`.
 * Best-effort only: cheerio/htmlparser2 can normalize markup slightly
 * (attribute quoting, self-closing slashes), so a needle taken from a
 * re-serialized element won't always match the original source byte-for-byte.
 * Returns null rather than throwing when no match is found.
 */
function locateInHtml(rawHtml, needle) {
  if (!rawHtml || !needle) return null;
  const index = rawHtml.indexOf(needle);
  if (index === -1) return null;
  const upToIndex = rawHtml.slice(0, index);
  const line = (upToIndex.match(/\n/g) || []).length + 1;
  const lastNewline = upToIndex.lastIndexOf('\n');
  const column = index - lastNewline;
  return { line, column, index };
}

/**
 * Builds a best-effort CSS selector path for a cheerio element by walking up
 * to 6 ancestors, preferring #id (which stops the climb - it's unique enough)
 * and otherwise using tag.class or tag:nth-of-type(n) among same-tag siblings.
 */
function cssSelectorFor($, el) {
  try {
    const parts = [];
    let current = el;
    let depth = 0;
    while (current && current.type === 'tag' && depth < 6) {
      const $current = $(current);
      let part = current.name || 'element';
      const id = $current.attr('id');
      if (id) {
        parts.unshift(`${part}#${id}`);
        break;
      }
      const classAttr = ($current.attr('class') || '').trim();
      if (classAttr) {
        const classes = classAttr.split(/\s+/).filter(Boolean).slice(0, 2);
        if (classes.length) part += '.' + classes.join('.');
      }
      const parent = current.parent;
      if (parent && parent.type === 'tag') {
        const siblings = $(parent).children(current.name).toArray();
        if (siblings.length > 1) {
          const idx = siblings.indexOf(current) + 1;
          if (idx > 0) part += `:nth-of-type(${idx})`;
        }
      }
      parts.unshift(part);
      current = parent;
      depth++;
    }
    return parts.join(' > ') || (el.name || 'element');
  } catch (e) {
    return (el && el.name) || 'element';
  }
}

/**
 * Evidence for a DOM/HTML finding: the trimmed outerHTML (~300 chars), a CSS
 * selector, and (best-effort) the line/column in the originally fetched HTML.
 */
function buildDomEvidence($, el, rawHtml, label) {
  let outerHtml = '';
  try {
    outerHtml = $.html(el) || '';
  } catch (e) {
    outerHtml = '';
  }
  const snippet = outerHtml.length > 300 ? outerHtml.slice(0, 300) + '…' : outerHtml;
  const selector = cssSelectorFor($, el);
  const openTagMatch = outerHtml.match(/^<[^>]+>/);
  const needle = openTagMatch ? openTagMatch[0] : outerHtml.slice(0, 60);
  const location = rawHtml ? locateInHtml(rawHtml, needle) : null;

  return {
    type: 'dom',
    label: label || null,
    snippet,
    selector,
    line: location ? location.line : null,
    column: location ? location.column : null
  };
}

/**
 * Evidence for a raw text/regex pattern match: the exact matched text plus
 * ~contextChars of surrounding page text on each side.
 */
function buildPatternEvidence(text, match, options = {}) {
  const contextChars = options.contextChars ?? 200;
  const matchedRule = options.matchedRule || null;
  if (!text || match === undefined || match === null) return null;

  const matchedText = typeof match === 'string' ? match : match[0];
  const index = typeof match === 'string' ? text.indexOf(match) : match.index;

  if (index === undefined || index === -1) {
    return { type: 'pattern', matchedText, context: matchedText, matchedRule };
  }

  const start = Math.max(0, index - contextChars);
  const end = Math.min(text.length, index + matchedText.length + contextChars);
  let context = text.slice(start, end);
  if (start > 0) context = '…' + context;
  if (end < text.length) context += '…';

  return { type: 'pattern', matchedText, context, matchedRule, index };
}

/**
 * Evidence for an HTTP header check: the full raw response headers (so the
 * panel can show the whole set, with the relevant one highlighted/marked
 * missing), the final URL after redirects, status code, and redirect chain.
 */
function buildHeaderEvidence({ headers, finalUrl, statusCode, redirectChain, highlightHeader }) {
  const present = highlightHeader
    ? !!(headers && headers[highlightHeader.toLowerCase()])
    : null;
  return {
    type: 'headers',
    finalUrl: finalUrl || null,
    statusCode: statusCode ?? null,
    redirectChain: redirectChain || [],
    headers: headers || {},
    highlightHeader: highlightHeader || null,
    present
  };
}

/**
 * Evidence for a <script> tag: its full URL/domain, inline vs external,
 * first-party/known-cdn/known-vendor/unknown classification (via the shared
 * Public-Suffix-List-based domain util), and its relevant tag attributes.
 */
function buildScriptEvidence({ src, isInline, hostname, pageHostname, attributes, inlineSnippet }) {
  let classification, classificationReason;
  if (isInline) {
    classification = 'inline';
    classificationReason = 'Inline script (no external source)';
  } else {
    const result = classifyDomain(hostname, pageHostname);
    classification = result.tier;
    classificationReason = result.reason;
  }

  return {
    type: 'script',
    src: src || null,
    hostname: hostname || null,
    isInline: !!isInline,
    classification,
    classificationReason,
    attributes: attributes || {},
    inlineSnippet: inlineSnippet
      ? (inlineSnippet.length > 300 ? inlineSnippet.slice(0, 300) + '…' : inlineSnippet)
      : undefined
  };
}

// Tags that actively execute/render fetched content over the insecure
// connection (can be used to inject/execute attacker content) vs tags that
// merely display passive content (can be spoofed/tampered but not executed).
const ACTIVE_MIXED_CONTENT_TAGS = new Set(['script', 'iframe', 'embed', 'object', 'link']);

/**
 * Evidence for a mixed-content (http:// on an https:// page) resource: the
 * insecure URL, the tag/attribute it came from, and whether it's active
 * (script/iframe/embed/object/stylesheet link) or passive (e.g. an image).
 */
function buildMixedContentEvidence({ url, tag, attribute }) {
  const tagLower = (tag || '').toLowerCase();
  return {
    type: 'mixed-content',
    url,
    tag: tag || null,
    attribute: attribute || null,
    activity: ACTIVE_MIXED_CONTENT_TAGS.has(tagLower) ? 'active' : 'passive'
  };
}

/**
 * Evidence for a discovered link/URL: where it was found on the page (an
 * <a> tag, a <script> body, JSON-LD, a meta tag, an onclick handler, etc).
 */
function buildLinkEvidence({ url, sourceType, sourceDetail }) {
  return {
    type: 'link',
    url,
    sourceType: sourceType || 'unknown',
    sourceDetail: sourceDetail || null
  };
}

/**
 * Attaches the FULL evidence list to `check.evidence` (plus `check.evidenceTotal`
 * for convenience). Deliberately does NOT truncate here - capping happens only in
 * the UI's rendering (which shows the first 20 with a "show all N" control) and
 * in the export report if needed, so "show all" has real data to reveal and the
 * export doesn't silently lose evidence. Use capEvidence() directly if a caller
 * specifically needs a hard-capped list (e.g. for a size-constrained payload).
 */
function attachEvidence(check, list) {
  const items = Array.isArray(list) ? list.filter(Boolean) : [];
  check.evidence = items;
  check.evidenceTotal = items.length;
  return check;
}

module.exports = {
  capEvidence,
  attachEvidence,
  locateInHtml,
  cssSelectorFor,
  buildDomEvidence,
  buildPatternEvidence,
  buildHeaderEvidence,
  buildScriptEvidence,
  buildMixedContentEvidence,
  buildLinkEvidence,
  ACTIVE_MIXED_CONTENT_TAGS
};
