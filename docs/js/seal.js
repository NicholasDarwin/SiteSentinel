// ─────────────────────────────────────────────────────────────
// SiteSentinel seal - a guilloche rosette generated from a hostname.
// Same idea as the line-work printed on banknotes and certificates: the
// pattern is deterministic for an input, and changing one character of the
// input draws a visibly different seal. It is a visual fingerprint only,
// never a security verdict.
// ─────────────────────────────────────────────────────────────

(function () {
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function hash(text) {
    let h = 2166136261;
    for (const ch of text) {
      h ^= ch.codePointAt(0);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  // mulberry32 - small seeded PRNG so a hostname always draws the same seal
  function seeded(seed) {
    return function () {
      seed = (seed + 0x6D2B79F5) >>> 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function gcd(a, b) {
    while (b) [a, b] = [b, a % b];
    return a;
  }

  function pick(rand, min, max) {
    return min + Math.floor(rand() * (max - min + 1));
  }

  // Hypotrochoid with `petals` lobes; `loops` controls how densely the lace
  // overlaps. Scaled to fit a circle of radius `radius` around the origin.
  function hypotrochoid(petals, loops, depth, radius) {
    const R = petals;
    const r = loops;
    const d = loops * depth;
    const k = (R - r) / r;
    const extent = R - r + d;
    const steps = Math.min(3200, petals * loops * 14);
    const turns = loops * 2 * Math.PI;
    let path = '';
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * turns;
      const x = (((R - r) * Math.cos(t) + d * Math.cos(k * t)) / extent) * radius;
      const y = (((R - r) * Math.sin(t) - d * Math.sin(k * t)) / extent) * radius;
      path += (i ? 'L' : 'M') + x.toFixed(2) + ' ' + y.toFixed(2);
    }
    return path;
  }

  function layerSpec(rand, minPetals, maxPetals, minLoops, maxLoops) {
    const petals = pick(rand, minPetals, maxPetals);
    let loops = pick(rand, minLoops, maxLoops);
    while (gcd(petals, loops) !== 1) loops += 1;
    return { petals, loops, depth: 0.75 + rand() * 0.6 };
  }

  /** Path strings for the three rings of the seal for `text`. */
  function sealPaths(text) {
    const key = (text || '').trim().toLowerCase() || 'sitesentinel';
    const rand = seeded(hash(key));
    const outer = layerSpec(rand, 26, 44, 5, 9);
    const middle = layerSpec(rand, 15, 25, 3, 7);
    const inner = layerSpec(rand, 8, 14, 2, 5);
    return [
      hypotrochoid(outer.petals, outer.loops, outer.depth, 98),
      hypotrochoid(middle.petals, middle.loops, middle.depth, 66),
      hypotrochoid(inner.petals, inner.loops, inner.depth, 36)
    ];
  }

  function buildGroup(text) {
    const g = document.createElementNS(SVG_NS, 'g');
    g.setAttribute('class', 'seal-lines');
    // Each ring is printed as a band of slightly shrunk, slightly turned
    // copies - that offset banding is what makes guilloche read as lace.
    sealPaths(text).forEach((d, ring) => {
      const copies = ring === 2 ? 4 : 7;
      for (let i = 0; i < copies; i++) {
        const p = document.createElementNS(SVG_NS, 'path');
        p.setAttribute('d', d);
        p.setAttribute('pathLength', '1');
        p.setAttribute('transform', `rotate(${(i * 1.6).toFixed(1)}) scale(${(1 - i * 0.022).toFixed(3)})`);
        p.style.setProperty('--i', i + ring * 3);
        g.appendChild(p);
      }
    });
    return g;
  }

  /** Replace the seal drawn inside `svg` with the seal for `text`. */
  function drawSeal(svg, text, { animate = false } = {}) {
    if (!svg) return;
    const next = buildGroup(text);
    const previous = svg.querySelector('.seal-lines:not(.is-leaving)');
    if (animate) next.classList.add('is-drawing');
    svg.appendChild(next);
    if (previous) {
      previous.classList.add('is-leaving');
      setTimeout(() => previous.remove(), 450);
    }
  }

  function hostnameOf(value) {
    const raw = (value || '').trim();
    if (!raw) return '';
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'https://' + raw).hostname;
    } catch {
      return raw.toLowerCase();
    }
  }

  window.SiteSeal = { drawSeal, hostnameOf };
})();
