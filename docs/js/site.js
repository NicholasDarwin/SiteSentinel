// ─────────────────────────────────────────────────────────────
// Shared page behaviour: section reveals, and on the home page the hero
// seal that redraws for whatever address is typed.
// ─────────────────────────────────────────────────────────────

document.documentElement.classList.add('js');

document.addEventListener('DOMContentLoaded', () => {
  // Reveal sections once as they scroll into view. Content is visible by
  // default; the hidden starting state only applies once this script runs.
  const revealables = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && revealables.length) {
    const io = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        // Also reveal anything already scrolled past, so a fast flick never
        // leaves a section hidden above the viewport.
        if (!entry.isIntersecting && entry.boundingClientRect.top > 0) continue;
        entry.target.classList.add('is-visible');
        io.unobserve(entry.target);
      }
    }, { rootMargin: '0px 0px -8% 0px' });
    revealables.forEach(el => io.observe(el));
  } else {
    revealables.forEach(el => el.classList.add('is-visible'));
  }

  const heroSeal = document.getElementById('heroSeal');
  const urlInput = document.getElementById('urlInput');
  const sealHost = document.getElementById('sealHost');
  if (!heroSeal || !urlInput || !window.SiteSeal) return;

  const { drawSeal, hostnameOf } = window.SiteSeal;
  let lastHost = 'sitesentinel';
  drawSeal(heroSeal, lastHost, { animate: true });

  let pending;
  urlInput.addEventListener('input', () => {
    clearTimeout(pending);
    pending = setTimeout(() => {
      const host = hostnameOf(urlInput.value) || 'sitesentinel';
      if (host === lastHost) return;
      lastHost = host;
      if (sealHost) sealHost.textContent = host;
      drawSeal(heroSeal, host);
    }, 140);
  });

  document.querySelectorAll('.try-link').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      urlInput.dispatchEvent(new Event('input'));
      document.getElementById('analysisForm')?.requestSubmit();
    });
  });
});
