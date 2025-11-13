/**
 * URL and Input Validators
 */

function validateUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    // Ensure it's http or https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed.href;
  } catch (error) {
    return null;
  }
}

function isValidDomain(domain) {
  const domainRegex = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  return domainRegex.test(domain);
}

function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return null;
  }
}

module.exports = {
  validateUrl,
  isValidDomain,
  getHostname
};
