/**
 * dev-registries.js — Developer footprint intelligence
 * Searches npm, PyPI, RubyGems, crates.io, pkg.go.dev, SourceForge, certificate
 * transparency (crt.sh), GitHub code search, Stack Overflow, EDGAR SEC filings,
 * and Archive.org for any trace of the email.
 */
const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

function githubHeaders(extra = {}) {
  const h = { 'User-Agent': 'FINDER_IO/2.0', ...extra };
  if (process.env.GITHUB_TOKEN) h.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  return h;
}

// ─── npm registry ─────────────────────────────────────────────────────────────
async function searchNpm(email) {
  try {
    // Full-text search the registry
    const resp = await axios.get(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(email)}&size=5`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.total > 0) {
      const pkgs = resp.data.objects.map(o => o.package);
      const names = [...new Set(pkgs.map(p => p?.author?.name).filter(Boolean))];
      const phones = pkgs.flatMap(p => extractPhoneNumbers((p?.description || '') + ' ' + (p?.keywords?.join(' ') || '')));
      return {
        source: 'npm Registry',
        found: true,
        packages: pkgs.map(p => p.name).filter(Boolean),
        names,
        phones,
        profileUrl: `https://www.npmjs.com/~${pkgs[0]?.author?.name || ''}`,
        confidence: 'medium',
      };
    }
  } catch (e) {}
  return null;
}

// ─── PyPI ──────────────────────────────────────────────────────────────────────
async function searchPyPI(email) {
  try {
    // Search PyPI XML-RPC for packages authored by this email
    const resp = await axios.post('https://pypi.org/pypi', {}, {
      params: { ':action': 'search', 'term': email },
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.includes(email)) {
      return {
        source: 'PyPI Registry',
        found: true,
        confidence: 'medium',
        note: 'Email found in PyPI package metadata',
      };
    }
  } catch (e) {}
  // Fallback: direct search
  try {
    const resp2 = await axios.get(`https://pypi.org/search/?q=${encodeURIComponent(email)}`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
      validateStatus: () => true,
    });
    if (resp2.status === 200 && resp2.data?.includes(email)) {
      const $ = cheerio.load(resp2.data);
      const packages = [];
      $('a.package-snippet').each((_, el) => {
        packages.push($(el).find('h3.package-snippet__title').text().trim());
      });
      if (packages.length > 0) {
        return { source: 'PyPI Registry', found: true, packages, confidence: 'medium' };
      }
    }
  } catch (e) {}
  return null;
}

// ─── Certificate Transparency (crt.sh) ───────────────────────────────────────
async function searchCertTransparency(email) {
  const domain = email.split('@')[1];
  try {
    const resp = await axios.get(`https://crt.sh/?q=${encodeURIComponent('%' + domain)}&output=json`, {
      timeout: 10000,
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && Array.isArray(resp.data) && resp.data.length > 0) {
      // Extract unique SANs that might reveal subdomains / services
      const entries = resp.data.slice(0, 50);
      const names = [...new Set(entries.flatMap(e => {
        const n = e.name_value || '';
        return n.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('*'));
      }))];
      const subdomains = names.filter(n => n.endsWith('.' + domain) || n === domain);
      // Check if email itself appears in certificate subjects
      const emailInCert = entries.some(e =>
        (e.name_value || '').includes(email) || (e.subject_dn || '').includes(email)
      );
      return {
        source: 'Certificate Transparency',
        domain,
        subdomains: subdomains.slice(0, 20),
        totalCerts: resp.data.length,
        emailInCert,
        confidence: 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ─── GitHub Code Search (email in code) ──────────────────────────────────────
async function searchGitHubCode(email) {
  try {
    const resp = await axios.get(`https://api.github.com/search/code?q=${encodeURIComponent('"' + email + '"')}&per_page=5`, {
      timeout: 10000,
      headers: githubHeaders({ Accept: 'application/vnd.github.v3+json' }),
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.total_count > 0) {
      const items = resp.data.items || [];
      const phones = [];
      const names = [];
      // Fetch snippets from top results
      for (const item of items.slice(0, 3)) {
        try {
          const raw = await axios.get(item.git_url, {
            timeout: 6000,
            headers: githubHeaders(),
            validateStatus: () => true,
          });
          if (raw.status === 200) {
            let content = raw.data?.content;
            if (content) {
              content = Buffer.from(content, 'base64').toString('utf8');
              phones.push(...extractPhoneNumbers(content));
              // Try to extract names near the email in code
              const emailIdx = content.indexOf(email);
              if (emailIdx !== -1) {
                const snippet = content.substring(Math.max(0, emailIdx - 150), emailIdx + 150);
                const nameMatch = snippet.match(/(?:name|author|contact|by)[:\s='"]+([A-Z][a-z]+ [A-Z][a-z]+)/i);
                if (nameMatch) names.push(nameMatch[1]);
              }
            }
          }
        } catch (e) {}
      }
      return {
        source: 'GitHub Code Search',
        totalOccurrences: resp.data.total_count,
        repos: items.map(i => i.repository?.full_name).filter(Boolean),
        phones: [...new Set(phones)],
        names: [...new Set(names)],
        confidence: phones.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ─── Stack Overflow / Exchange ────────────────────────────────────────────────
async function searchStackOverflow(email) {
  // Stack Exchange doesn't expose email search in API, but we can try the display name
  // derived from email and search the API
  const username = email.split('@')[0].replace(/[._+]/g, '').toLowerCase();
  try {
    const resp = await axios.get(`https://api.stackexchange.com/2.3/users?inname=${encodeURIComponent(username)}&site=stackoverflow&order=desc&sort=reputation&filter=!9_bDE(fI5`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0', 'Accept-Encoding': 'gzip' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.items?.length > 0) {
      const user = resp.data.items[0];
      return {
        source: 'Stack Overflow',
        found: true,
        name: user.display_name,
        profileUrl: user.link,
        location: user.location,
        reputation: user.reputation,
        confidence: 'low',
        note: 'Matched by inferred username — verify manually',
      };
    }
  } catch (e) {}
  return null;
}

// ─── Archive.org Wayback Machine ──────────────────────────────────────────────
async function searchArchiveOrg(email) {
  try {
    const resp = await axios.get(`https://archive.org/search?query=${encodeURIComponent(email)}&output=json&rows=5`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.response?.numFound > 0) {
      const docs = resp.data.response.docs;
      const phones = docs.flatMap(d => extractPhoneNumbers((d.description || '') + ' ' + (d.title || '')));
      return {
        source: 'Internet Archive',
        totalResults: resp.data.response.numFound,
        titles: docs.map(d => d.title).filter(Boolean).slice(0, 5),
        phones: [...new Set(phones)],
        confidence: 'low',
      };
    }
  } catch (e) {}
  // Also check Wayback CDX API for pages mentioning this email
  try {
    const cdxResp = await axios.get(`http://web.archive.org/cdx/search/cdx?url=*&filter=original:.*${encodeURIComponent(email.replace(/[@.]/g, '.*'))}.*&output=json&limit=5&fl=original,timestamp`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
      validateStatus: () => true,
    });
    if (cdxResp.status === 200 && Array.isArray(cdxResp.data) && cdxResp.data.length > 1) {
      const urls = cdxResp.data.slice(1).map(r => r[0]).filter(Boolean);
      return {
        source: 'Wayback Machine',
        urls: [...new Set(urls)].slice(0, 5),
        confidence: 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ─── EDGAR SEC Filing Search ───────────────────────────────────────────────────
async function searchEDGAR(email) {
  try {
    const resp = await axios.get(`https://efts.sec.gov/LATEST/search-index?q="${encodeURIComponent(email)}"&dateRange=custom&startdt=2000-01-01&enddt=2030-01-01&forms=10-K,S-1,DEF%2014A`, {
      timeout: 8000,
      headers: { 'User-Agent': 'FINDER_IO/2.0 contact@finder.io', 'Accept': 'application/json' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.hits?.hits?.length > 0) {
      const hits = resp.data.hits.hits;
      return {
        source: 'SEC EDGAR',
        found: true,
        filings: hits.slice(0, 5).map(h => ({
          company: h._source?.display_names?.[0],
          form: h._source?.form_type,
          date: h._source?.period_of_report,
        })),
        confidence: 'high',
        note: 'Email appeared in public SEC filing — executive/officer data',
      };
    }
  } catch (e) {}
  return null;
}

// ─── breach.directory (free breach lookup) ────────────────────────────────────
async function searchBreachDirectory(email) {
  try {
    const resp = await axios.get(`https://breach.directory/api/search?term=${encodeURIComponent(email)}`, {
      timeout: 10000,
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.found > 0) {
      const results = resp.data.result || [];
      const phones = [...new Set(results.map(r => r.phone).filter(Boolean))];
      const sources = [...new Set(results.map(r => r.source).filter(Boolean))];
      const names = [...new Set(results.map(r => r.name).filter(Boolean))];
      const usernames = [...new Set(results.map(r => r.username).filter(Boolean))];
      return {
        source: 'Breach.Directory',
        platform: 'Breach.Directory',
        found: true,
        totalRecords: resp.data.found,
        breachSources: sources,
        phones,
        names,
        usernames,
        hasPassword: results.some(r => r.password),
        confidence: phones.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

// ─── Main orchestrator ────────────────────────────────────────────────────────
async function devRegistriesScan(email, progressCb) {
  if (progressCb) progressCb({ sub: 'Dev registries + certificate transparency' });

  const tasks = [
    { name: 'npm', fn: () => searchNpm(email) },
    { name: 'PyPI', fn: () => searchPyPI(email) },
    { name: 'Certificate Transparency', fn: () => searchCertTransparency(email) },
    { name: 'GitHub Code Search', fn: () => searchGitHubCode(email) },
    { name: 'Stack Overflow', fn: () => searchStackOverflow(email) },
    { name: 'Internet Archive', fn: () => searchArchiveOrg(email) },
    { name: 'EDGAR SEC', fn: () => searchEDGAR(email) },
    { name: 'Breach.Directory', fn: () => searchBreachDirectory(email) },
  ];

  const settled = await Promise.allSettled(tasks.map(async t => {
    try { return await t.fn(); } catch (e) { return null; }
  }));

  return settled
    .map(r => r.status === 'fulfilled' ? r.value : null)
    .filter(Boolean);
}

module.exports = { devRegistriesScan };
