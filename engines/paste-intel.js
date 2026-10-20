/**
 * paste-intel.js — Pastebin / paste site OSINT
 * Searches Google-dorked paste sites for the email, extracts phones, names,
 * passwords and context snippets from any paste mentioning the target.
 */
const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers, searchEngine } = require('./google-dorker');

const PASTE_SITES = [
  'pastebin.com',
  'paste.ee',
  'hastebin.com',
  'dpaste.com',
  'paste.fo',
  'ghostbin.co',
  'justpaste.it',
  'controlc.com',
  'rentry.co',
  'pastie.org',
  'gist.github.com',     // GitHub Gists — dev emails very frequently leaked here
  'paste.mozilla.org',
  'termbin.com',
];

async function fetchAndExtract(url, email) {
  try {
    const resp = await axios.get(url, {
      timeout: 8000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      validateStatus: () => true,
      maxRedirects: 3,
    });
    if (resp.status !== 200) return null;
    const $ = cheerio.load(resp.data);
    const text = $('body').text();
    if (!text.toLowerCase().includes(email.toLowerCase())) return null;

    const phones = extractPhoneNumbers(text);
    // Look for names near the email
    const emailIdx = text.toLowerCase().indexOf(email.toLowerCase());
    const snippet = text.substring(Math.max(0, emailIdx - 200), emailIdx + 200);
    const nameMatch = snippet.match(/(?:name|user|contact|author|from|by)[:\s='"]+([A-Z][a-z]+ [A-Z][a-z]+)/i);
    // Look for password patterns (partial, for detection only)
    const passMatch = snippet.match(/(?:pass(?:word)?|pwd)[:\s='"]+([^\s"',\n]{4,30})/i);

    return {
      url,
      phones,
      name: nameMatch?.[1] || null,
      hasPassword: !!passMatch,
      snippet: snippet.trim().slice(0, 300),
    };
  } catch (e) {
    return null;
  }
}

async function searchPasteGoogle(email) {
  const results = [];
  const queries = PASTE_SITES.map(site => `site:${site} "${email}"`);
  // Also generic paste dorks
  queries.push(`"${email}" paste`);
  queries.push(`"${email}" pastebin`);

  for (const query of queries.slice(0, 6)) {
    try {
      const html = await searchEngine(query, 'google');
      if (!html) continue;
      const $ = cheerio.load(html);
      const links = [];
      $('a').each((_, el) => {
        const href = $(el).attr('href') || '';
        if (href.startsWith('/url?q=')) {
          try {
            const u = new URL('https://google.com' + href);
            const target = u.searchParams.get('q');
            if (target && PASTE_SITES.some(s => target.includes(s))) links.push(target);
          } catch (e) {}
        }
      });

      for (const link of [...new Set(links)].slice(0, 3)) {
        const extracted = await fetchAndExtract(link, email);
        if (extracted) results.push(extracted);
      }
      await new Promise(r => setTimeout(r, 1500 + Math.random() * 1000));
    } catch (e) {}
  }

  return results;
}

// Bing-based paste search as fallback
async function searchPasteBing(email) {
  const results = [];
  const query = `${PASTE_SITES.slice(0,5).map(s => `site:${s}`).join(' OR ')} "${email}"`;
  try {
    const html = await searchEngine(query, 'bing');
    if (!html) return results;
    const $ = cheerio.load(html);
    const links = [];
    $('a').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href.startsWith('http') && PASTE_SITES.some(s => href.includes(s))) {
        links.push(href);
      }
    });
    for (const link of [...new Set(links)].slice(0, 4)) {
      const extracted = await fetchAndExtract(link, email);
      if (extracted) results.push(extracted);
    }
  } catch (e) {}
  return results;
}

async function pasteIntel(email, progressCb) {
  if (progressCb) progressCb({ sub: 'Scanning paste sites for email leaks' });

  const [googleResults, bingResults] = await Promise.allSettled([
    searchPasteGoogle(email),
    searchPasteBing(email),
  ]);

  const allResults = [
    ...(googleResults.status === 'fulfilled' ? googleResults.value : []),
    ...(bingResults.status === 'fulfilled' ? bingResults.value : []),
  ];

  // Deduplicate by URL
  const seen = new Set();
  const deduped = allResults.filter(r => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });

  if (deduped.length === 0) return null;

  const allPhones = [...new Set(deduped.flatMap(r => r.phones))];
  const allNames = [...new Set(deduped.map(r => r.name).filter(Boolean))];
  const hasPasswords = deduped.some(r => r.hasPassword);

  return {
    source: 'Paste Intelligence',
    found: true,
    totalPastes: deduped.length,
    pasteLinks: deduped.map(r => r.url),
    phones: allPhones,
    names: allNames,
    hasPasswordLeak: hasPasswords,
    snippets: deduped.map(r => ({ url: r.url, preview: r.snippet?.slice(0, 150) })),
    confidence: allPhones.length > 0 ? 'high' : hasPasswords ? 'medium' : 'low',
  };
}

module.exports = { pasteIntel };
