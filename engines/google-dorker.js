const axios = require('axios');
const cheerio = require('cheerio');

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
];

function randomAgent() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function extractPhoneNumbers(text) {
  if (!text || typeof text !== 'string') return [];

  const patterns = [
    // International with + prefix
    /\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}/g,
    // US/CA: (xxx) xxx-xxxx or xxx-xxx-xxxx
    /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
    // UK: +44 xxxx xxxxxx
    /\+44\s?\d{4}\s?\d{6}/g,
    // EU: +3x or +4x patterns
    /\+3[0-9]\s?\d{1,3}\s?\d{3,8}/g,
    /\+4[0-9]\s?\d{1,3}\s?\d{3,8}/g,
    // AU: +61 x xxxx xxxx
    /\+61\s?\d\s?\d{4}\s?\d{4}/g,
    // Bare 10-digit (US)
    /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
    // Continuous international
    /\+\d{10,15}/g,
    // Parenthesized area code intl
    /\(\d{2,4}\)\s?\d{4,8}/g,
    // tel: links in HTML
    /tel:[\+]?\d[\d\s\-\.]{6,18}/gi,
  ];

  // Collect all raw matches with their cleaned digits
  const rawMatches = [];
  for (const pattern of patterns) {
    const matches = text.match(pattern) || [];
    for (const m of matches) {
      const stripped = m.replace(/^tel:/i, '');
      const hadPlus = stripped.trimStart().startsWith('+');
      let cleaned = stripped.replace(/[^\d]/g, '');
      if (cleaned.length >= 7 && cleaned.length <= 16) {
        if (/^(19|20)\d{6,}$/.test(cleaned) && !hadPlus) continue; // dates/timestamps — but keep +20 Egypt, +19x intl
        if (/^1[5-9]\d{9,}$/.test(cleaned)) continue; // unix timestamps (1.5T+)
        if (/^\d{12,}$/.test(cleaned) && !hadPlus) continue; // bare 12+ digits without + = ID not phone
        if (/^0{4,}/.test(cleaned)) continue; // zero-padded junk
        if (/^(\d)\1{6,}$/.test(cleaned)) continue; // repeated digits
        if (/^555\d{7}$/.test(cleaned)) continue; // US 555 fictitious numbers
        if (/^1555\d{7}$/.test(cleaned)) continue; // +1 555 fictitious
        if (/^10\d{8,}$/.test(cleaned) && !hadPlus) continue; // 10-prefix junk (often HTML IDs or port numbers)
        if (/^(800|888|877|866|855|844|833|822)\d{7}$/.test(cleaned)) continue; // US toll-free (usually not personal)
        rawMatches.push({ raw: m.trim(), cleaned });
      }
    }
  }

  // Sort longest first — greedy: longer numbers consume shorter fragments
  rawMatches.sort((a, b) => b.cleaned.length - a.cleaned.length);

  const found = new Map();
  for (const match of rawMatches) {
    // Skip if this cleaned number is a substring of an already-added number
    let isFragment = false;
    for (const [existing] of found) {
      if (existing.includes(match.cleaned) || match.cleaned.includes(existing)) {
        // Keep the longer one
        if (match.cleaned.length > existing.length) {
          found.delete(existing);
        } else {
          isFragment = true;
        }
        break;
      }
    }
    if (!isFragment) {
      found.set(match.cleaned, match.raw);
    }
  }
  return [...found.keys()];
}

async function searchEngine(query, engine = 'google') {
  const urls = {
    google: `https://www.google.com/search?q=${encodeURIComponent(query)}&num=15`,
    bing: `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=15`,
    duckduckgo: `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
  };

  try {
    const resp = await axios.get(urls[engine], {
      headers: {
        'User-Agent': randomAgent(),
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 3,
    });

    if (resp.status === 200) {
      return resp.data;
    }
  } catch (e) {}
  return '';
}

function extractLinks(html, engine = 'google') {
  if (!html) return [];
  const $ = cheerio.load(html);
  const links = [];

  if (engine === 'google') {
    $('a').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href.startsWith('/url?q=')) {
        try {
          const parsed = new URL('https://google.com' + href);
          const target = parsed.searchParams.get('q');
          if (target && !target.includes('google.com') && !target.includes('accounts.google')) {
            links.push(target);
          }
        } catch (e) {}
      }
    });
  } else if (engine === 'bing') {
    $('a').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href.startsWith('http') && !href.includes('bing.com') && !href.includes('microsoft.com')) {
        links.push(href);
      }
    });
  } else if (engine === 'duckduckgo') {
    $('a.result__a').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href.startsWith('http')) links.push(href);
    });
  }

  return [...new Set(links)].slice(0, 10);
}

async function dorkSearch(email, progressCb) {
  const results = [];
  const domain = email.split('@')[1];
  const localPart = email.split('@')[0];

  const dorkSets = [
    // Google dorks — primary
    { engine: 'google', queries: [
      `"${email}" phone OR mobile OR cell OR tel`,
      `"${email}" "phone number" OR "contact number"`,
      `"${email}" site:linkedin.com`,
      `"${email}" site:facebook.com`,
      `"${email}" filetype:pdf phone`,
      `"${email}" filetype:csv`,
      `"${email}" filetype:xlsx`,
      `"${email}" site:whitepages.com OR site:truecaller.com OR site:truepeoplesearch.com`,
      `"${localPart}" "@${domain}" phone`,
      `intext:"${email}" intext:"+1" OR intext:"+44" OR intext:"+61"`,
      `"${email}" "cell" OR "cellular" OR "mobile number"`,
      `"${email}" filetype:vcf`,
      `"${email}" site:411.com OR site:anywho.com OR site:pipl.com`,
      `"${email}" "+1" phone number`,
    ]},
    // Bing dorks — secondary
    { engine: 'bing', queries: [
      `"${email}" phone number`,
      `"${email}" contact mobile`,
    ]},
    // DuckDuckGo — tertiary
    { engine: 'duckduckgo', queries: [
      `"${email}" phone`,
    ]},
  ];

  let queryCount = 0;
  const totalQueries = dorkSets.reduce((sum, s) => sum + Math.min(s.queries.length, s.engine === 'google' ? 6 : 2), 0);

  for (const dorkSet of dorkSets) {
    const maxQueries = dorkSet.engine === 'google' ? 6 : 2;

    for (const query of dorkSet.queries.slice(0, maxQueries)) {
      queryCount++;
      if (progressCb) progressCb({ sub: `${dorkSet.engine}: query ${queryCount}/${totalQueries}` });

      try {
        const html = await searchEngine(query, dorkSet.engine);
        if (!html) continue;

        const $ = cheerio.load(html);
        // ── Extract phones from RESULT SNIPPETS only — not the whole page ──────
        // Extracting from $('body').text() includes Bing/Google navigation, ads,
        // footers, and suggestions, which causes false-positive phones unrelated
        // to the search query. We restrict to snippet/description elements only.
        let snippetText = '';
        if (dorkSet.engine === 'google') {
          // Google result snippets: span inside .VwiC3b, .MUxGbd, .IsZvec
          $('div.VwiC3b, span.MUxGbd, div.IsZvec, span[class]').each((_, el) => {
            snippetText += ' ' + $(el).text();
          });
          // Fallback to h3 titles + any visible text in result blocks
          if (snippetText.length < 100) {
            $('h3, cite, .LC20lb').each((_, el) => { snippetText += ' ' + $(el).text(); });
          }
        } else if (dorkSet.engine === 'bing') {
          // Bing result snippets: .b_caption p, .b_algoSlug, h2
          $('.b_caption p, .b_algoSlug, h2, cite').each((_, el) => {
            snippetText += ' ' + $(el).text();
          });
        } else {
          // DuckDuckGo and others
          $('.result__snippet, .result__url, .result__title').each((_, el) => {
            snippetText += ' ' + $(el).text();
          });
          if (snippetText.length < 100) snippetText = $('body').text(); // fallback
        }
        const phones = extractPhoneNumbers(snippetText || $('body').text());
        const links = extractLinks(html, dorkSet.engine);

        if (phones.length > 0) {
          results.push({
            source: `${dorkSet.engine.charAt(0).toUpperCase() + dorkSet.engine.slice(1)} Dork`,
            query,
            phones: phones.slice(0, 8),
            confidence: dorkSet.engine === 'google' ? 'medium' : 'low',
          });
        }

        if (links.length > 0) {
          results.push({
            source: `${dorkSet.engine.charAt(0).toUpperCase() + dorkSet.engine.slice(1)} Dork Links`,
            query,
            urls: links,
            confidence: 'low',
          });
        }

        // Respectful delay between queries
        const delay = dorkSet.engine === 'google' ? 2000 : 1000;
        await new Promise(r => setTimeout(r, delay + Math.random() * 1500));
      } catch (err) {
        // Rate limited or blocked — move on silently
      }
    }
  }

  return results;
}

module.exports = { dorkSearch, extractPhoneNumbers, searchEngine, extractLinks };
