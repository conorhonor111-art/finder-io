/**
 * breach-scrapers.js — Snusbase + Dehashed intelligence
 * API key path (fast, full data) + free scrape fallback (slower, partial)
 * Both branches are tried; best available result is returned.
 */
const axios = require('axios');
const cheerio = require('cheerio');

async function safeGet(url, opts = {}) {
  try { return await axios.get(url, { timeout: 12000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}
async function safePost(url, data, opts = {}) {
  try { return await axios.post(url, data, { timeout: 12000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// ─────────────────────────────────────────────────────────────
// SNUSBASE
// ─────────────────────────────────────────────────────────────

async function snusbaseAPI(email) {
  if (!process.env.SNUSBASE_API_KEY) return null;
  try {
    const resp = await safePost(
      'https://api.snusbase.com/',
      JSON.stringify({ type: 'email', term: email, wildcard: false }),
      {
        headers: {
          'Auth': process.env.SNUSBASE_API_KEY,
          'Content-Type': 'application/json',
          'User-Agent': 'FINDER_IO/3.0',
        },
      }
    );
    if (resp?.status === 200 && resp.data?.results) {
      const rows = Object.values(resp.data.results).flat();
      if (rows.length === 0) return { source: 'Snusbase', found: false };

      const phones = [...new Set(rows.flatMap(r => r.phone ? [r.phone] : []).filter(Boolean))];
      const names  = [...new Set(rows.flatMap(r => r.name  ? [r.name]  : []).filter(Boolean))];
      const usernames = [...new Set(rows.flatMap(r => r.username ? [r.username] : []).filter(Boolean))];
      const ips = [...new Set(rows.flatMap(r => r.ip_address ? [r.ip_address] : []).filter(Boolean))];
      const dbNames = [...new Set(rows.map(r => r.dbname).filter(Boolean))];

      return {
        source: 'Snusbase',
        found: true,
        totalRecords: rows.length,
        databases: dbNames,
        phones,
        names,
        usernames,
        ips,
        hasPasswords: rows.some(r => r.password),
        confidence: 'high',
        note: `${rows.length} records across ${dbNames.length} breach database(s)`,
      };
    }
  } catch (e) {}
  return null;
}

async function snusbaseScrape(email) {
  // Public search fallback — returns aggregate count + limited fields
  try {
    const homeResp = await safeGet('https://snusbase.com/', {
      headers: { 'User-Agent': UA, Accept: 'text/html' },
    });
    if (!homeResp || homeResp.status !== 200) return null;

    // Extract CSRF / session token from the home page
    const $home = cheerio.load(homeResp.data);
    const csrf = $home('input[name="_token"], input[name="csrf_token"], meta[name="csrf-token"]').first().val()
      || $home('meta[name="csrf-token"]').attr('content')
      || '';
    const cookies = (homeResp.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

    const searchResp = await safePost(
      'https://snusbase.com/search',
      new URLSearchParams({ email, type: 'email', _token: csrf }).toString(),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookies,
          Referer: 'https://snusbase.com/',
          Origin: 'https://snusbase.com',
        },
        maxRedirects: 5,
      }
    );

    if (!searchResp || searchResp.status !== 200) return null;
    const $s = cheerio.load(searchResp.data);

    // Parse result count from page
    const countText = $s('body').text();
    const countMatch = countText.match(/(\d[\d,]+)\s+result/i);
    const totalRecords = countMatch ? parseInt(countMatch[1].replace(/,/g, ''), 10) : 0;

    if (totalRecords === 0) return { source: 'Snusbase', found: false, note: 'No records found (public search)' };

    // Extract visible fields from results table
    const phones = [], names = [], usernames = [];
    $s('[class*="result"], tr, .row').each((_, el) => {
      const row = $s(el).text();
      const phoneMatch = row.match(/\+?[\d\s\-().]{9,18}/g);
      if (phoneMatch) phones.push(...phoneMatch.map(p => p.trim()).filter(p => p.replace(/\D/g,'').length >= 9));
    });

    return {
      source: 'Snusbase',
      found: true,
      totalRecords,
      phones: [...new Set(phones)].slice(0, 5),
      names: [...new Set(names)].slice(0, 5),
      usernames: [...new Set(usernames)].slice(0, 5),
      confidence: 'medium',
      note: `${totalRecords} records found via Snusbase public search (no API key — upgrade for full data)`,
    };
  } catch (e) {}
  return null;
}

// ─────────────────────────────────────────────────────────────
// DEHASHED
// ─────────────────────────────────────────────────────────────

async function dehashedAPI(email) {
  if (!process.env.DEHASHED_USERNAME || !process.env.DEHASHED_API_KEY) return null;
  try {
    const auth = Buffer.from(`${process.env.DEHASHED_USERNAME}:${process.env.DEHASHED_API_KEY}`).toString('base64');
    const resp = await safeGet(
      `https://api.dehashed.com/search?query=email:"${encodeURIComponent(email)}"&size=20`,
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json',
          'User-Agent': 'FINDER_IO/3.0',
        },
      }
    );
    if (resp?.status === 200 && resp.data?.entries) {
      const entries = resp.data.entries;
      if (!entries || entries.length === 0) return { source: 'Dehashed', found: false };

      const phones = [...new Set(entries.flatMap(e => e.phone ? [e.phone] : []).filter(Boolean))];
      const names  = [...new Set(entries.flatMap(e => e.name  ? [e.name]  : []).filter(Boolean))];
      const usernames = [...new Set(entries.flatMap(e => e.username ? [e.username] : []).filter(Boolean))];
      const ips    = [...new Set(entries.flatMap(e => e.ip_address ? [e.ip_address] : []).filter(Boolean))];
      const dbNames = [...new Set(entries.map(e => e.database_name).filter(Boolean))];

      return {
        source: 'Dehashed',
        found: true,
        totalRecords: resp.data.total || entries.length,
        databases: dbNames,
        phones,
        names,
        usernames,
        ips,
        hasPasswords: entries.some(e => e.password || e.hashed_password),
        confidence: 'high',
        note: `${resp.data.total || entries.length} records in Dehashed database`,
      };
    }
  } catch (e) {}
  return null;
}

async function dehashedScrape(email) {
  // Dehashed public search — returns hit count from the search preview
  try {
    const resp = await safeGet(
      `https://www.dehashed.com/search?query=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': UA, Accept: 'text/html' },
        maxRedirects: 5,
      }
    );
    if (!resp || resp.status !== 200) return null;
    const $ = cheerio.load(resp.data);
    const pageText = $('body').text();

    // Dehashed shows something like "X results for..."
    const countMatch = pageText.match(/(\d[\d,]+)\s+(result|entr|record)/i);
    const totalRecords = countMatch ? parseInt(countMatch[1].replace(/,/g, ''), 10) : 0;

    // Check for "No results" text
    const noResults = /no results|not found|0 results/i.test(pageText);
    if (noResults || totalRecords === 0) return { source: 'Dehashed', found: false, note: 'Not indexed in Dehashed' };

    return {
      source: 'Dehashed',
      found: true,
      totalRecords,
      phones: [],
      names: [],
      usernames: [],
      confidence: 'medium',
      note: `${totalRecords} records found in Dehashed (no API key — upgrade for full data including passwords, IPs, usernames)`,
    };
  } catch (e) {}
  return null;
}

// ─────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────

async function breachScraperScan(email, progressCb) {
  if (progressCb) progressCb({ sub: 'Snusbase + Dehashed breach lookup' });

  const [snusResult, dehashResult] = await Promise.allSettled([
    (async () => {
      // Try API first, fall back to scrape
      const apiRes = await snusbaseAPI(email);
      if (apiRes) return apiRes;
      return snusbaseScrape(email);
    })(),
    (async () => {
      const apiRes = await dehashedAPI(email);
      if (apiRes) return apiRes;
      return dehashedScrape(email);
    })(),
  ]);

  const results = [];
  if (snusResult.status === 'fulfilled' && snusResult.value) results.push(snusResult.value);
  if (dehashResult.status === 'fulfilled' && dehashResult.value) results.push(dehashResult.value);
  return results;
}

module.exports = { breachScraperScan };
