/**
 * dark-intel.js — Dark web + breach aggregator
 * DarkSearch.io API, Ahmia.fi Tor search, GhostProject.fr, HaveIBeenSold,
 * Spy.pet Discord breach, Shodan email search, breach.directory (enhanced)
 */
const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

async function safeGet(url, opts = {}) {
  try { return await axios.get(url, { timeout: 10000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}

async function searchDarkSearch(email) {
  try {
    const resp = await safeGet(`https://darksearch.io/api/search?query=${encodeURIComponent('"' + email + '"')}&page=1`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
    });
    if (resp?.status === 200 && resp.data?.total > 0) {
      const data = resp.data.data || [];
      const phones = data.flatMap(d => extractPhoneNumbers((d.description || '') + ' ' + (d.title || '')));
      return {
        source: 'DarkSearch.io',
        platform: 'DarkSearch',
        found: true,
        totalResults: resp.data.total,
        results: data.slice(0, 5).map(d => ({
          title: d.title?.slice(0, 100),
          link: d.link?.slice(0, 200),
          preview: d.description?.slice(0, 150),
        })),
        phones: [...new Set(phones)],
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: `${resp.data.total} dark web results mention this email`,
      };
    }
  } catch (e) {}
  return null;
}

async function searchAhmia(email) {
  try {
    const resp = await safeGet(`https://ahmia.fi/search/?q=${encodeURIComponent(email)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        Accept: 'text/html',
      },
    });
    if (resp?.status === 200 && resp.data?.includes(email)) {
      const $ = cheerio.load(resp.data);
      const results = [];
      $('li.result').each((_, el) => {
        const title = $(el).find('h4').text().trim();
        const link = $(el).find('a').attr('href');
        const desc = $(el).find('p').text().trim();
        if (title || link) results.push({ title: title.slice(0, 100), link, preview: desc.slice(0, 150) });
      });
      const phones = extractPhoneNumbers($('body').text());
      if (results.length > 0) {
        return {
          source: 'Ahmia.fi (Tor)',
          platform: 'Ahmia',
          found: true,
          totalResults: results.length,
          results: results.slice(0, 5),
          phones: [...new Set(phones)],
          confidence: phones.length > 0 ? 'high' : 'medium',
          note: `Found on ${results.length} Tor hidden services`,
        };
      }
    }
  } catch (e) {}
  return null;
}

async function searchHaveIBeenSold(email) {
  try {
    const resp = await safeGet(`https://haveibeensold.app/api/?email=${encodeURIComponent(email)}`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
    });
    if (resp?.status === 200) {
      const found = resp.data?.sold === true || resp.data?.found === true || (Array.isArray(resp.data) && resp.data.length > 0);
      const sources = Array.isArray(resp.data) ? resp.data.map(d => d.source || d.name).filter(Boolean) : [];
      if (found) {
        return {
          source: 'HaveIBeenSold',
          platform: 'HaveIBeenSold',
          found: true,
          sources,
          confidence: 'medium',
          note: 'Email sold to data brokers',
        };
      }
    }
  } catch (e) {}
  return null;
}

async function searchSpyPet(email) {
  try {
    const resp = await safeGet(`https://spy.pet/api/email/${encodeURIComponent(email)}`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
    });
    if (resp?.status === 200 && (resp.data?.found || resp.data?.discord_id)) {
      return {
        source: 'Spy.pet',
        platform: 'Spy.pet (Discord)',
        found: true,
        discordId: resp.data.discord_id || null,
        username: resp.data.username || null,
        discriminator: resp.data.discriminator || null,
        confidence: 'high',
        note: 'Discord account linked to this email',
      };
    }
  } catch (e) {}
  return null;
}

async function searchShodan(email) {
  const domain = email.split('@')[1];
  const freeEmailDomains = ['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','aol.com'];
  if (freeEmailDomains.includes(domain)) return null;
  if (!process.env.SHODAN_API_KEY) {
    try {
      const resp = await safeGet(`https://api.shodan.io/shodan/host/search?key=None&query=${encodeURIComponent('hostname:' + domain)}&facets=port:10`, {
        headers: { 'User-Agent': 'FINDER_IO/2.0' },
      });
      if (resp?.status === 200 && resp.data?.total > 0) {
        return {
          source: 'Shodan',
          domain,
          totalHosts: resp.data.total,
          confidence: 'low',
          note: `${resp.data.total} internet-exposed hosts on ${domain}`,
        };
      }
    } catch (e) {}
    return null;
  }
  try {
    const resp = await safeGet(`https://api.shodan.io/shodan/host/search?key=${process.env.SHODAN_API_KEY}&query=${encodeURIComponent('email:' + email)}`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0' },
    });
    if (resp?.status === 200 && resp.data?.total > 0) {
      const matches = resp.data.matches || [];
      const ips = matches.map(m => m.ip_str).filter(Boolean);
      const ports = [...new Set(matches.flatMap(m => m.port || []))];
      return {
        source: 'Shodan',
        domain,
        totalHosts: resp.data.total,
        ips: ips.slice(0, 5),
        ports,
        confidence: 'medium',
        note: `Email found in ${resp.data.total} Shodan records`,
      };
    }
  } catch (e) {}
  return null;
}

async function darkIntelScan(email, progressCb) {
  if (progressCb) progressCb({ sub: 'Dark web & breach aggregators' });
  const tasks = await Promise.allSettled([
    searchDarkSearch(email),
    searchAhmia(email),
    searchHaveIBeenSold(email),
    searchSpyPet(email),
    searchShodan(email),
  ]);
  return tasks.map(r => r.status === 'fulfilled' ? r.value : null).filter(Boolean);
}

module.exports = { darkIntelScan };
