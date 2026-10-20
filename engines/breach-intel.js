const axios = require('axios');
const { extractPhoneNumbers } = require('./google-dorker');

async function safeGet(url, opts = {}) {
  try {
    return await axios.get(url, {
      timeout: opts.timeout || 10000,
      headers: { 'User-Agent': 'FINDER_IO/2.0', ...opts.headers },
      validateStatus: () => true,
      ...opts,
    });
  } catch (e) { return null; }
}

// IntelX Phonebook — searches breach databases for phone selectors
async function checkIntelX(email) {
  if (!process.env.INTELX_API_KEY) return [];
  const results = [];
  try {
    const resp = await safeGet('https://2.intelx.io/phonebook/search', {
      params: { term: email, maxresults: 30, media: 0, target: 2 },
      headers: { 'x-key': process.env.INTELX_API_KEY || '' },
      timeout: 12000,
    });

    if (resp?.status === 200 && resp.data?.id) {
      await new Promise(r => setTimeout(r, 4000));

      const resultResp = await safeGet('https://2.intelx.io/phonebook/search/result', {
        params: { id: resp.data.id, limit: 30 },
        headers: { 'x-key': process.env.INTELX_API_KEY || '' },
        timeout: 12000,
      });

      if (resultResp?.status === 200 && resultResp.data?.selectors) {
        const phoneSelectors = resultResp.data.selectors.filter(
          s => s.selectortypeh === 'Phone Number' || s.selectortype === 2
        );
        const emailSelectors = resultResp.data.selectors.filter(
          s => (s.selectortypeh === 'Email Address' || s.selectortype === 1) && s.selectorvalue !== email
        );
        const domainSelectors = resultResp.data.selectors.filter(
          s => s.selectortypeh === 'Domain' || s.selectortype === 3
        );
        const urlSelectors = resultResp.data.selectors.filter(
          s => s.selectortypeh === 'URL' || s.selectortype === 4
        );

        if (phoneSelectors.length > 0) {
          results.push({
            source: 'IntelX Phonebook',
            phones: phoneSelectors.map(s => s.selectorvalue),
            confidence: 'high',
            totalSelectors: resultResp.data.selectors.length,
          });
        }
        if (emailSelectors.length > 0) {
          results.push({
            source: 'IntelX Related Emails',
            relatedEmails: emailSelectors.map(s => s.selectorvalue).slice(0, 15),
            confidence: 'medium',
          });
        }
        if (domainSelectors.length > 0) {
          results.push({
            source: 'IntelX Related Domains',
            domains: domainSelectors.map(s => s.selectorvalue).slice(0, 10),
            confidence: 'low',
          });
        }
        if (urlSelectors.length > 0) {
          results.push({
            source: 'IntelX Related URLs',
            urls: urlSelectors.map(s => s.selectorvalue).slice(0, 10),
            confidence: 'low',
          });
        }
      }
    }
  } catch (e) {}
  return results;
}

// HudsonRock Cavalier — stealer log phone data
async function checkHudsonRock(email) {
  try {
    const resp = await safeGet('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email', {
      params: { email },
      timeout: 12000,
    });

    if (resp?.status === 200 && resp.data) {
      const stealers = resp.data.stealers || [];
      const phones = [];
      const usernames = [];
      const passwords = [];
      const ips = [];
      const urls = [];

      for (const s of stealers) {
        if (s.phone) phones.push(s.phone);
        if (s.phone_number) phones.push(s.phone_number);
        if (s.username) usernames.push(s.username);
        if (s.password) passwords.push(s.password.substring(0, 3) + '***');
        if (s.ip) ips.push(s.ip);
        if (s.url) urls.push(s.url);
      }

      return {
        source: 'HudsonRock Cavalier',
        found: stealers.length > 0,
        compromisedMachines: stealers.length,
        phones: [...new Set(phones)],
        usernames: [...new Set(usernames)].slice(0, 10),
        partialPasswords: [...new Set(passwords)].slice(0, 5),
        ips: [...new Set(ips)].slice(0, 5),
        urls: [...new Set(urls)].slice(0, 10),
        confidence: phones.length > 0 ? 'high' : 'medium',
        dateCompromised: stealers[0]?.date_compromised || null,
        operatingSystem: stealers[0]?.operating_system || null,
        malwareFamily: stealers[0]?.malware_family || null,
      };
    }
  } catch (e) {}
  return null;
}

// Breach dork searches across multiple engines
async function breachDorkSearch(email) {
  const results = [];
  const dorks = [
    `"${email}" phone leak database`,
    `"${email}" breach phone number credentials`,
    `"${email}" dump phone mobile`,
    `"${email}" pastebin OR ghostbin OR rentry`,
  ];

  for (const dork of dorks.slice(0, 3)) {
    try {
      const resp = await safeGet(`https://www.google.com/search?q=${encodeURIComponent(dork)}&num=10`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      });

      if (resp?.status === 200) {
        const phones = extractPhoneNumbers(resp.data);
        if (phones.length > 0) {
          results.push({
            source: 'Breach Dork',
            query: dork,
            phones: phones.slice(0, 5),
            confidence: 'low',
          });
        }
      }
      await new Promise(r => setTimeout(r, 2500));
    } catch (e) {}
  }
  return results;
}

// Dehashed-style search via dork
async function dehashedDork(email) {
  try {
    const resp = await safeGet(`https://www.google.com/search?q=site:dehashed.com+"${encodeURIComponent(email)}"`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    });
    if (resp?.status === 200) {
      const phones = extractPhoneNumbers(resp.data);
      return {
        source: 'Dehashed Dork',
        found: resp.data.includes('dehashed.com'),
        phones,
        confidence: phones.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

// Leak-Lookup check — try premium key first, fall back to public key
async function leakLookup(email) {
  const key = process.env.LEAK_LOOKUP_API_KEY || 'free';
  let d = null;

  // Try JSON format (premium) first
  try {
    const r = await axios.post('https://leak-lookup.com/api/search',
      JSON.stringify({ key, type: 'email_address', query: email }),
      { timeout: 12000, headers: { 'Content-Type': 'application/json', 'User-Agent': 'FINDER_IO/2.0' }, validateStatus: () => true }
    );
    if (r?.status === 200 && r.data) d = typeof r.data === 'string' ? JSON.parse(r.data) : r.data;
  } catch (e) {}

  // Fall back to form-encoded
  if (!d) {
    try {
      const r = await axios.post('https://leak-lookup.com/api/search',
        `key=${encodeURIComponent(key)}&type=email_address&query=${encodeURIComponent(email)}`,
        { timeout: 12000, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'FINDER_IO/2.0' }, validateStatus: () => true }
      );
      if (r?.status === 200 && r.data) d = typeof r.data === 'string' ? JSON.parse(r.data) : r.data;
    } catch (e) {}
  }

  if (!d) return null;

  const notFound = d.error === 'true' || d.message === 'Not found' || d.success === false;
  const message = (typeof d.message === 'object' && d.message !== null) ? d.message : {};
  const allRecords = Object.values(message).flat();
  const phones = [...new Set(
    allRecords.flatMap(r => [r.phone, r.mobile, r.telephone, r.cellphone, r.cell, r.phone_number]).filter(Boolean)
  )];
  const sources = Object.keys(message).filter(k => (message[k] || []).length > 0);

  return {
    source: 'Leak-Lookup',
    platform: 'LeakLookup',
    found: !notFound && (allRecords.length > 0 || sources.length > 0),
    totalRecords: allRecords.length,
    breachSources: sources.slice(0, 8),
    phones,
    names: [...new Set(allRecords.map(r => r.name || r.full_name).filter(Boolean))],
    hasPassword: allRecords.some(r => r.password || r.hash),
    confidence: phones.length > 0 ? 'high' : sources.length > 0 ? 'medium' : 'low',
    note: phones.length > 0
      ? `Leak-Lookup: ${phones.length} phone(s) in breach records`
      : sources.length > 0
        ? `Leak-Lookup: found in ${sources.slice(0,4).join(', ')}`
        : 'Leak-Lookup: not found',
  };
}

async function breachIntel(email, progressCb) {
  const allResults = [];

  const stages = [
    { name: 'IntelX Phonebook', fn: () => checkIntelX(email) },
    { name: 'HudsonRock Cavalier', fn: () => checkHudsonRock(email) },
    { name: 'Leak-Lookup', fn: () => leakLookup(email) },
    { name: 'Dehashed Dork', fn: () => dehashedDork(email) },
    { name: 'Breach Dork Search', fn: () => breachDorkSearch(email) },
  ];

  for (const stage of stages) {
    if (progressCb) progressCb({ sub: stage.name });
    try {
      const result = await stage.fn();
      if (result) {
        if (Array.isArray(result)) allResults.push(...result);
        else allResults.push(result);
      }
    } catch (e) {}
  }

  return allResults;
}

module.exports = { breachIntel };
