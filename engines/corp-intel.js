/**
 * corp-intel.js — Corporate / professional intelligence
 * OpenCorporates (free), LinkedIn probe, company email patterns,
 * Hunter.io domain search, GitHub org members
 */
const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

async function safeGet(url, opts = {}) {
  try { return await axios.get(url, { timeout: 10000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const FREE_EMAIL_DOMAINS = ['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','aol.com','me.com','live.com','msn.com'];

async function searchOpenCorporates(name, email) {
  if (!name || name.length < 4) return null;
  try {
    const resp = await safeGet(`https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(name)}&per_page=5&order=score`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
    });
    if (resp?.status === 200 && resp.data?.results?.officers?.length > 0) {
      const officers = resp.data.results.officers.map(o => o.officer);
      const companies = officers.flatMap(o => [{
        name: o.company?.name || o.organisation_name,
        jurisdiction: o.jurisdiction_code,
        role: o.position,
        address: o.address,
        inactive: o.inactive,
      }]).filter(c => c.name);
      return {
        source: 'OpenCorporates',
        found: true,
        name,
        companies: companies.slice(0, 5),
        totalMatches: resp.data.results.total_count,
        confidence: 'medium',
        note: `${name} found in company officer records`,
      };
    }
  } catch (e) {}
  return null;
}

async function searchLinkedInProbe(email) {
  try {
    const init = await safeGet('https://www.linkedin.com/login', { headers: { 'User-Agent': UA } });
    const cookies = (init?.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
    const csrfMatch = cookies.match(/JSESSIONID="([^"]+)"/);
    const csrf = csrfMatch?.[1] || '';

    const resp = await safeGet(
      `https://www.linkedin.com/voyager/api/typeahead/hitsV2?q=blended&query=${encodeURIComponent(email)}&queryContext=List()`,
      {
        headers: {
          'User-Agent': UA,
          'Accept': 'application/vnd.linkedin.normalized+json+2.1',
          'Cookie': cookies,
          'Csrf-Token': csrf,
          'x-restli-protocol-version': '2.0.0',
        },
      }
    );
    if (resp?.status === 200 && resp.data?.included?.length > 0) {
      const profiles = resp.data.included
        .filter(i => i.$type?.includes('Profile') || i.$type?.includes('miniProfile'))
        .slice(0, 3);
      return {
        source: 'LinkedIn',
        platform: 'LinkedIn',
        found: profiles.length > 0,
        profiles: profiles.map(p => ({
          name: [p.firstName, p.lastName].filter(Boolean).join(' '),
          headline: p.occupation || p.headline,
          location: p.locationName,
          publicId: p.publicIdentifier,
          profileUrl: p.publicIdentifier ? `https://www.linkedin.com/in/${p.publicIdentifier}` : null,
        })).filter(p => p.name),
        confidence: 'medium',
      };
    }
  } catch (e) {}
  return null;
}

async function searchCompanyDomain(email) {
  const domain = email.split('@')[1];
  if (FREE_EMAIL_DOMAINS.includes(domain)) return null;

  const results = { source: 'Domain Intel', domain, phones: [], names: [], emails: [] };

  if (process.env.HUNTER_API_KEY) {
    try {
      const resp = await safeGet(
        `https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${process.env.HUNTER_API_KEY}&limit=5`,
        { headers: { 'User-Agent': 'FINDER_IO/2.0' } }
      );
      if (resp?.status === 200 && resp.data?.data) {
        const d = resp.data.data;
        const emails = (d.emails || []).map(e => e.value);
        const phones = (d.emails || []).flatMap(e => e.phone_number ? [e.phone_number] : []);
        const names = (d.emails || []).map(e => [e.first_name, e.last_name].filter(Boolean).join(' ')).filter(Boolean);
        Object.assign(results, { emails, phones, names, organization: d.organization, country: d.country });
      }
    } catch (e) {}
  }

  const orgName = domain.split('.')[0];
  try {
    const h = { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/vnd.github.v3+json' };
    if (process.env.GITHUB_TOKEN) h.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    const resp = await safeGet(`https://api.github.com/orgs/${orgName}/members?per_page=10`, { headers: h });
    if (resp?.status === 200 && Array.isArray(resp.data)) {
      results.githubOrgMembers = resp.data.map(m => m.login).slice(0, 10);
    }
  } catch (e) {}

  try {
    const contactResp = await safeGet(`https://${domain}/contact`, { headers: { 'User-Agent': UA } });
    if (contactResp?.status === 200) {
      const $ = cheerio.load(contactResp.data);
      const pagePhones = extractPhoneNumbers($('body').text());
      results.phones.push(...pagePhones);
      const emailMatches = contactResp.data.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
      results.emails.push(...emailMatches.filter(e => e !== email).slice(0, 10));
    }
  } catch (e) {}

  results.phones = [...new Set(results.phones)];
  results.emails = [...new Set(results.emails)];
  results.confidence = results.phones.length > 0 ? 'medium' : 'low';

  if (results.phones.length > 0 || results.emails.length > 0 || results.names?.length > 0 || results.githubOrgMembers?.length > 0) return results;
  return null;
}

async function corpIntelScan(email, knownNames, progressCb) {
  if (progressCb) progressCb({ sub: 'Corporate intelligence + OpenCorporates' });
  const domain = email.split('@')[1];
  const tasks = await Promise.allSettled([
    searchOpenCorporates(knownNames?.[0], email),
    FREE_EMAIL_DOMAINS.includes(domain) ? Promise.resolve(null) : searchLinkedInProbe(email),
    searchCompanyDomain(email),
  ]);
  return tasks.map(r => r.status === 'fulfilled' ? r.value : null).filter(Boolean);
}

module.exports = { corpIntelScan };
