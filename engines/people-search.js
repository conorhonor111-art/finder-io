const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function githubHeaders(extra = {}) {
  const h = { 'User-Agent': 'FINDER_IO/2.0', ...extra };
  if (process.env.GITHUB_TOKEN) h.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  return h;
}

const FREE_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'live.com', 'msn.com', 'me.com', 'googlemail.com',
  'fastmail.com', 'tutanota.com', 'pm.me', 'hey.com', 'cock.li',
];

async function scrapePage(url, timeout = 10000) {
  try {
    const resp = await axios.get(url, {
      headers: { 'User-Agent': USER_AGENT },
      timeout,
      validateStatus: () => true,
      maxRedirects: 5,
    });
    if (resp.status === 200) return resp.data;
  } catch (e) {}
  return null;
}

// ═══════════════════════════════════════
// EMAIL LOCAL PART → NAME INFERENCE
// ═══════════════════════════════════════

function inferNameFromEmail(email) {
  const local = email.split('@')[0].toLowerCase();
  // Skip obviously non-name patterns
  if (/^\d+$/.test(local)) return null;
  if (/^(info|admin|contact|support|hello|sales|help|no.?reply|test|root|webmaster|postmaster)$/i.test(local)) return null;

  // Try common patterns: firstname.lastname, firstname_lastname, firstnamelastname
  let parts = [];
  if (local.includes('.')) {
    parts = local.split('.');
  } else if (local.includes('_')) {
    parts = local.split('_');
  } else if (local.includes('-')) {
    parts = local.split('-');
  } else {
    // Try to split camelCase or guess — "johnsmith" → hard, but we can try common first names
    const commonFirst = [
      'james','john','robert','michael','david','william','richard','joseph','thomas',
      'christopher','charles','daniel','matthew','anthony','mark','donald','steven',
      'andrew','paul','joshua','kenneth','kevin','brian','george','timothy','ronald',
      'edward','jason','jeffrey','ryan','jacob','gary','nicholas','eric','jonathan',
      'stephen','larry','justin','scott','brandon','benjamin','samuel','raymond',
      'gregory','frank','patrick','alexander','jack','dennis','jerry','tyler',
      'aaron','jose','adam','nathan','henry','douglas','peter','zachary','kyle',
      'mary','patricia','jennifer','linda','barbara','elizabeth','susan','jessica',
      'sarah','karen','lisa','nancy','betty','margaret','sandra','ashley','dorothy',
      'kimberly','emily','donna','michelle','carol','amanda','melissa','deborah',
      'stephanie','rebecca','sharon','laura','cynthia','kathleen','amy','angela',
      'shirley','anna','brenda','pamela','emma','nicole','helen','samantha','katherine',
      'christine','debra','rachel','carolyn','janet','catherine','maria','heather',
      'diane','ruth','julie','olivia','joyce','virginia','victoria','kelly','lauren',
      'christina','joan','evelyn','judith','megan','andrea','cheryl','hannah','jacqueline',
      'conor','connor','sean','liam','owen','aiden','ethan','mason','logan',
    ];
    const cleaned = local.replace(/\d+$/, ''); // strip trailing digits
    for (const name of commonFirst) {
      if (cleaned.startsWith(name) && cleaned.length > name.length) {
        const remainder = cleaned.slice(name.length);
        if (remainder.length >= 2 && !/^\d+$/.test(remainder)) {
          parts = [name, remainder];
          break;
        }
      }
    }
    if (parts.length === 0 && cleaned.length >= 3 && !/^\d+$/.test(cleaned)) {
      // Just use the local part as a potential username/name hint
      return { type: 'username', value: cleaned, confidence: 'low' };
    }
  }

  // Clean up and filter
  parts = parts.map(p => p.replace(/\d+/g, '').trim()).filter(p => p.length >= 2);
  if (parts.length >= 2) {
    const firstName = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
    const lastName = parts[parts.length - 1].charAt(0).toUpperCase() + parts[parts.length - 1].slice(1);
    return { type: 'name', firstName, lastName, fullName: `${firstName} ${lastName}`, confidence: 'low' };
  }
  if (parts.length === 1 && parts[0].length >= 3) {
    return { type: 'username', value: parts[0], confidence: 'low' };
  }
  return null;
}

// ═══════════════════════════════════════
// EMAILREP.IO — REPUTATION + PROFILES
// ═══════════════════════════════════════

async function searchEmailRep(email) {
  try {
    const repHeaders = { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' };
    if (process.env.EMAILREP_API_KEY) repHeaders.Key = process.env.EMAILREP_API_KEY;
    const resp = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`, {
      headers: repHeaders,
      timeout: 8000,
      validateStatus: () => true,
    });
    if (resp.status === 200) {
      return {
        source: 'EmailRep.io',
        reputation: resp.data.reputation,
        suspicious: resp.data.suspicious,
        references: resp.data.references,
        details: resp.data.details || {},
        profiles: resp.data.details?.profiles || [],
        firstSeen: resp.data.details?.first_seen || null,
        lastSeen: resp.data.details?.last_seen || null,
        daysSinceCreation: resp.data.details?.days_since_domain_creation || null,
        dataBreaches: resp.data.details?.data_breach || null,
        darkWeb: resp.data.details?.dark_web_appearance || null,
        maliciousActivity: resp.data.details?.malicious_activity || null,
        credential_leaked: resp.data.details?.credentials_leaked || null,
        spamListed: resp.data.details?.spam?.listed || null,
        confidence: resp.data.details?.profiles?.length > 0 ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ═══════════════════════════════════════
// KICKBOX — DISPOSABLE CHECK
// ═══════════════════════════════════════

async function searchDisposableCheck(email) {
  const domain = email.split('@')[1];
  try {
    const resp = await axios.get(`https://open.kickbox.com/v1/disposable/${domain}`, {
      timeout: 5000,
      validateStatus: () => true,
    });
    if (resp.status === 200) {
      return { source: 'Kickbox', domain, disposable: resp.data.disposable };
    }
  } catch (e) {}
  return null;
}

// ═══════════════════════════════════════
// WHOIS / RDAP — FILTER OUT REGISTRAR PHONES
// ═══════════════════════════════════════

async function searchWhoisEmail(email) {
  const domain = email.split('@')[1];
  const isFreeProvider = FREE_EMAIL_DOMAINS.includes(domain.toLowerCase());
  const results = [];

  // ARIN WHOIS — only for custom domains (free provider WHOIS is useless for user info)
  if (!isFreeProvider) {
    try {
      const resp = await axios.get(`https://whois.arin.net/rest/pocs;email=${encodeURIComponent(email)}`, {
        headers: { Accept: 'application/json' },
        timeout: 8000,
        validateStatus: () => true,
      });
      if (resp.status === 200 && resp.data) {
        results.push({ source: 'ARIN WHOIS', data: resp.data, confidence: 'medium' });
      }
    } catch (e) {}
  }

  // RDAP domain lookup — only extract phones for CUSTOM domains
  // For free providers (gmail, yahoo etc) the RDAP phones belong to the
  // email provider's registrar (e.g. MarkMonitor for Google), NOT the user
  // Known registrar companies whose phones should NEVER be treated as personal
  const KNOWN_REGISTRARS = [
    'markmonitor', 'godaddy', 'namecheap', 'tucows', 'enom', 'network solutions',
    'register.com', 'name.com', '1&1', 'ionos', 'gandi', 'ovh', 'cloudflare',
    'google llc', 'amazon registrar', 'squarespace', 'hover', 'dynadot', 'epik',
    'porkbun', 'rebel.com', 'bluehost', 'hostgator', 'dreamhost', 'domain.com',
    'namesilo', 'key-systems', 'ascio', 'csc corporate domains', 'safenames',
  ];

  try {
    const resp2 = await axios.get(`https://rdap.org/domain/${domain}`, {
      timeout: 8000,
      validateStatus: () => true,
    });
    if (resp2.status === 200) {
      const registrarName = resp2.data.entities?.[0]?.vcardArray?.[1]?.find(p => p[0] === 'fn')?.[3] || null;

      // Always record domain info
      results.push({
        source: 'RDAP Domain',
        domain,
        registrar: registrarName,
        registrationDate: resp2.data.events?.find(e => e.eventAction === 'registration')?.eventDate || null,
        expirationDate: resp2.data.events?.find(e => e.eventAction === 'expiration')?.eventDate || null,
        confidence: 'low',
      });

      // Only extract phones from RDAP for custom/business domains
      if (!isFreeProvider) {
        // Walk entities — separate registrar entities from registrant/admin entities
        const entities = resp2.data.entities || [];
        for (const entity of entities) {
          const roles = (entity.roles || []).map(r => r.toLowerCase());
          const vcards = entity.vcardArray?.[1] || [];
          const entityName = vcards.find(p => p[0] === 'fn')?.[3] || '';
          const isRegistrar = roles.includes('registrar') ||
            KNOWN_REGISTRARS.some(r => entityName.toLowerCase().includes(r));

          // Skip phone extraction from registrar entities — those are the registrar's office phones
          if (isRegistrar) continue;

          for (const prop of vcards) {
            if (prop[0] === 'tel') {
              results.push({
                source: 'RDAP WHOIS',
                phone: prop[3],
                registrantName: entityName || null,
                registrant: entity.handle,
                note: `Domain ${roles.join('/')} contact — verify this is the same person as the email owner`,
                confidence: 'low',
              });
            }
          }
        }
      }
    }
  } catch (e) {}

  return results;
}

// ═══════════════════════════════════════
// PASTEBIN DORKS
// ═══════════════════════════════════════

async function searchPastebinDorks(email) {
  const results = [];
  try {
    const searchUrl = `https://www.google.com/search?q=site:pastebin.com+"${encodeURIComponent(email)}"&num=5`;
    const html = await scrapePage(searchUrl);
    if (html) {
      const $ = cheerio.load(html);
      const links = [];
      $('a').each((_, el) => {
        const href = $(el).attr('href') || '';
        if (href.includes('pastebin.com') && !href.includes('google')) links.push(href);
      });
      if (links.length > 0) {
        results.push({
          source: 'Pastebin Dork',
          pasteLinks: links.slice(0, 5),
          note: 'Email found in public pastes — may contain leaked credentials or associated data',
          confidence: 'low',
        });
      }
    }
  } catch (e) {}
  return results;
}

// ═══════════════════════════════════════
// GITHUB COMMITS SEARCH — find real name from git commits
// ═══════════════════════════════════════

async function searchGitHubCommits(email) {
  try {
    const resp = await axios.get(`https://api.github.com/search/commits?q=author-email:${encodeURIComponent(email)}&sort=author-date&per_page=5`, {
      headers: githubHeaders({ Accept: 'application/vnd.github.cloak-preview+json' }),
      timeout: 12000,
      validateStatus: () => true,
    });
    if (resp.status === 200 && resp.data?.total_count > 0) {
      const commits = resp.data.items || [];
      const names    = new Set();
      const repos    = new Set();
      const logins   = new Set();

      for (const c of commits) {
        if (c.commit?.author?.name) names.add(c.commit.author.name);
        if (c.repository?.full_name) repos.add(c.repository.full_name);
        // c.author is the VERIFIED GitHub account — this is the real login
        if (c.author?.login) logins.add(c.author.login);
      }

      const confirmedLogin = logins.size === 1 ? [...logins][0] : (logins.size > 1 ? [...logins][0] : null);

      // Fetch the full GitHub profile for the confirmed login
      let githubProfile = null;
      if (confirmedLogin) {
        try {
          const profileResp = await axios.get(`https://api.github.com/users/${confirmedLogin}`, {
            headers: githubHeaders(),
            timeout: 8000,
            validateStatus: () => true,
          });
          if (profileResp.status === 200 && profileResp.data?.login) {
            const p = profileResp.data;
            githubProfile = {
              login: p.login,
              name: p.name,
              bio: p.bio,
              location: p.location,
              company: p.company,
              blog: p.blog,
              twitterUsername: p.twitter_username,
              followers: p.followers,
              publicRepos: p.public_repos,
              avatarUrl: p.avatar_url,
              htmlUrl: p.html_url,
              createdAt: p.created_at,
            };
            // Profile name takes priority over commit name if it's set
            if (p.name) names.add(p.name);
            if (p.location) {}  // will be surfaced below
          }
        } catch (e) {}
      }

      return {
        source: 'GitHub Commits',
        totalCommits: resp.data.total_count,
        authorNames: [...names],
        repos: [...repos].slice(0, 10),
        // Confirmed GitHub account directly linked to this email via commit authorship
        githubLogin: confirmedLogin,
        githubProfile,
        note: confirmedLogin
          ? `Email verified on GitHub as @${confirmedLogin} (${resp.data.total_count} commits)`
          : 'Name from git commit author field',
        confidence: confirmedLogin ? 'high' : (names.size > 0 ? 'medium' : 'low'),
      };
    }
  } catch (e) {}
  return null;
}

// ═══════════════════════════════════════
// USERNAME PIVOT — search found username across platforms
// ═══════════════════════════════════════

async function usernamePivot(username) {
  if (!username || username.length < 3) return [];
  const results = [];

  const platforms = [
    { name: 'Twitter/X', url: `https://api.twitter.com/i/users/username_available.json?username=${encodeURIComponent(username)}`, check: (r) => r?.data?.valid === false },
    { name: 'Reddit', url: `https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`, check: (r) => r?.status === 200 && r?.data?.data?.name },
    { name: 'Keybase', url: `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(username)}`, check: (r) => r?.status === 200 && r?.data?.them?.length > 0 },
    { name: 'PyPI', url: `https://pypi.org/user/${encodeURIComponent(username)}/`, check: (r) => r?.status === 200 },
    { name: 'npm', url: `https://registry.npmjs.org/-/user/org.couchdb.user:${encodeURIComponent(username)}`, check: (r) => r?.status === 200 && r?.data?.name },
    { name: 'Medium', url: `https://medium.com/@${encodeURIComponent(username)}`, check: (r) => r?.status === 200 && !r?.data?.includes?.('PAGE_NOT_FOUND') },
    { name: 'DEV.to', url: `https://dev.to/api/users/by_username?url=${encodeURIComponent(username)}`, check: (r) => r?.status === 200 && r?.data?.id },
    { name: 'HackerOne', url: `https://hackerone.com/${encodeURIComponent(username)}`, check: (r) => r?.status === 200 },
  ];

  const checks = platforms.map(async (p) => {
    try {
      const resp = await axios.get(p.url, {
        headers: { 'User-Agent': 'FINDER_IO/2.0' },
        timeout: 6000,
        validateStatus: () => true,
        maxRedirects: 3,
      });
      if (p.check(resp)) {
        let profileData = {};
        // Extract extra data from Reddit
        if (p.name === 'Reddit' && resp.data?.data) {
          profileData = {
            karma: resp.data.data.total_karma,
            created: new Date(resp.data.data.created_utc * 1000).toISOString(),
          };
        }
        // Extract extra data from DEV.to
        if (p.name === 'DEV.to' && resp.data) {
          profileData = {
            name: resp.data.name,
            bio: resp.data.summary,
            location: resp.data.location,
            joined: resp.data.joined_at,
            githubUsername: resp.data.github_username,
            twitterUsername: resp.data.twitter_username,
          };
        }
        // Extract extra data from Keybase
        if (p.name === 'Keybase' && resp.data?.them?.[0]) {
          const kb = resp.data.them[0];
          profileData = {
            name: kb.profile?.full_name,
            location: kb.profile?.location,
            bio: kb.profile?.bio,
          };
        }
        return {
          platform: p.name,
          username,
          found: true,
          ...profileData,
        };
      }
    } catch (e) {}
    return null;
  });

  const settled = await Promise.allSettled(checks);
  for (const r of settled) {
    if (r.status === 'fulfilled' && r.value) results.push(r.value);
  }

  return results.length > 0 ? {
    source: 'Username Pivot',
    username,
    foundOn: results,
    note: `Username "${username}" (from GitHub) also found on other platforms`,
    confidence: 'medium',
  } : null;
}

// ═══════════════════════════════════════
// MAIN — PEOPLE SEARCH
// ═══════════════════════════════════════

async function peopleSearch(email, foundUsernames = []) {
  const allResults = [];

  // Email name inference
  const nameInference = inferNameFromEmail(email);
  if (nameInference) {
    allResults.push({
      source: 'Email Analysis',
      ...nameInference,
      note: nameInference.type === 'name'
        ? `Name pattern "${email.split('@')[0]}" suggests: ${nameInference.fullName}`
        : `Local part "${nameInference.value}" used as username hint`,
      confidence: 'low',
    });
  }

  // Parallel searches
  const searches = [
    searchEmailRep(email),
    searchDisposableCheck(email),
    searchWhoisEmail(email),
    searchPastebinDorks(email),
    searchGitHubCommits(email),
  ];

  // Username pivots for any found usernames
  for (const username of foundUsernames.slice(0, 3)) {
    searches.push(usernamePivot(username));
  }

  const settled = await Promise.allSettled(searches);
  for (const result of settled) {
    if (result.status === 'fulfilled' && result.value) {
      if (Array.isArray(result.value)) allResults.push(...result.value);
      else allResults.push(result.value);
    }
  }

  return allResults;
}

module.exports = { peopleSearch, inferNameFromEmail, usernamePivot, searchGitHubCommits };
