const { dorkSearch } = require('./google-dorker');
const { socialRecon } = require('./social-recon');
const { peopleSearch, usernamePivot, searchGitHubCommits } = require('./people-search');
const { breachIntel } = require('./breach-intel');
const { dnsRecon } = require('./dns-recon');
const { deepEnum } = require('./deep-enum');
const { usernameScan, generateUsernames } = require('./username-gen');
const { devRegistriesScan } = require('./dev-registries');
const { pasteIntel } = require('./paste-intel');
const { phoneHarvest } = require('./phone-harvest');
const { darkIntelScan } = require('./dark-intel');
const { reversePhoneLookup } = require('./reverse-lookup');
const { corpIntelScan } = require('./corp-intel');
const { breachScraperScan } = require('./breach-scrapers');
const { runVerification } = require('./verification');
const { parsePhoneNumberFromString } = require('libphonenumber-js');

// Country code → readable name (common set)
const COUNTRY_NAMES = {
  US: 'United States', GB: 'United Kingdom', CA: 'Canada', AU: 'Australia',
  DE: 'Germany', FR: 'France', IT: 'Italy', ES: 'Spain', NL: 'Netherlands',
  RU: 'Russia', IN: 'India', BR: 'Brazil', MX: 'Mexico', JP: 'Japan',
  CN: 'China', KR: 'South Korea', ZA: 'South Africa', NG: 'Nigeria',
  PK: 'Pakistan', BD: 'Bangladesh', PH: 'Philippines', TR: 'Turkey',
  AR: 'Argentina', CO: 'Colombia', TH: 'Thailand', MY: 'Malaysia',
  ID: 'Indonesia', SG: 'Singapore', NZ: 'New Zealand', SE: 'Sweden',
  NO: 'Norway', DK: 'Denmark', FI: 'Finland', PL: 'Poland', AT: 'Austria',
  CH: 'Switzerland', BE: 'Belgium', PT: 'Portugal', GR: 'Greece',
  CZ: 'Czech Republic', RO: 'Romania', HU: 'Hungary', IE: 'Ireland',
  UA: 'Ukraine', IL: 'Israel', SA: 'Saudi Arabia', AE: 'UAE', EG: 'Egypt',
};

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().split('').map(c => String.fromCodePoint(c.charCodeAt(0) + 127397)).join('');
}

function enrichPhone(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const cleaned = raw.replace(/[^\d+]/g, '');

  // Pre-filter: reject fictional/invalid patterns before hitting libphonenumber
  if (/^1?[2-9]\d{2}555\d{4}$/.test(cleaned)) return null;    // 555 fictionals
  if (/^1?(800|888|877|866|855|844|833|822)\d{7}$/.test(cleaned)) return null; // toll-free

  const attempts = [
    () => parsePhoneNumberFromString(raw),
    () => parsePhoneNumberFromString('+' + cleaned),
    () => parsePhoneNumberFromString(raw, 'US'),
  ];

  for (const attempt of attempts) {
    try {
      const p = attempt();
      if (p && p.isValid()) {
        const country = p.country || null;
        const type = p.getType() || 'UNKNOWN';
        return {
          raw,
          formatted: p.formatInternational(),
          national: p.formatNational(),
          e164: p.number,
          country,
          countryName: country ? (COUNTRY_NAMES[country] || country) : null,
          flag: country ? countryFlag(country) : '',
          type,
          valid: true,
        };
      }
    } catch (e) {}
  }

  // ── Fallback: isPossible() for new / not-yet-indexed NANP area codes ─────────
  // libphonenumber-js's isValid() uses a range table that lags NANPA activations
  // by months. Area codes like 265 (Alabama, active Dec 2022), 472 (NC overlay),
  // 943 (TX overlay) parse fine and isPossible()=true but isValid()=false.
  // Accept these at reduced confidence — they won't block genuine new numbers.
  //
  // CRITICAL ordering: for bare 10-digit strings without a + prefix, try
  // parsePhoneNumberFromString(raw, 'US') FIRST. Without this, "+2655946983"
  // triggers Malawi's +265 country code before the US parse gets a chance, so
  // Alabama (265) area-code numbers land as MW instead of US.
  const fallbackAttempts = (!cleaned.startsWith('+') && cleaned.length === 10)
    ? [
        () => parsePhoneNumberFromString(raw, 'US'),  // 10-digit NANP → prefer US
        () => parsePhoneNumberFromString(raw),
        () => parsePhoneNumberFromString('+' + cleaned),
      ]
    : attempts;
  for (const attempt of fallbackAttempts) {
    try {
      const p = attempt();
      if (p && p.isPossible() && p.country) {
        const country = p.country;
        const type = p.getType() || 'UNKNOWN';
        return {
          raw,
          formatted: p.formatInternational(),
          national: p.formatNational(),
          e164: p.number,
          country,
          countryName: country ? (COUNTRY_NAMES[country] || country) : null,
          flag: countryFlag(country),
          type,
          valid: true,
          possibleOnly: true, // isValid()=false but isPossible()=true — new/unlisted area code
        };
      }
    } catch (e) {}
  }
  return null;
}

const FREE_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'live.com', 'msn.com', 'me.com', 'googlemail.com',
];

function isValidPhone(phone) {
  const clean = phone.replace(/[^\d+]/g, '');
  if (clean.length < 7 || clean.length > 16) return false;
  // Date patterns: YYYYMMDD, YYYYMMDDHH, etc
  if (/^(19|20)\d{6,}$/.test(clean)) return false;
  // US 555 numbers are fictional/reserved
  if (/^1?555\d{7}$/.test(clean)) return false;
  // All repeated digits
  if (/^(\d)\1{6,}$/.test(clean)) return false;
  // 10-prefix junk (HTML IDs, port numbers, timestamps)
  if (/^10\d{8,}$/.test(clean) && !clean.startsWith('+')) return false;
  // Zero-padded junk
  if (/^0{4,}/.test(clean)) return false;
  // US toll-free (usually company, not personal)
  if (/^1?(800|888|877|866|855|844|833|822)\d{7}$/.test(clean)) return false;
  return true;
}

function deduplicatePhones(phones) {
  const normalized = new Map();
  for (const phone of phones) {
    const clean = phone.replace(/[^\d+]/g, '');
    if (!normalized.has(clean) && isValidPhone(phone)) {
      normalized.set(clean, phone);
    }
  }
  return [...normalized.values()];
}

// ═══════════════════════════════════════
// CLUE TRACKER — records WHERE each piece of data came from
// ═══════════════════════════════════════

class ClueTracker {
  constructor() {
    this.clues = [];
  }

  add(type, value, source, note, confidence = 'low') {
    if (!value || (typeof value === 'string' && value.trim() === '')) return;
    // Don't duplicate
    const exists = this.clues.find(c => c.type === type && c.value === value && c.source === source);
    if (exists) return;
    this.clues.push({ type, value, source, note, confidence, timestamp: new Date().toISOString() });
  }

  getByType(type) {
    return this.clues.filter(c => c.type === type);
  }

  getAll() {
    return this.clues;
  }
}

function processResult(result, allPhones, report, clues) {
  if (!result || typeof result !== 'object') return;

  report.rawFindings.push(result);
  report.summary.totalSources++;

  if (result.source) {
    if (!report.summary.enginesRan.includes(result.source)) {
      report.summary.enginesRan.push(result.source);
    }
  }

  // ── PHONE EXTRACTION ──
  // NOTE: GitHub Code Search has a dedicated handler below that applies sequential
  // filtering + adds phones. Skip the generic handler for it to avoid double-adding.
  const SKIP_GENERIC_PHONE = new Set(['GitHub Code Search']);
  const phones = result.phones || [];
  const confidence = result.confidence || 'low';
  if (phones.length > 0 && !SKIP_GENERIC_PHONE.has(result.source)) {
    (allPhones[confidence] || allPhones.low).push(...phones);
    for (const p of phones) {
      clues.add('phone', p, result.source, result.note || `Found by ${result.source}`, confidence);
      // Track how many independent sources found this phone (for corroboration scoring)
      const norm = p.replace(/[^\d+]/g, '');
      if (!allPhones._sources) allPhones._sources = {};
      if (!allPhones._sources[norm]) allPhones._sources[norm] = new Set();
      allPhones._sources[norm].add(result.source);
    }
  }
  if (result.phone) {
    (allPhones[confidence] || allPhones.low).push(result.phone);
    clues.add('phone', result.phone, result.source, result.note || `Found by ${result.source}`, confidence);
    const norm = result.phone.replace(/[^\d+]/g, '');
    if (!allPhones._sources) allPhones._sources = {};
    if (!allPhones._sources[norm]) allPhones._sources[norm] = new Set();
    allPhones._sources[norm].add(result.source);
  }
  if (result.companyPhones) {
    allPhones.low.push(...result.companyPhones);
    for (const p of result.companyPhones) clues.add('phone', p, result.source, 'Company main line — NOT personal', 'low');
  }
  if (result.contactPagePhones) {
    allPhones.low.push(...result.contactPagePhones);
    for (const p of result.contactPagePhones) clues.add('phone', p, result.source, 'From company contact page — NOT personal', 'low');
  }
  if (result.phoneLastTwo) {
    report.partialPhone = result.phoneLastTwo;
    clues.add('partial_phone', result.phoneLastTwo, result.source, `Last digits of phone linked to account: **${result.phoneLastTwo}`, 'medium');
  }

  // ── NAME EXTRACTION ──
  if (result.authorNames) {
    // Filter out garbage names from git commits
    const junkNames = ['user', 'root', 'admin', 'test', 'unknown', 'nobody', 'default', 'ubuntu', 'pi', 'ec2-user'];
    for (const name of result.authorNames) {
      if (junkNames.includes(name.toLowerCase()) || name.length < 3) continue;
      clues.add('name', name, result.source, result.note || `Git commit author name`, 'high');
      if (!report.identity.names.includes(name)) report.identity.names.push(name);
    }
  }

  // ── CONFIRMED GITHUB LOGIN (from commit authorship — hardest evidence) ──────
  if (result.githubLogin) {
    const p = result.githubProfile || {};
    clues.add('username', result.githubLogin, 'GitHub (confirmed)', `GitHub account verified via commit email (${result.totalCommits || '?'} commits)`, 'high');

    // Build a confirmed social profile entry — overrides any username-pivot GitHub guess
    const confirmedGitHubProfile = {
      platform: 'GitHub',
      username: result.githubLogin,
      profileUrl: `https://github.com/${result.githubLogin}`,
      name: p.name || null,
      location: p.location || null,
      company: p.company || null,
      bio: (() => {
        const b = p.bio;
        if (!b || b.trim().length < 8) return null;
        const t = b.trim();
        if (/^\d+\s+\w/.test(t) || /^https?:\/\//.test(t)) return null;
        if (t.split(/\s+/).length < 2) return null;
        return t;
      })(),
      blog: p.blog || null,
      twitterUsername: p.twitterUsername || null,
      followers: p.followers || null,
      publicRepos: p.publicRepos || null,
      avatarUrl: p.avatarUrl || null,
      createdAt: p.createdAt || null,
      confirmedByEmail: true,  // ← key flag: this account is definitively linked to the scanned email
      confidence: 'high',
    };

    // Store the confirmed login on the report so later pipeline stages can reference it
    report._confirmedGitHubLogin = result.githubLogin;

    // Remove any existing GitHub social profile that doesn't match the confirmed login
    // (These are username-pivot guesses that found a DIFFERENT person named "conor", etc.)
    report.socialProfiles = report.socialProfiles.filter(sp =>
      !(sp.platform === 'GitHub' && sp.username !== result.githubLogin)
    );
    // Add confirmed profile if not already present
    if (!report.socialProfiles.some(sp => sp.platform === 'GitHub' && sp.username === result.githubLogin)) {
      report.socialProfiles.unshift(confirmedGitHubProfile);
    }

    // Promote name/location/company from the confirmed GitHub profile
    if (p.name && !report.identity.names.includes(p.name)) {
      report.identity.names.push(p.name);
      clues.add('name', p.name, 'GitHub (confirmed)', `Display name on verified GitHub account @${result.githubLogin}`, 'high');
    }
    if (p.location && !report.identity.locations.includes(p.location)) {
      report.identity.locations.push(p.location);
      clues.add('location', p.location, 'GitHub (confirmed)', `Location on verified GitHub account`, 'high');
    }
    if (p.company && !report.identity.company) {
      report.identity.company = p.company;
      clues.add('company', p.company, 'GitHub (confirmed)', `Company on verified GitHub account`, 'high');
    }
    if (p.twitterUsername) clues.add('username', p.twitterUsername, 'GitHub (confirmed)', `Twitter linked from verified GitHub`, 'high');
    if (p.blog) clues.add('website', p.blog, 'GitHub (confirmed)', `Website from verified GitHub`, 'medium');
  }
  if (result.type === 'name' && result.fullName) {
    clues.add('name_inference', result.fullName, result.source, result.note, 'low');
    if (!report.identity.nameInferences) report.identity.nameInferences = [];
    report.identity.nameInferences.push({ name: result.fullName, source: result.source, note: result.note });
  }
  if (result.type === 'username' && result.value) {
    clues.add('username_hint', result.value, result.source, result.note, 'low');
  }

  // ── REPOS ──
  if (result.repos) {
    report.identity.repos = [...new Set([...(report.identity.repos || []), ...result.repos])];
    for (const repo of result.repos) clues.add('repo', repo, result.source, `Active repository`, 'medium');
  }
  if (result.totalCommits) {
    report.identity.totalCommits = result.totalCommits;
    clues.add('activity', `${result.totalCommits} public git commits`, result.source, 'Developer activity level', 'medium');
  }

  // ── SOCIAL PROFILES ──
  // Skip breach/intel platforms — they have their own handlers below
  const NON_SOCIAL_PLATFORMS = [
    'HIBP', 'Have I Been Pwned', 'HudsonRock Cavalier', 'Hudson Rock',
    'PDL', 'People Data Labs', 'FullContact',
    'Microsoft', 'Discord', 'Steam',
    // Wave 2
    'LeakLookup', 'Leak-Lookup', 'GhostProject', 'Have I Been Pwned', 'HIBP', 'EmailRep',
    'Gravatar', 'Clearbit',
    'Spotify', 'PayPal', 'Apple', 'Adobe', 'Twitch',
    'Roblox', 'Nintendo', 'BattleNet', 'RiotGames', 'Netflix',
    // Wave 3
    'Hunter', 'Hunter.io',
  ];
  if (result.platform && result.found && !NON_SOCIAL_PLATFORMS.includes(result.platform)) {
    // ── CONFIRMED GITHUB GUARD ───────────────────────────────────────────────
    // If we have a confirmed GitHub login from commit search, any other GitHub
    // profile (from username pivot) is provably a DIFFERENT person. Skip it entirely.
    if (result.platform === 'GitHub' && report._confirmedGitHubLogin && result.username !== report._confirmedGitHubLogin) {
      return; // This @conor / whoever is NOT our target — proven by commit email match
    }

    // Cross-platform GitHub link check: if this profile explicitly links to a
    // DIFFERENT GitHub account than our confirmed one, it's a different person → skip entirely
    if (report._confirmedGitHubLogin && result.githubUsername && result.githubUsername !== report._confirmedGitHubLogin) {
      return; // e.g. Dev.to @conor links to GitHub:purr — proven different person
    }

    // ── PROVIDER DOMAIN USERNAME GUARD ──────────────────────────────────────
    // If the probed username is a well-known email provider domain name (e.g. "hotmail",
    // "gmail"), any match is a random person who chose that word as their handle.
    // Discard the profile entirely — it will never be our target.
    const PROVIDER_USERNAMES = new Set([
      'gmail','yahoo','hotmail','outlook','live','msn','icloud','me','mac','aol',
      'protonmail','proton','tutanota','yandex','mail','inbox','zoho','gmx',
      'fastmail','bt','sky','comcast','verizon','att','sbcglobal','google',
      'facebook','apple','microsoft','amazon',
    ]);
    if (PROVIDER_USERNAMES.has((result.username || '').toLowerCase())) {
      return; // Username is an email-provider name — guaranteed different person
    }

    const profileName = result.name || result.displayName || null;
    const profileLocation = result.location || null;
    const profileCompany = result.company || null;
    // Only accept real bio text — filter out numeric junk, test data, counter strings
    const profileBio = (() => {
      const b = result.bio;
      if (!b || typeof b !== 'string' || b.trim().length < 8) return null;
      const t = b.trim();
      // Reject: "200 bio found", "0 scrobbles", "150 items", "3 repos", etc.
      if (/^\d+\s+\w/.test(t)) return null;
      // Reject: URLs as bio
      if (/^https?:\/\//.test(t)) return null;
      // Reject: "@username" as bio
      if (/^@[a-z0-9_]/i.test(t)) return null;
      // Reject: null/undefined literals
      if (/^(null|undefined|none|n\/a)$/i.test(t)) return null;
      // Reject: HTML artifacts
      if (/<[a-z]/i.test(t)) return null;
      // Require at least two words (real bios have multiple words)
      if (t.split(/\s+/).length < 2) return null;
      return t;
    })();

    // Discard ghost entries — profiles with no username AND no URL are noise
    const hasIdentifier = (result.username && result.username.trim()) || (result.profileUrl && result.profileUrl.startsWith('http'));
    if (!hasIdentifier) return;

    report.socialProfiles.push({
      platform: result.platform,
      username: result.username || null,
      profileUrl: result.profileUrl || null,
      name: profileName,
      location: profileLocation,
      hasPhone: result.hasLinkedPhone || false,
      company: profileCompany,
      bio: profileBio,
      twitterUsername: result.twitterUsername || null,
      blog: result.blog || null,
      photos: result.photos || [],
      accounts: result.accounts || [],
      urls: result.urls || [],
      followers: result.followers || null,
      publicRepos: result.publicRepos || null,
      karma: result.karma || null,
      created: result.created || result.joined || null,
      githubUsername: result.githubUsername || null,
    });

    // Clues from social
    if (result.username) clues.add('username', result.username, result.platform, `Username on ${result.platform}`, 'high');
    if (profileName) clues.add('name', profileName, result.platform, `Display name on ${result.platform}`, 'medium');
    if (profileLocation) clues.add('location', profileLocation, result.platform, `Location on ${result.platform}`, 'medium');
    if (profileCompany) clues.add('company', profileCompany, result.platform, `Company on ${result.platform}`, 'medium');
    if (profileBio) clues.add('bio', profileBio, result.platform, `Bio on ${result.platform}`, 'medium');
    if (result.twitterUsername) clues.add('username', result.twitterUsername, 'Twitter (via GitHub)', 'Twitter linked from GitHub profile', 'high');
    if (result.blog) clues.add('website', result.blog, result.platform, `Personal website from ${result.platform}`, 'medium');
    if (result.followers) clues.add('followers', `${result.followers} followers`, result.platform, `Follower count on ${result.platform}`, 'low');
    if (result.publicRepos) clues.add('activity', `${result.publicRepos} public repos`, result.platform, 'Developer activity', 'low');
    if (result.hasLinkedPhone) clues.add('phone_hint', 'Has linked phone', result.platform, `${result.platform} account has a linked phone number`, 'medium');
    if (result.hasPassword !== undefined) clues.add('auth', result.hasPassword ? 'Has password' : 'Passwordless', result.platform, 'Authentication method', 'low');

    // ── IDENTITY EXTRACTION GUARD ───────────────────────────────────────────
    // If we have a confirmed GitHub login (proven by email), any probe result
    // with a DIFFERENT username is statistically likely a different person.
    // Don't let ambiguous username-probe results contaminate identity data.
    // Exception: confirmedByEmail profiles always contribute to identity.
    const isAmbiguousProbe = report._confirmedGitHubLogin &&
        result.username && result.username !== report._confirmedGitHubLogin &&
        !result.confirmedByEmail;

    // Feed into identity card (skip ambiguous probes)
    if (!isAmbiguousProbe) {
      if (profileName && !report.identity.names.includes(profileName)) report.identity.names.push(profileName);
      if (profileLocation && !report.identity.locations.includes(profileLocation)) report.identity.locations.push(profileLocation);
      if (profileCompany && !report.identity.company) report.identity.company = profileCompany;
      if (profileBio && !report.identity.bio) report.identity.bio = profileBio;
    }

    if (result.twitterUsername) report.identity.socialLinks.push({ platform: 'twitter', value: '@' + result.twitterUsername });
    if (result.profileUrl) report.identity.socialLinks.push({ platform: result.platform.toLowerCase(), value: result.profileUrl });
    if (result.blog) report.identity.socialLinks.push({ platform: 'website', value: result.blog });
    if (result.accounts?.length > 0) {
      for (const acc of result.accounts) {
        if (acc.url) {
          report.identity.socialLinks.push({ platform: acc.shortname || acc.domain, value: acc.url });
          clues.add('linked_account', `${acc.shortname || acc.domain}: ${acc.url}`, 'Gravatar', 'Linked account from Gravatar profile', 'medium');
        }
      }
    }
  }

  // ── USERNAME PIVOT RESULTS ──
  if (result.source === 'Username Pivot' && result.foundOn) {
    // Drop pivot results from provider-name usernames (e.g. "hotmail", "gmail") —
    // these are random people who chose that word as a handle, not our target.
    const PROVIDER_PIVOT_NAMES = new Set([
      'gmail','yahoo','hotmail','outlook','live','msn','icloud','me','mac','aol',
      'protonmail','proton','tutanota','yandex','mail','inbox','zoho','gmx',
      'fastmail','bt','sky','comcast','verizon','att','sbcglobal','google',
      'facebook','apple','microsoft','amazon',
    ]);
    if (PROVIDER_PIVOT_NAMES.has((result.username || '').toLowerCase())) {
      return; // Entire pivot result is noise — provider name, not a personal username
    }

    for (const found of result.foundOn) {
      // ── CONFIRMED GITHUB GUARD (pivot path) ────────────────────────────────
      // If we confirmed the real GitHub login via commit authorship, block any
      // pivot result that found a DIFFERENT person's GitHub account.
      if (found.platform === 'GitHub' && report._confirmedGitHubLogin && result.username !== report._confirmedGitHubLogin) {
        continue; // This is a different "conor" on GitHub — not our target
      }

      clues.add('username_pivot', `${found.platform}: @${result.username}`, 'Username Pivot',
        `Same username "${result.username}" found on ${found.platform}`, 'medium');
      // Add as social profile if not already there
      if (!report.socialProfiles.find(p => p.platform === found.platform && p.username === result.username)) {
        // Don't add a platform entry that's already covered by a confirmed profile
        const alreadyConfirmed = report._confirmedGitHubLogin && found.platform === 'GitHub';
        if (!alreadyConfirmed) {
          report.socialProfiles.push({
            platform: found.platform,
            username: result.username,
            found: true,
            name: found.name || null,
            location: found.location || null,
            bio: found.bio || null,
            karma: found.karma || null,
            created: found.created || found.joined || null,
            viaUsernamePivot: true,
          });
        }
        // Only extract identity data if this platform is NOT GitHub (pivot may be wrong person)
        // For GitHub, only the confirmed profile contributes to identity
        if (found.platform !== 'GitHub') {
          if (found.name) {
            clues.add('name', found.name, found.platform, `Name from ${found.platform} (via username pivot)`, 'medium');
            if (!report.identity.names.includes(found.name)) report.identity.names.push(found.name);
          }
          if (found.location) {
            clues.add('location', found.location, found.platform, `Location from ${found.platform}`, 'medium');
            if (!report.identity.locations.includes(found.location)) report.identity.locations.push(found.location);
          }
        }
        if (found.twitterUsername) clues.add('username', found.twitterUsername, `${found.platform} → Twitter`, 'Cross-linked Twitter', 'high');
        if (found.githubUsername) clues.add('username', found.githubUsername, `${found.platform} → GitHub`, 'Cross-linked GitHub', 'high');
      }
    }
  }

  // ── EMAILREP DATA ──
  if (result.source === 'EmailRep.io') {
    if (result.reputation) clues.add('reputation', result.reputation, 'EmailRep.io', 'Email reputation score', 'medium');
    if (result.profiles?.length > 0) {
      for (const p of result.profiles) clues.add('profile_hint', p, 'EmailRep.io', `Known profile on ${p}`, 'medium');
    }
    if (result.firstSeen) clues.add('first_seen', result.firstSeen, 'EmailRep.io', 'First seen in the wild', 'medium');
    if (result.lastSeen) clues.add('last_seen', result.lastSeen, 'EmailRep.io', 'Last seen in the wild', 'medium');
    if (result.dataBreaches) clues.add('breach_flag', 'Yes', 'EmailRep.io', 'Email found in data breach(es)', 'medium');
    if (result.darkWeb) clues.add('dark_web', 'Yes', 'EmailRep.io', 'Email appeared on dark web', 'medium');
    if (result.credential_leaked) clues.add('cred_leak', 'Yes', 'EmailRep.io', 'Credentials leaked', 'medium');
    report.emailReputation = result;
  }

  // ── BREACH DATA ──
  if (result.source === 'HIBP' || result.platform === 'HIBP' ||
      result.source?.includes('Breach') ||
      result.source?.includes('Cavalier') || result.platform?.includes('Cavalier') ||
      result.source?.includes('IntelX') ||
      result.source?.includes('Leak') || result.source?.includes('Dehash')) {
    // Normalize: social-recon HIBP uses platform, not source
    if (!result.source && result.platform) result.source = result.platform;
    report.breachData.push(result);
  }

  // ── DNS ──
  if (result.source === 'DNS Recon') {
    report.dnsInfo.push(result);
    // Infer location from MX records (country-specific mail servers)
    const mxStr = (result.mxRecords || []).join(' ').toLowerCase();
    const MX_COUNTRY_MAP = {
      '.it.': 'Italy', '.it,': 'Italy', 'aruba.it': 'Italy', 'myantispam.it': 'Italy',
      '.de.': 'Germany', '.fr.': 'France', '.uk.': 'United Kingdom', '.co.uk': 'United Kingdom',
      '.nl.': 'Netherlands', '.es.': 'Spain', '.br.': 'Brazil', '.jp.': 'Japan',
      '.au.': 'Australia', '.ca.': 'Canada', '.ru.': 'Russia', '.ch.': 'Switzerland',
      '.at.': 'Austria', '.be.': 'Belgium', '.se.': 'Sweden', '.no.': 'Norway',
      '.dk.': 'Denmark', '.fi.': 'Finland', '.pl.': 'Poland', '.pt.': 'Portugal',
      '.cz.': 'Czech Republic', '.ro.': 'Romania', '.hu.': 'Hungary',
    };
    for (const [pattern, country] of Object.entries(MX_COUNTRY_MAP)) {
      if (mxStr.includes(pattern)) {
        clues.add('location', country, 'DNS MX Analysis', `MX records point to ${country}-based mail server`, 'low');
        if (!report.identity.locations.includes(country)) report.identity.locations.push(country);
        break;
      }
    }
  }

  // ── REGISTRATIONS ──
  if (result.source === 'Registration Checks') {
    report.registrations = {
      totalChecked: result.totalChecked,
      registeredOn: result.registeredOn || [],
      notRegisteredOn: result.notRegisteredOn || [],
      unknown: result.unknown || [],
    };
    for (const platform of (result.registeredOn || [])) {
      clues.add('registration', platform, 'Registration Check', `Email registered on ${platform}`, 'high');
    }
  }

  // ── ENRICHMENT ──
  if (result.source === 'Clearbit' || result.source === 'FullContact' || result.source === 'PeopleDataLabs') {
    if (!report.enrichment) report.enrichment = [];
    report.enrichment.push(result);

    if (result.person || result.name) {
      const name = result.person?.name || result.name;
      const location = result.person?.location || result.location;
      const title = result.person?.title || result.jobTitle || result.title;
      const company = result.person?.company || result.company;

      if (name) { clues.add('name', name, result.source, `Full name from ${result.source}`, 'high'); if (!report.identity.names.includes(name)) report.identity.names.push(name); }
      if (location) { clues.add('location', location, result.source, `Location from ${result.source}`, 'high'); if (!report.identity.locations.includes(location)) report.identity.locations.push(location); }
      if (title) { clues.add('job_title', title, result.source, `Job title from ${result.source}`, 'high'); report.identity.jobTitle = title; }
      if (company) { clues.add('company', company, result.source, `Company from ${result.source}`, 'high'); report.identity.company = company; }

      if (result.person?.avatar) clues.add('avatar', result.person.avatar, result.source, 'Profile photo URL', 'medium');
      if (result.gender) clues.add('gender', result.gender, result.source, `Gender from ${result.source}`, 'medium');
      if (result.age) clues.add('age_range', result.age, result.source, `Age range from ${result.source}`, 'medium');
      if (result.industry) clues.add('industry', result.industry, result.source, `Industry from ${result.source}`, 'medium');

      const socialFields = ['twitter', 'linkedin', 'facebook', 'github', 'twitterUrl', 'linkedinUrl', 'facebookUrl', 'githubUrl'];
      for (const f of socialFields) {
        const val = result.person?.[f] || result[f];
        if (val) {
          report.identity.socialLinks.push({ platform: f.replace('Url', ''), value: val });
          clues.add('social_link', val, result.source, `${f.replace('Url', '')} from ${result.source}`, 'high');
        }
      }
    }
  }

  // ── TRUECALLER ──
  if (result.source === 'Truecaller') {
    report.truecaller = result;
  }

  // ── EMAIL VERIFICATION ──
  if (result.source === 'VerifyMail' || result.source === 'Kickbox' || result.source === 'Hunter.io') {
    if (!report.emailVerification) report.emailVerification = {};
    Object.assign(report.emailVerification, result);
  }

  // ── RELATED EMAILS ──
  if (result.relatedEmails) {
    report.relatedEmails = [...new Set([...(report.relatedEmails || []), ...result.relatedEmails])];
    for (const e of result.relatedEmails) clues.add('related_email', e, result.source, 'Related email address', 'medium');
  }

  // ── RELATED DOMAINS ──
  if (result.domains) {
    report.relatedDomains = [...new Set([...(report.relatedDomains || []), ...result.domains])];
  }

  // ── STEALER DATA ──
  if (result.compromisedMachines) {
    report.stealerData = {
      compromisedMachines: result.compromisedMachines,
      usernames: result.usernames || [],
      ips: result.ips || [],
      urls: result.urls || [],
      partialPasswords: result.partialPasswords || [],
      dateCompromised: result.dateCompromised,
      operatingSystem: result.operatingSystem,
      malwareFamily: result.malwareFamily,
    };
    if (result.operatingSystem) clues.add('os', result.operatingSystem, 'HudsonRock', 'Operating system from stealer log', 'high');
    if (result.dateCompromised) clues.add('compromise_date', result.dateCompromised, 'HudsonRock', 'Date machine was compromised', 'high');
    if (result.malwareFamily) clues.add('malware', result.malwareFamily, 'HudsonRock', 'Malware family that compromised the machine', 'high');
    for (const ip of (result.ips || [])) clues.add('ip', ip, 'HudsonRock', 'IP from stealer log — possible home/work IP', 'medium');
    for (const u of (result.urls || []).slice(0, 10)) clues.add('visited_url', u, 'HudsonRock', 'URL from stealer log — sites the person used', 'medium');
    for (const un of (result.usernames || [])) clues.add('username', un, 'HudsonRock', 'Username from stealer log', 'high');
  }

  // ── RDAP / WHOIS DOMAIN INFO ──
  if (result.source === 'RDAP Domain') {
    if (result.registrar) clues.add('registrar', result.registrar, 'RDAP', 'Domain registrar', 'low');
    if (result.registrationDate) clues.add('domain_created', result.registrationDate, 'RDAP', 'Domain registration date', 'low');
  }
  if (result.source === 'RDAP WHOIS' && result.registrantName) {
    clues.add('registrant', result.registrantName, 'RDAP WHOIS', 'Domain registrant name', 'medium');
  }

  // ── EMAIL ANALYSIS ──
  if (result.source === 'Email Analysis') {
    // Already handled above (name inference)
  }

  // ── PASTEBIN ──
  if (result.pasteLinks) {
    for (const link of result.pasteLinks) clues.add('paste', link, 'Pastebin Dork', 'Email found in public paste', 'low');
  }

  // ── USERNAME PROBE HITS ──
  if (result.source?.startsWith('Username Probe') && result.found) {
    const platform = result.platform;
    if (!report.socialProfiles.find(p => p.platform === platform && p.username === result.username)) {
      report.socialProfiles.push({
        platform,
        username: result.username,
        profileUrl: result.profileUrl || null,
        name: result.name || null,
        location: result.location || null,
        bio: result.bio || null,
        company: result.company || null,
        blog: result.blog || null,
        twitterUsername: result.twitterUsername || null,
        followers: result.followers || null,
        publicRepos: result.publicRepos || null,
        karma: result.karma || null,
        created: result.created || null,
        found: true,
        viaUsernameScan: true,
      });
      if (result.username) clues.add('username', result.username, platform, `Username found on ${platform} via email username derivation`, 'medium');
      if (result.name) { clues.add('name', result.name, platform, `Name from ${platform}`, 'medium'); if (!report.identity.names.includes(result.name)) report.identity.names.push(result.name); }
      if (result.location) { clues.add('location', result.location, platform, `Location from ${platform}`, 'medium'); if (!report.identity.locations.includes(result.location)) report.identity.locations.push(result.location); }
      if (result.bio) clues.add('bio', result.bio, platform, `Bio from ${platform}`, 'medium');
      if (result.twitterUsername) clues.add('username', result.twitterUsername, platform, `Twitter linked from ${platform}`, 'high');
      if (result.blog) clues.add('website', result.blog, platform, `Website from ${platform}`, 'medium');
    }
  }

  // ── DEV REGISTRIES ──
  if (result.source === 'npm Registry' || result.source === 'PyPI Registry') {
    if (result.names) for (const n of result.names) { clues.add('name', n, result.source, `Package author name`, 'medium'); if (!report.identity.names.includes(n)) report.identity.names.push(n); }
    if (result.packages) clues.add('activity', `${result.packages.length} packages on ${result.source}`, result.source, 'Package author', 'medium');
  }

  if (result.source === 'Certificate Transparency') {
    if (result.subdomains?.length > 0) {
      for (const s of result.subdomains) clues.add('subdomain', s, 'Certificate Transparency', 'Subdomain from crt.sh', 'low');
    }
    if (result.emailInCert) clues.add('cert_hit', 'Email in TLS certificate', 'Certificate Transparency', 'Direct email match in certificate SAN/subject', 'medium');
  }

  if (result.source === 'GitHub Code Search') {
    if (result.names) for (const n of result.names) { clues.add('name', n, 'GitHub Code', `Name found near email in source code`, 'medium'); if (!report.identity.names.includes(n)) report.identity.names.push(n); }
    if (result.repos) for (const r of result.repos) clues.add('repo', r, 'GitHub Code Search', 'Repo containing this email in source', 'low');
    // New: phones extracted from public code context
    if (result.phones?.length > 0) {
      // Pre-filter: deduplicate and remove sequential-increment noise.
      // WHOIS serial numbers look like phone numbers (10 digits, valid area code)
      // but share identical first-4 AND last-4 digits with many others in the set
      // (e.g. 4509000831, 4509180831, 4509260831 — all start 4509, all end 0831).
      const phoneNums = [...new Set(result.phones)];

      // Build prefix|suffix map
      const prefixSuffixMap = {};
      for (const p of phoneNums) {
        const d = p.replace(/[^\d]/g, '');
        if (d.length >= 10) {
          const key = d.slice(0, 4) + '|' + d.slice(-4);
          if (!prefixSuffixMap[key]) prefixSuffixMap[key] = [];
          prefixSuffixMap[key].push(p);
        }
      }
      // If 4+ numbers share the same first-4 and last-4 digits → serial ID block, discard all
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

      for (const p of cleanPhones) clues.add('phone', p, 'GitHub Code Search', 'Phone found adjacent to email in public repository', 'high');
      allPhones.high.push(...cleanPhones);
    }
    if (result.totalFiles > 0) clues.add('activity', `Email in ${result.totalFiles} public GitHub file(s)`, 'GitHub Code Search', 'Developer footprint in public repos', result.phones?.length > 0 ? 'high' : 'low');
    if (result.contexts?.length > 0) {
      for (const ctx of result.contexts) clues.add('code_context', `${ctx.repo}/${ctx.file}`, 'GitHub Code Search', `Phone ${ctx.phones?.join(', ')} found in public file`, 'high');
    }
  }

  if (result.source === 'Breach.Directory' || result.source === 'BreachDirectory') {
    report.breachData.push(result);
    if (result.breachSources) for (const s of result.breachSources) clues.add('breach', s, result.source, `Found in breach: ${s}`, 'high');
    if (result.usernames) for (const u of result.usernames) clues.add('username', u, result.source, `Username from breach data`, 'high');
    if (result.names) for (const n of result.names) { clues.add('name', n, result.source, 'Real name from breach record', 'high'); if (!report.identity.names.includes(n)) report.identity.names.push(n); }
    if (result.totalRecords > 0) clues.add('breach_flag', `Found in ${result.totalRecords} record(s) across ${(result.breachSources||[]).length} source(s)`, result.source, result.note || '', 'high');
  }

  // Google Account Recovery probe — account existence + masked phone + GAIA
  if (result.source === 'Google Account Probe') {
    if (result.accountExists) {
      clues.add('registration', 'Google Account', 'Google Account Probe', 'Gmail account confirmed active', 'high');
      if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
      if (!report.registrations.registeredOn.includes('Google/Gmail')) report.registrations.registeredOn.push('Google/Gmail');
    }
    if (result.displayName) {
      clues.add('name', result.displayName, 'Google Account Probe', 'Display name from Google profile', 'high');
      if (!report.identity.names.includes(result.displayName)) report.identity.names.push(result.displayName);
    }
    if (result.gaiaId) clues.add('gaia_id', result.gaiaId, 'Google Account Probe', 'Google Account GAIA ID', 'high');
    // maskedPhone handled by the generic result.maskedPhone handler below
  }

  // Proxynova partial phone fragments — separate from full phones
  if (result.source === 'Proxynova COMB (partial)' && result.partialPhones?.length > 0) {
    for (const p of result.partialPhones) {
      clues.add('partial_phone', p, 'Proxynova COMB', `Truncated phone fragment from breach dump (${p.replace(/\D/g,'').length} digits — may be partial)`, 'low');
    }
  }

  if (result.source === 'SEC EDGAR') {
    for (const f of (result.filings || [])) {
      clues.add('sec_filing', `${f.company} - ${f.form} (${f.date})`, 'SEC EDGAR', 'Email in public SEC filing', 'high');
      if (f.company && !report.identity.company) { report.identity.company = f.company; clues.add('company', f.company, 'SEC EDGAR', 'Company from SEC filing', 'high'); }
    }
  }

  if (result.source === 'Paste Intelligence') {
    if (result.pasteLinks) for (const link of result.pasteLinks) clues.add('paste', link, 'Paste Intelligence', 'Email leaked in paste', 'medium');
    if (result.names) for (const n of result.names) { clues.add('name', n, 'Paste Intelligence', 'Name found near email in paste', 'medium'); if (!report.identity.names.includes(n)) report.identity.names.push(n); }
    if (result.hasPasswordLeak) clues.add('cred_leak', 'Yes', 'Paste Intelligence', 'Password found near email in paste dump', 'high');
  }

  if (result.source === 'Stack Overflow' && result.found) {
    report.socialProfiles.push({ platform: 'Stack Overflow', username: result.name, profileUrl: result.profileUrl, name: result.name, location: result.location, karma: result.reputation, found: true });
    if (result.name) { clues.add('name', result.name, 'Stack Overflow', 'Display name on Stack Overflow (inferred)', 'low'); }
    if (result.location) { clues.add('location', result.location, 'Stack Overflow', 'Location on Stack Overflow', 'low'); }
  }

  if (result.source === 'Internet Archive' || result.source === 'Wayback Machine') {
    if (result.urls) for (const u of result.urls) clues.add('archived_url', u, 'Wayback Machine', 'Archived page containing this email', 'low');
  }

  // ── PHONE HARVEST ──
  if (result.source === 'People Search Brokers' && result.phones?.length > 0) {
    for (const p of result.phones) clues.add('phone', p, 'People Search Brokers', `Phone from data broker scrape (name: ${result.name})`, 'medium');
    allPhones.medium.push(...result.phones);
  }

  if ((result.source === 'LeakCheck.io' || result.source === 'Proxynova COMB') && result.found) {
    report.breachData.push(result);
    clues.add('breach_flag', `Found in ${result.totalRecords} records`, result.source, `Email indexed in ${result.source}`, 'high');
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, result.source, 'Phone from leak database', 'high'); }
  }

  if ((result.source === 'Snusbase' || result.source === 'Dehashed') && result.found) {
    report.breachData.push(result);
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, result.source, 'Leaked phone number from breach database', 'high'); }
    if (result.names?.length > 0) { for (const n of result.names) { clues.add('name', n, result.source, `Real name from breach record`, 'high'); if (!report.identity.names.includes(n)) report.identity.names.push(n); } }
    if (result.usernames?.length > 0) { for (const u of result.usernames) clues.add('username', u, result.source, 'Username from breach record', 'high'); }
    if (result.ips?.length > 0) { for (const ip of result.ips) clues.add('ip', ip, result.source, 'IP address from breach record', 'high'); }
  }

  // Hudson Rock Cavalier — stealer log intelligence
  if (result.source === 'Hudson Rock Cavalier') {
    if (result.found) {
      report.breachData.push(result);
      clues.add('breach_flag', `Found in ${result.totalStealers} stealer log(s)`, 'Hudson Rock', `${result.credentialCount} credentials across: ${(result.platforms||[]).slice(0,5).join(', ')}`, 'high');
      if (result.ips?.length > 0) { for (const ip of result.ips) clues.add('ip', ip, 'Hudson Rock', 'IP from infected machine in stealer log', 'high'); }
      if (result.computers?.length > 0) { for (const c of result.computers) clues.add('hostname', c, 'Hudson Rock', 'Computer name from stealer log', 'medium'); }
    } else {
      clues.add('breach_flag', 'Not in stealer logs', 'Hudson Rock', result.note || '', 'low');
    }
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, 'Hudson Rock', 'Phone extracted from stealer log data', 'high'); }
  }

  // People Data Labs — commercial enrichment API (key-gated, free tier)
  if (result.source === 'People Data Labs' && result.found) {
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, 'People Data Labs', 'Phone from PDL enrichment database', 'high'); }
    if (result.names?.length > 0) { for (const n of result.names) { clues.add('name', n, 'People Data Labs', 'Name from PDL database', 'high'); if (!report.identity.names.includes(n)) report.identity.names.push(n); } }
    if (result.location) { clues.add('location', result.location, 'People Data Labs', 'Location from PDL database', 'medium'); if (!report.identity.locations.includes(result.location)) report.identity.locations.push(result.location); }
    if (result.linkedin) clues.add('website', result.linkedin, 'People Data Labs', 'LinkedIn URL from PDL database', 'high');
  }

  // FullContact — commercial enrichment API (key-gated, 250/month free)
  if (result.source === 'FullContact' && result.found) {
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, 'FullContact', 'Phone from FullContact enrichment database', 'high'); }
    if (result.names?.length > 0) { for (const n of result.names) { clues.add('name', n, 'FullContact', 'Name from FullContact database', 'high'); if (!report.identity.names.includes(n)) report.identity.names.push(n); } }
    if (result.location) { clues.add('location', result.location, 'FullContact', 'Location from FullContact database', 'medium'); }
  }

  // Microsoft Account Probe — for @hotmail/@outlook/@live accounts
  if (result.source === 'Microsoft Account Probe') {
    if (result.accountExists) {
      clues.add('registration', 'Microsoft Account', 'Microsoft Account Probe', 'Microsoft account confirmed active', 'high');
      if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
      if (!report.registrations.registeredOn.includes('Microsoft')) report.registrations.registeredOn.push('Microsoft');
    }
    if (result.displayName) { clues.add('name', result.displayName, 'Microsoft Account Probe', 'Display name from Microsoft account', 'high'); if (!report.identity.names.includes(result.displayName)) report.identity.names.push(result.displayName); }
    // maskedPhone is handled by the generic maskedPhone handler below
  }

  // Discord Probe — account existence (no phone leak, but confirms platform presence)
  if (result.source === 'Discord Probe' && result.exists) {
    clues.add('registration', 'Discord', 'Discord Probe', 'Discord account found for this email', 'medium');
    if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
    if (!report.registrations.registeredOn.includes('Discord')) report.registrations.registeredOn.push('Discord');
  }

  // Steam Probe — account existence
  if (result.source === 'Steam Probe' && result.exists) {
    clues.add('registration', 'Steam', 'Steam Probe', 'Steam account registered with this email', 'medium');
    if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
    if (!report.registrations.registeredOn.includes('Steam')) report.registrations.registeredOn.push('Steam');
  }

  // ── Wave 2 breach/enrichment sources ─────────────────────────────────────

  // Leak-Lookup
  if (result.source === 'Leak-Lookup' && result.found) {
    report.breachData = report.breachData || [];
    report.breachData.push(result);
    clues.add('breach_flag', `Leak-Lookup: ${result.totalRecords || result.lineCount || 0} records in ${(result.breachSources||[]).slice(0,5).join(', ')}`, 'Leak-Lookup', 'Email found in Leak-Lookup breach corpus', 'high');
    if (result.phones?.length > 0) {
      allPhones.high.push(...result.phones);
      for (const p of result.phones) clues.add('phone', p, 'Leak-Lookup', 'Phone extracted from Leak-Lookup breach record', 'high');
    }
  }

  // Have I Been Pwned / GhostProject (former slot — replaced with HIBP)
  if ((result.source === 'Have I Been Pwned' || result.source === 'GhostProject') && result.found) {
    report.breachData = report.breachData || [];
    report.breachData.push(result);
    const srcLabel = result.source === 'Have I Been Pwned' ? `HIBP: ${result.breachCount} breach(es)` : `GhostProject: ${result.recordCount} record(s)`;
    const srcNames = (result.breachSources || []).slice(0,4).join(', ') || 'breach DB';
    clues.add('breach_flag', `${srcLabel} — ${srcNames}${result.hasPhoneField ? ' ⚠ phone data exposed' : ''}`, result.source, 'Email confirmed in breach database', 'high');
  }

  // EmailRep
  if (result.source === 'EmailRep.io') {
    if (result.credentialsLeaked) clues.add('breach_flag', 'Credentials leaked (EmailRep)', 'EmailRep.io', 'EmailRep confirms credentials in breach data', 'high');
    if (result.profiles?.length > 0) {
      for (const p of result.profiles) {
        clues.add('registration', p, 'EmailRep.io', `EmailRep linked account: ${p}`, 'medium');
        if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
        if (!report.registrations.registeredOn.includes(p)) report.registrations.registeredOn.push(p);
      }
    }
  }

  // Gravatar
  if (result.source === 'Gravatar' && result.found) {
    if (result.displayName) { clues.add('name', result.displayName, 'Gravatar', 'Display name from Gravatar profile', 'medium'); if (!report.identity.names.includes(result.displayName)) report.identity.names.push(result.displayName); }
    if (result.location) clues.add('location', result.location, 'Gravatar', 'Location from Gravatar profile', 'medium');
    for (const u of (result.urls || [])) clues.add('website', u, 'Gravatar', 'URL from Gravatar profile', 'low');
    for (const a of (result.linkedAccounts || [])) { clues.add('registration', a, 'Gravatar', `Gravatar linked account: ${a}`, 'medium'); if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 }; if (!report.registrations.registeredOn.includes(a)) report.registrations.registeredOn.push(a); }
    if (result.phones?.length > 0) {
      allPhones.medium.push(...result.phones);
      for (const p of result.phones) clues.add('phone', p, 'Gravatar', 'Phone found in Gravatar profile data', 'medium');
    }
  }

  // Clearbit
  if (result.source === 'Clearbit' && result.found) {
    if (result.name) { clues.add('name', result.name, 'Clearbit', 'Full name from Clearbit enrichment', 'high'); if (!report.identity.names.includes(result.name)) report.identity.names.push(result.name); }
    if (result.location) clues.add('location', result.location, 'Clearbit', 'Location from Clearbit', 'high');
    if (result.linkedin) clues.add('website', result.linkedin, 'Clearbit', 'LinkedIn from Clearbit', 'high');
    if (result.company) clues.add('employer', result.company, 'Clearbit', 'Employer from Clearbit', 'high');
    if (result.phones?.length > 0) {
      allPhones.high.push(...result.phones);
      for (const p of result.phones) clues.add('phone', p, 'Clearbit', 'Phone from Clearbit enrichment', 'high');
    }
  }

  // ── Wave 2 platform probes ───────────────────────────────────────────────
  const WAVE2_PLATFORMS = ['Spotify Probe','PayPal Probe','Apple ID Probe','Adobe Probe',
    'Twitch Probe','Roblox Probe','Nintendo Probe','Battle.net Probe','Riot Games Probe','Netflix Probe'];
  if (WAVE2_PLATFORMS.includes(result.source) && result.exists) {
    const platform = result.platform || result.source.replace(' Probe','');
    clues.add('registration', platform, result.source, `${platform} account found for this email`, 'medium');
    if (!report.registrations) report.registrations = { registeredOn: [], notRegisteredOn: [], unknown: [], totalChecked: 0 };
    if (!report.registrations.registeredOn.includes(platform)) report.registrations.registeredOn.push(platform);
    // Masked phones from these platforms (Apple, Nintendo, Battle.net, etc.)
    // are handled by the generic maskedPhone handler below
  }

  if (result.source === 'IntelX Deep Search' && result.phones?.length > 0) {
    allPhones.high.push(...result.phones);
    for (const p of result.phones) clues.add('phone', p, 'IntelX', 'Phone extracted from IntelX dark web / paste / breach index', 'high');
    if (result.darkWebHits > 0) clues.add('dark_web', `${result.darkWebHits} dark web hits`, 'IntelX', 'Email found on dark web sources', 'high');
  }

  if (result.source === 'Truecaller' && result.phones?.length > 0) {
    allPhones.high.push(...result.phones);
    for (const p of result.phones) clues.add('phone', p, 'Truecaller', `Truecaller confirmed: ${result.name || 'unknown name'}`, 'high');
    if (result.name) { clues.add('name', result.name, 'Truecaller', 'Caller ID name from Truecaller', 'high'); if (!report.identity.names.includes(result.name)) report.identity.names.push(result.name); }
    if (result.location) { clues.add('location', result.location, 'Truecaller', 'Location from Truecaller', 'medium'); }
    if (result.carrier) clues.add('carrier', result.carrier, 'Truecaller', `Phone carrier: ${result.carrier}`, 'medium');
  }

  if (result.maskedPhone) {
    // Only store if it looks like a real masked phone (contains * or •, reasonable length)
    const mp = result.maskedPhone;
    if (/[*•X]/.test(mp) && mp.replace(/[^0-9]/g,'').length >= 2) {
      clues.add('partial_phone', mp, result.source, result.note || 'Masked recovery phone', 'medium');
      if (!report.partialPhone) report.partialPhone = mp;
    }
  }

  if ((result.source === 'SecurityTrails WHOIS' || result.source === 'ViewDNS WHOIS') && result.phones?.length > 0) {
    for (const p of result.phones) { allPhones.medium.push(p); clues.add('phone', p, result.source, `Phone from historical WHOIS record for ${result.domain}`, 'medium'); }
    if (result.registrantName) { clues.add('name', result.registrantName, result.source, 'Domain registrant name from WHOIS', 'high'); if (!report.identity.names.includes(result.registrantName)) report.identity.names.push(result.registrantName); }
  }

  // ── DARK INTEL (DarkSearch, Ahmia, GhostProject, HaveIBeenSold, Spy.pet, Shodan, IntelX Deep) ──
  if (result.source === 'DarkSearch.io' || result.source === 'Ahmia.fi (Tor)') {
    report.breachData.push(result);
    clues.add('dark_web', `${result.totalResults} result(s) on ${result.source}`, result.source, result.note || 'Dark web exposure', 'high');
    if (result.phones?.length > 0) { allPhones.high.push(...result.phones); for (const p of result.phones) clues.add('phone', p, result.source, `Phone extracted from dark web`, 'high'); }
  }

  if (result.source === 'GhostProject.fr' && result.found) {
    report.breachData.push(result);
    clues.add('breach_flag', `${result.totalRecords} plaintext record(s)`, 'GhostProject.fr', result.note || 'Plaintext breach records', 'high');
    if (result.hasPasswords) clues.add('cred_leak', 'YES', 'GhostProject.fr', 'Cleartext password(s) found in GhostProject breach data', 'high');
    if (result.breachSources?.length > 0) for (const s of result.breachSources) clues.add('breach_flag', s, 'GhostProject.fr', `Breach source: ${s}`, 'high');
  }

  if (result.source === 'HaveIBeenSold' && result.found) {
    report.breachData.push(result);
    clues.add('breach_flag', 'Sold to data brokers', 'HaveIBeenSold', 'Email address sold to marketing data broker networks', 'medium');
    if (result.sources?.length > 0) for (const s of result.sources) clues.add('registration', s, 'HaveIBeenSold', 'Data broker that purchased this email', 'low');
  }

  if (result.source === 'Spy.pet' && result.found) {
    report.breachData.push(result);
    if (result.username) { clues.add('username', result.username, 'Spy.pet', 'Discord username from breach database', 'high'); }
    if (result.discordId) clues.add('discord_id', result.discordId, 'Spy.pet', 'Discord user ID from Spy.pet', 'high');
  }

  if (result.source === 'Shodan' && result.found) {
    if (result.ips?.length > 0) for (const ip of result.ips) clues.add('ip', ip, 'Shodan', `Infrastructure IP for ${result.domain}`, 'low');
    if (result.ports?.length > 0) clues.add('activity', `Ports: ${result.ports.join(', ')}`, 'Shodan', `Open ports on ${result.domain} infrastructure`, 'low');
  }

  if (result.source === 'IntelX Deep' && result.found) {
    report.breachData.push(result);
    if (result.darkweb > 0)  clues.add('dark_web',   `${result.darkweb} records`,  'IntelX Deep', 'Dark web exposure in IntelX index', 'high');
    if (result.pastes > 0)   clues.add('paste',       `${result.pastes} pastes`,   'IntelX Deep', 'Paste exposure in IntelX index', 'high');
    if (result.breaches > 0) clues.add('breach_flag', `${result.breaches} breaches`,'IntelX Deep', 'Breach records in IntelX index', 'high');
  }

  // ── CORP INTEL (OpenCorporates, LinkedIn, GitHub Org, Hunter.io, Domain Intel) ──
  if (result.source === 'OpenCorporates' && result.found) {
    for (const c of (result.companies || [])) {
      if (c.name) { clues.add('company', c.name, 'OpenCorporates', `${result.name} — ${c.role || 'officer'} ${c.jurisdiction ? '[' + c.jurisdiction + ']' : ''}`, 'high'); if (!report.identity.company) report.identity.company = c.name; }
      if (c.address) { clues.add('location', c.address, 'OpenCorporates', 'Business address from company officer record', 'medium'); if (!report.identity.locations.includes(c.address)) report.identity.locations.push(c.address); }
    }
  }

  if (result.source === 'LinkedIn' && result.found) {
    for (const p of (result.profiles || [])) {
      if (p.name) { clues.add('name', p.name, 'LinkedIn', 'Full name from LinkedIn', 'high'); if (!report.identity.names.includes(p.name)) report.identity.names.push(p.name); }
      if (p.headline) { clues.add('job_title', p.headline, 'LinkedIn', 'Professional headline from LinkedIn', 'high'); if (!report.identity.jobTitle) report.identity.jobTitle = p.headline; }
      if (p.location) { clues.add('location', p.location, 'LinkedIn', 'Location from LinkedIn', 'high'); if (!report.identity.locations.includes(p.location)) report.identity.locations.push(p.location); }
      if (p.profileUrl) { clues.add('social_link', p.profileUrl, 'LinkedIn', 'LinkedIn profile URL', 'high'); report.identity.socialLinks.push({ platform: 'LinkedIn', value: p.profileUrl }); }
      if (!report.socialProfiles.find(s => s.platform === 'LinkedIn' && s.username === p.publicId)) {
        report.socialProfiles.push({ platform: 'LinkedIn', username: p.publicId, name: p.name, location: p.location, bio: p.headline, profileUrl: p.profileUrl, found: true });
      }
    }
  }

  if (result.source === 'GitHub Org') {
    for (const m of (result.members || [])) clues.add('username', m, 'GitHub Org', `GitHub member of org @${result.org}`, 'medium');
  }

  if (result.source === 'Hunter.io' && (result.emails?.length > 0 || result.phones?.length > 0)) {
    if (result.phones?.length > 0) { allPhones.medium.push(...result.phones); for (const p of result.phones) clues.add('phone', p, 'Hunter.io', 'Employee phone from Hunter domain search', 'medium'); }
    if (result.emails?.length > 0) { report.relatedEmails = [...new Set([...(report.relatedEmails||[]), ...result.emails])]; for (const e of result.emails) clues.add('related_email', e, 'Hunter.io', 'Co-worker email from Hunter domain search', 'medium'); }
    if (result.names?.length > 0) for (const n of result.names) { clues.add('name', n, 'Hunter.io', 'Employee name from Hunter domain search', 'medium'); if (!report.identity.names.includes(n)) report.identity.names.push(n); }
    if (result.organization) { clues.add('company', result.organization, 'Hunter.io', 'Company name from Hunter domain search', 'high'); if (!report.identity.company) report.identity.company = result.organization; }
  }

  if (result.source === 'Domain Intel') {
    if (result.phones?.length > 0) { allPhones.medium.push(...result.phones); for (const p of result.phones) clues.add('phone', p, 'Domain Intel', `Phone scraped from ${result.domain} company pages`, 'medium'); }
    if (result.emails?.length > 0) { report.relatedEmails = [...new Set([...(report.relatedEmails||[]), ...result.emails])]; for (const e of result.emails) clues.add('related_email', e, 'Domain Intel', `Co-worker email on ${result.domain}`, 'medium'); }
  }
}

function buildReport(email, results) {
  const clues = new ClueTracker();
  const report = {
    target: email,
    timestamp: new Date().toISOString(),
    phones: { confirmed: [], probable: [], possible: [] },
    identity: {
      names: [], nameInferences: [], locations: [], jobTitle: null, company: null,
      bio: null, socialLinks: [], repos: [], totalCommits: 0,
    },
    socialProfiles: [],
    registrations: { totalChecked: 0, registeredOn: [], notRegisteredOn: [], unknown: [] },
    breachData: [],
    dnsInfo: [],
    enrichment: [],
    emailVerification: null,
    emailReputation: null,
    relatedEmails: [],
    relatedDomains: [],
    stealerData: null,
    truecaller: null,
    partialPhone: null,
    clues: [],
    rawFindings: [],
    summary: {
      totalSources: 0,
      totalPhonesFound: 0,
      highestConfidence: 'none',
      enginesRan: [],
    },
  };

  const allPhones = { high: [], medium: [], low: [] };

  for (const result of results) {
    if (!result) continue;
    if (Array.isArray(result)) {
      for (const r of result) processResult(r, allPhones, report, clues);
    } else {
      processResult(result, allPhones, report, clues);
    }
  }

  // ── POST-PROCESSING: Remove stray wrong-GitHub profiles ───────────────────
  // Belt-and-suspenders: after ALL results, strip any GitHub profiles that
  // aren't the confirmed login (handles edge cases where guards were bypassed).
  if (report._confirmedGitHubLogin) {
    report.socialProfiles = report.socialProfiles.filter(sp =>
      !(sp.platform === 'GitHub' && sp.username !== report._confirmedGitHubLogin)
    );
  }

  // Validate + enrich each tier — numbers that fail libphonenumber are dropped (noise).
  // possibleOnly phones (isPossible but not isValid — new/unlisted area codes) are always
  // capped at the 'possible' tier regardless of which allPhones bucket they came from.
  const enrichTierResult = (phones) => {
    const seen = new Set();
    const enriched = [];
    const spillToPossible = []; // possibleOnly numbers get capped here
    for (const raw of deduplicatePhones(phones)) {
      const e = enrichPhone(raw);
      if (!e) continue;
      if (!seen.has(e.e164)) {
        seen.add(e.e164);
        if (e.possibleOnly) spillToPossible.push(e);
        else enriched.push(e);
      }
    }
    return { enriched, spillToPossible };
  };

  const highRes    = enrichTierResult(allPhones.high);
  const medRes     = enrichTierResult(allPhones.medium);
  const lowRes     = enrichTierResult(allPhones.low);

  const confirmedEnriched = highRes.enriched;
  const probableEnriched  = medRes.enriched;
  const possibleEnriched  = [
    ...lowRes.enriched,
    ...highRes.spillToPossible,
    ...medRes.spillToPossible,
    ...lowRes.spillToPossible,
  ];

  // Cross-tier dedup — keep each number in its highest confidence tier only
  const seenAcross = new Set();
  let confirmedFinal = confirmedEnriched.filter(p => { const ok = !seenAcross.has(p.e164); seenAcross.add(p.e164); return ok; });
  let probableFinal  = probableEnriched.filter(p =>  { const ok = !seenAcross.has(p.e164); seenAcross.add(p.e164); return ok; });
  let possibleFinal  = possibleEnriched.filter(p =>  { const ok = !seenAcross.has(p.e164); seenAcross.add(p.e164); return ok; });

  // Corroboration: a phone in confirmed tier that only has 1 source gets
  // downgraded to probable until reverse-lookup (Phase 4) or verification (Phase 5) confirms it
  const phoneSourceMap = allPhones._sources || {};
  const singleSourceConfirmed = [];
  const stillConfirmed = [];
  for (const phone of confirmedFinal) {
    const norm = (phone.e164 || '').replace(/[^\d+]/g, '');
    const sourceCount = phoneSourceMap[norm]?.size || 1;
    if (sourceCount < 2) {
      // Mark it but move to probable — Phase 4/5 can upgrade it back
      singleSourceConfirmed.push({ ...phone, corrobPending: true, sourceCount });
    } else {
      phone.sourceCount = sourceCount;
      stillConfirmed.push(phone);
    }
  }
  confirmedFinal = stillConfirmed;
  // Single-source "high" phones go to probable with a note
  const probableSeenE164 = new Set(probableFinal.map(p => p.e164));
  for (const p of singleSourceConfirmed) {
    if (!probableSeenE164.has(p.e164)) probableFinal.push(p);
  }

  report.phones.confirmed = confirmedFinal;
  report.phones.probable  = probableFinal;
  report.phones.possible  = possibleFinal;

  const totalPhones = report.phones.confirmed.length +
    report.phones.probable.length +
    report.phones.possible.length;

  report.summary.totalPhonesFound = totalPhones;
  report.summary.highestConfidence = report.phones.confirmed.length > 0 ? 'high' :
    report.phones.probable.length > 0 ? 'medium' :
    report.phones.possible.length > 0 ? 'low' : 'none';

  // Deduplicate identity social links
  const seenLinks = new Set();
  report.identity.socialLinks = report.identity.socialLinks.filter(l => {
    const key = `${l.platform}:${l.value}`;
    if (seenLinks.has(key)) return false;
    seenLinks.add(key);
    return true;
  });

  // Deduplicate social profiles: one entry per platform+username combination
  const seenProfiles = new Set();
  report.socialProfiles = report.socialProfiles.filter(p => {
    const key = `${p.platform}::${(p.username || '').toLowerCase()}`;
    if (seenProfiles.has(key)) return false;
    seenProfiles.add(key);
    return true;
  });

  // Attach all clues sorted by confidence
  const confOrder = { high: 0, medium: 1, low: 2 };
  report.clues = clues.getAll().sort((a, b) => (confOrder[a.confidence] || 2) - (confOrder[b.confidence] || 2));

  return report;
}

async function runFullScan(email, progressCallback) {
  const pc = (msg) => { if (progressCallback) progressCallback(msg); };

  // ── Phase 1: DNS + Social recon (fast, baseline fingerprint) ──────────────
  pc({ engine: 'DNS Reconnaissance', progress: 5, status: 'running' });
  const [dnsResult, socialResult] = await Promise.allSettled([
    dnsRecon(email).catch(e => ({ source: 'DNS', error: e.message })),
    socialRecon(email, progressCallback).catch(e => []),
  ]);
  const phase1Results = [
    dnsResult.status === 'fulfilled' ? dnsResult.value : null,
    ...(Array.isArray(socialResult.value) ? socialResult.value : [socialResult.value]),
  ].filter(Boolean);

  // Extract all usernames found in phase 1 for pivot
  const foundUsernames = new Set(generateUsernames(email));
  for (const result of phase1Results) {
    if (!result) continue;
    const items = Array.isArray(result) ? result : [result];
    for (const item of items) {
      if (item?.username) foundUsernames.add(item.username);
      if (item?.twitterUsername) foundUsernames.add(item.twitterUsername);
      if (item?.githubUsername) foundUsernames.add(item.githubUsername);
    }
  }

  // Extract names + locations from phase 1 to feed phone harvest
  const phase1Names = [];
  const phase1Locations = [];
  for (const result of phase1Results) {
    if (!result) continue;
    const items = Array.isArray(result) ? result : [result];
    for (const item of items) {
      if (item?.name && !phase1Names.includes(item.name)) phase1Names.push(item.name);
      if (item?.displayName && !phase1Names.includes(item.displayName)) phase1Names.push(item.displayName);
      if (item?.location && !phase1Locations.includes(item.location)) phase1Locations.push(item.location);
      if (item?.authorNames) phase1Names.push(...item.authorNames.filter(n => !phase1Names.includes(n)));
    }
  }

  // ── Phase 2: All heavy engines in parallel ─────────────────────────────────
  pc({ engine: 'Deep enumeration + breaches + dorking + registries + phone harvest', progress: 20, status: 'running' });

  const phase2Engines = await Promise.allSettled([
    deepEnum(email, progressCallback),
    peopleSearch(email, [...foundUsernames]),
    breachIntel(email, progressCallback),
    dorkSearch(email, progressCallback),
    usernameScan(email, progressCallback),
    devRegistriesScan(email, progressCallback),
    pasteIntel(email, progressCallback),
    phoneHarvest(email, phase1Names, phase1Locations, progressCallback),
    darkIntelScan(email, progressCallback),
    corpIntelScan(email, phase1Names, progressCallback),
    breachScraperScan(email, progressCallback),
  ]);

  pc({ engine: 'Processing phase 2 results', progress: 75, status: 'running' });

  const phase2Results = phase2Engines
    .map(r => r.status === 'fulfilled' ? r.value : null)
    .filter(Boolean)
    .flat();

  // Extract any NEW usernames discovered in phase 2 for recursive pivot
  const newUsernames = new Set();
  for (const result of phase2Results) {
    if (!result) continue;
    const items = Array.isArray(result) ? result : [result];
    for (const item of items) {
      if (item?.username && !foundUsernames.has(item.username)) newUsernames.add(item.username);
      if (item?.usernames) for (const u of item.usernames) if (!foundUsernames.has(u)) newUsernames.add(u);
      // CONFIRMED GitHub login from commit authorship — always pivot this, high priority
      if (item?.githubLogin && !foundUsernames.has(item.githubLogin)) {
        newUsernames.add(item.githubLogin);
        foundUsernames.add(item.githubLogin);
      }
    }
  }

  // ── Phase 3: Recursive pivot on newly discovered usernames ─────────────────
  let phase3Results = [];
  if (newUsernames.size > 0) {
    pc({ engine: `Recursive pivot on ${newUsernames.size} new username(s)`, progress: 80, status: 'running' });
    const pivotResults = await Promise.allSettled(
      [...newUsernames].slice(0, 5).map(u => usernamePivot(u))
    );
    phase3Results = pivotResults
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value)
      .filter(Boolean)
      .flat();

  }

  pc({ engine: 'Aggregation & Cross-Reference', progress: 90, status: 'finalizing' });

  const report = buildReport(email, [...phase1Results, ...phase2Results, ...phase3Results]);

  // Phase 3: Numverify carrier lookup — confirmed phones only, max 5, gated on API key
  if (process.env.NUMVERIFY_API_KEY && report.phones.confirmed.length > 0) {
    if (progressCallback) progressCallback({ engine: 'Phone Carrier Lookup (Numverify)', progress: 99, status: 'running' });
    const axios = require('axios');
    report.phones.confirmed = await Promise.all(
      report.phones.confirmed.slice(0, 5).map(async (phone) => {
        try {
          const digits = (phone.e164 || phone.raw).replace(/[^\d]/g, '');
          const resp = await axios.get('http://apilayer.net/api/validate', {
            params: { access_key: process.env.NUMVERIFY_API_KEY, number: digits, format: 1 },
            timeout: 8000,
            validateStatus: () => true,
          });
          if (resp?.status === 200 && resp.data?.valid) {
            return {
              ...phone,
              carrier: resp.data.carrier || null,
              lineType: resp.data.line_type || phone.type,
              location: resp.data.location || phone.location || null,
            };
          }
        } catch (e) {}
        return phone;
      })
    );
  }

  // ── Phase 4: Auto reverse-lookup any phones already found ─────────────────
  const allFoundPhoneStrs = [
    ...report.phones.confirmed.map(p => p.e164 || p.formatted || p.raw),
    ...report.phones.probable.map(p  => p.e164 || p.formatted || p.raw),
  ].filter(Boolean);

  if (allFoundPhoneStrs.length > 0) {
    if (progressCallback) progressCallback({ engine: 'Reverse Phone Lookup Cascade', progress: 96, status: 'running' });
    try {
      const reverseResults = await reversePhoneLookup(allFoundPhoneStrs);
      for (const r of reverseResults) {
        if (r.callerName) {
          if (!report.identity.names.includes(r.callerName)) report.identity.names.push(r.callerName);
          report.clues.push({ type: 'name', value: r.callerName, source: r.sources.join(' + '), note: 'Caller ID name from reverse phone lookup', confidence: 'high' });
        }
        if (r.carrier) {
          report.clues.push({ type: 'carrier', value: `${r.carrier} (${r.phone})`, source: r.sources.join(' + '), note: `Carrier for ${r.phone}`, confidence: 'medium' });
        }
        if (r.whatsapp) {
          report.clues.push({ type: 'registration', value: 'WhatsApp', source: 'Reverse Lookup', note: `${r.phone} is active on WhatsApp`, confidence: 'high' });
        }
        if (r.location) {
          report.clues.push({ type: 'location', value: r.location, source: r.sources.join(' + '), note: `Region from phone carrier data`, confidence: 'low' });
        }
      }
    } catch (e) {}
  }

  // ── Phase 5: Triple-check verification pass ────────────────────────────
  if (progressCallback) progressCallback({ engine: 'Triple-Check Verification', progress: 98, status: 'running' });
  try {
    const verified = await runVerification(report, progressCallback);
    // runVerification mutates and returns the report; merge any top-level additions
    if (verified && verified.verification) {
      report.verification = verified.verification;
      report.phones = verified.phones;
      report.socialProfiles = verified.socialProfiles;
      report.clues = verified.clues;
      report.identity = verified.identity;
      report.summary.totalPhonesFound = (report.phones.confirmed?.length || 0) +
        (report.phones.probable?.length || 0) +
        (report.phones.possible?.length || 0);
    }
  } catch (e) {
    report.verification = { ran: false, error: e.message };
  }

  if (progressCallback) progressCallback({ engine: 'Complete', progress: 100, status: 'finalizing' });
  return report;
}

module.exports = { runFullScan };
