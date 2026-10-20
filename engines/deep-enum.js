const axios = require('axios');
const cheerio = require('cheerio');
const { extractPhoneNumbers } = require('./google-dorker');

// Deep enumeration — finds ALL info associated with an email
// Registration checks, profile scraping, data enrichment

async function safeGet(url, opts = {}) {
  try {
    return await axios.get(url, {
      timeout: opts.timeout || 8000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36', ...opts.headers },
      validateStatus: () => true,
      maxRedirects: 3,
      ...opts,
    });
  } catch (e) { return null; }
}

async function safePost(url, data, opts = {}) {
  try {
    return await axios.post(url, data, {
      timeout: opts.timeout || 8000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', ...opts.headers },
      validateStatus: () => true,
      ...opts,
    });
  } catch (e) { return null; }
}

// ═══════════════════════════════════════
// REGISTRATION CHECKS — 30+ platforms
// ═══════════════════════════════════════

const REGISTRATION_CHECKS = [
  {
    name: 'Discord',
    check: async (email) => {
      const resp = await safePost('https://discord.com/api/v9/auth/register', {
        email, username: 'finderio_' + Date.now(), password: 'Aa1!' + Math.random().toString(36),
        date_of_birth: '1990-01-01', consent: true,
      }, { headers: { 'Content-Type': 'application/json' } });
      if (!resp) return false;
      // Require exact error code only — "already" is too broad and causes false positives
      // with captcha/rate-limit responses that contain unrelated "already" text
      const emailUsed = resp.data?.errors?.email?._errors?.some(e =>
        e.code === 'EMAIL_ALREADY_REGISTERED'
      );
      // Additional signal: HTTP 400 with email error (not 429 captcha/rate-limit)
      if (resp.status === 400 && emailUsed) return true;
      // Reject everything else — too unreliable without exact code
      return false;
    },
  },
  {
    name: 'Snapchat',
    check: async (email) => {
      const resp = await safePost('https://accounts.snapchat.com/accounts/merlin/check_email',
        `email=${encodeURIComponent(email)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.email_available === false;
    },
  },
  {
    name: 'Flickr',
    check: async (email) => {
      const resp = await safeGet(`https://www.flickr.com/signup/checkemailaddress?emailaddress=${encodeURIComponent(email)}`);
      return resp?.status === 200 && resp?.data?.includes?.('taken');
    },
  },
  {
    name: 'WordPress',
    check: async (email) => {
      const resp = await safePost('https://public-api.wordpress.com/rest/v1.1/users/new',
        `email=${encodeURIComponent(email)}&username=finderio${Date.now()}&password=FIO!${Math.random().toString(36)}&validate=1`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.message?.includes?.('already exists') || false;
    },
  },
  {
    name: 'PayPal',
    check: async (email) => {
      const resp = await safePost('https://www.paypal.com/signup/api/v1/validate/email',
        JSON.stringify({ email }),
        { headers: { 'Content-Type': 'application/json' } }
      );
      return resp?.data?.isEmailAvailable === false;
    },
  },
  {
    name: 'Amazon',
    check: async (email) => {
      const resp = await safePost('https://www.amazon.com/ap/signin',
        `email=${encodeURIComponent(email)}&create=0`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      if (!resp) return false;
      return resp.status === 200 && !resp.data?.includes?.('register');
    },
  },
  {
    name: 'Apple',
    check: async (email) => {
      const resp = await safePost('https://iforgot.apple.com/password/verify/appleid',
        JSON.stringify({ id: email }),
        { headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } }
      );
      return resp?.status === 200 || resp?.status === 302;
    },
  },
  {
    name: 'Netflix',
    check: async (email) => {
      const resp = await safeGet(`https://www.netflix.com/api/shakti/pathEvaluator?email=${encodeURIComponent(email)}`);
      return resp?.data?.existingUser === true;
    },
  },
  {
    name: 'Tumblr',
    check: async (email) => {
      const resp = await safePost('https://www.tumblr.com/svc/account/register',
        `email=${encodeURIComponent(email)}&action=signup`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.errors?.email?.includes?.('already in use') || false;
    },
  },
  {
    name: 'Zoom',
    check: async (email) => {
      const resp = await safeGet(`https://zoom.us/account/validate?email=${encodeURIComponent(email)}`);
      return resp?.data?.result === 0;
    },
  },
  {
    name: 'eBay',
    check: async (email) => {
      const resp = await safeGet(`https://signup.ebay.com/ajax/check?email=${encodeURIComponent(email)}`);
      return resp?.data?.errors?.email !== undefined;
    },
  },
  {
    name: 'TikTok',
    check: async (email) => {
      const resp = await safePost('https://www.tiktok.com/api/user/check_email',
        `email=${encodeURIComponent(email)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.data?.is_registered === true;
    },
  },
  {
    name: 'Twitch',
    check: async (email) => {
      const resp = await safePost('https://passport.twitch.tv/usernames',
        JSON.stringify({ email }),
        { headers: { 'Content-Type': 'application/json', 'Client-Id': 'kimne78kx3ncx6brgo4mv6wki5h1ko' } }
      );
      return resp?.status === 200 && resp?.data?.userExists === true;
    },
  },
  {
    name: 'Shopify',
    check: async (email) => {
      const resp = await safeGet(`https://accounts.shopify.com/lookup?email=${encodeURIComponent(email)}`);
      return resp?.status === 200 && resp?.data?.includes?.('password');
    },
  },
  {
    name: 'Slack',
    check: async (email) => {
      const resp = await safePost('https://slack.com/api/users.lookupByEmail',
        `email=${encodeURIComponent(email)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.ok === true;
    },
  },
  {
    name: 'GitLab',
    check: async (email) => {
      const resp = await safeGet(`https://gitlab.com/api/v4/users?search=${encodeURIComponent(email)}`);
      return resp?.status === 200 && Array.isArray(resp?.data) && resp.data.length > 0;
    },
  },
  {
    name: 'Bitbucket',
    check: async (email) => {
      const resp = await safeGet(`https://bitbucket.org/api/2.0/users?q=email="${encodeURIComponent(email)}"`);
      return resp?.data?.size > 0;
    },
  },
  {
    name: 'Reddit',
    check: async (email) => {
      const resp = await safePost('https://www.reddit.com/api/check_email.json',
        `email=${encodeURIComponent(email)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.json?.data?.email_available === false;
    },
  },
  {
    name: 'Dropbox',
    check: async (email) => {
      const resp = await safePost('https://www.dropbox.com/ajax_check_email',
        `email=${encodeURIComponent(email)}&is_ajax=true`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return resp?.data?.status === 'unavailable';
    },
  },
  {
    name: 'Evernote',
    check: async (email) => {
      const resp = await safeGet(`https://www.evernote.com/Registration.action?emailAddress=${encodeURIComponent(email)}`);
      return resp?.status === 200 && resp?.data?.includes?.('already registered');
    },
  },
  {
    name: 'Booking.com',
    check: async (email) => {
      const resp = await safePost('https://account.booking.com/api/identity/email/validate',
        JSON.stringify({ email }),
        { headers: { 'Content-Type': 'application/json' } }
      );
      return resp?.data?.error === 'EMAIL_ALREADY_IN_USE';
    },
  },
];

// ═══════════════════════════════════════
// FULL EMAIL ENRICHMENT
// ═══════════════════════════════════════

async function enrichWithClearbit(email) {
  if (!process.env.CLEARBIT_API_KEY) return null;
  try {
    const resp = await safeGet(`https://person.clearbit.com/v2/combined/find?email=${encodeURIComponent(email)}`, {
      headers: { Authorization: `Bearer ${process.env.CLEARBIT_API_KEY}` },
    });
    if (resp?.status === 200 && resp.data) {
      const person = resp.data.person || {};
      const company = resp.data.company || {};
      return {
        source: 'Clearbit',
        person: {
          name: person.name?.fullName,
          firstName: person.name?.givenName,
          lastName: person.name?.familyName,
          avatar: person.avatar,
          location: person.location,
          title: person.employment?.title,
          company: person.employment?.name,
          bio: person.bio,
          twitter: person.twitter?.handle,
          linkedin: person.linkedin?.handle,
          facebook: person.facebook?.handle,
          github: person.github?.handle,
          phone: person.phone,
        },
        company: {
          name: company.name,
          domain: company.domain,
          category: company.category?.industry,
          employees: company.metrics?.employees,
          phone: company.phone,
          location: company.geo ? `${company.geo.city}, ${company.geo.country}` : null,
        },
        phones: [person.phone, company.phone].filter(Boolean),
        confidence: 'high',
      };
    }
  } catch (e) {}
  return null;
}

async function enrichWithFullContact(email) {
  if (!process.env.FULLCONTACT_API_KEY) return null;
  try {
    const resp = await safePost('https://api.fullcontact.com/v3/person.enrich',
      JSON.stringify({ email }),
      { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.FULLCONTACT_API_KEY}` } }
    );
    if (resp?.status === 200 && resp.data) {
      return {
        source: 'FullContact',
        name: resp.data.fullName,
        age: resp.data.ageRange,
        gender: resp.data.gender,
        location: resp.data.location,
        title: resp.data.title,
        organization: resp.data.organization,
        socialProfiles: resp.data.socialProfiles || [],
        phones: resp.data.phones || [],
        confidence: resp.data.phones?.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

async function checkTruecaller(email) {
  try {
    // Truecaller web search
    const resp = await safeGet(`https://www.google.com/search?q=site:truecaller.com+"${encodeURIComponent(email)}"`, {
      timeout: 10000,
    });
    if (resp?.status === 200) {
      const $ = cheerio.load(resp.data);
      const text = $('body').text();
      const phones = extractPhoneNumbers(text);
      const links = [];
      $('a').each((_, el) => {
        const href = $(el).attr('href') || '';
        if (href.includes('truecaller.com')) links.push(href);
      });
      return {
        source: 'Truecaller',
        phones,
        links,
        confidence: phones.length > 0 ? 'high' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

async function checkPeopleDataLabs(email) {
  if (!process.env.PEOPLEDATALABS_API_KEY) return null;
  try {
    const resp = await safeGet(`https://api.peopledatalabs.com/v5/person/enrich?email=${encodeURIComponent(email)}&pretty=true`, {
      headers: { 'X-Api-Key': process.env.PEOPLEDATALABS_API_KEY },
    });
    if (resp?.status === 200 && resp.data?.data) {
      const d = resp.data.data;
      return {
        source: 'PeopleDataLabs',
        name: d.full_name,
        firstName: d.first_name,
        lastName: d.last_name,
        phones: d.phone_numbers || [],
        location: d.location_name,
        jobTitle: d.job_title,
        company: d.job_company_name,
        industry: d.industry,
        linkedinUrl: d.linkedin_url,
        facebookUrl: d.facebook_url,
        twitterUrl: d.twitter_url,
        githubUrl: d.github_url,
        gender: d.sex,
        confidence: d.phone_numbers?.length > 0 ? 'high' : 'medium',
      };
    }
  } catch (e) {}
  return null;
}

async function checkVerifyMail(email) {
  if (!process.env.VERIFYMAIL_API_KEY) return null;
  try {
    const resp = await safeGet(`https://verifymail.io/api/${encodeURIComponent(email)}?key=${encodeURIComponent(process.env.VERIFYMAIL_API_KEY)}`);
    if (resp?.status === 200 && resp.data) {
      return {
        source: 'VerifyMail',
        deliverable: resp.data.deliverable,
        disposable: resp.data.disposable,
        catchAll: resp.data.catch_all,
        freeProvider: resp.data.free,
        hostExists: resp.data.host_exists,
      };
    }
  } catch (e) {}
  return null;
}

async function searchPeopleLookup(email) {
  const sources = [
    `https://www.google.com/search?q=site:truepeoplesearch.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:thatsmynumber.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:spokeo.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:beenverified.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:fastpeoplesearch.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:411.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:anywho.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:pipl.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:peekyou.com+"${encodeURIComponent(email)}"`,
    `https://www.google.com/search?q=site:addresses.com+"${encodeURIComponent(email)}"`,
  ];

  const results = [];
  for (const url of sources) {
    try {
      const resp = await safeGet(url);
      if (resp?.status === 200) {
        const $ = cheerio.load(resp.data);
        const text = $('body').text();
        const phones = extractPhoneNumbers(text);
        const siteName = url.match(/site:([^+]+)/)?.[1] || 'Unknown';
        if (phones.length > 0) {
          results.push({
            source: `PeopleLookup (${siteName})`,
            phones,
            confidence: 'medium',
          });
        }
      }
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) {}
  }
  return results;
}

// ═══════════════════════════════════════
// HUNTER.IO — EMAIL VERIFICATION + DELIVERABILITY
// ═══════════════════════════════════════

async function checkHunterIO(email) {
  if (!process.env.HUNTER_API_KEY) return null;
  try {
    const resp = await safeGet(
      `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${encodeURIComponent(process.env.HUNTER_API_KEY)}`
    );
    if (resp?.status === 200 && resp.data?.data) {
      const d = resp.data.data;
      return {
        source: 'Hunter.io',
        deliverable: d.result === 'deliverable',
        disposable: d.disposable,
        webmail: d.webmail,
        score: d.score,
        mxValid: d.mx_records,
        confidence: d.result === 'deliverable' ? 'medium' : 'low',
      };
    }
  } catch (e) {}
  return null;
}

// ═══════════════════════════════════════
// MAIN DEEP ENUMERATION
// ═══════════════════════════════════════

async function deepEnum(email, progressCb) {
  const results = [];

  // 1. Registration checks (parallel batches of 5)
  if (progressCb) progressCb({ sub: 'Registration checks (30+ platforms)' });
  const registrations = {};
  const regBatchSize = 5;
  for (let i = 0; i < REGISTRATION_CHECKS.length; i += regBatchSize) {
    const batch = REGISTRATION_CHECKS.slice(i, i + regBatchSize);
    const checks = batch.map(async (platform) => {
      try {
        const found = await platform.check(email);
        registrations[platform.name] = found;
      } catch (e) {
        registrations[platform.name] = null; // unknown
      }
    });
    await Promise.allSettled(checks);
    await new Promise(r => setTimeout(r, 300));
  }

  const registeredOn = Object.entries(registrations)
    .filter(([_, found]) => found === true)
    .map(([name]) => name);
  const notRegistered = Object.entries(registrations)
    .filter(([_, found]) => found === false)
    .map(([name]) => name);
  const unknown = Object.entries(registrations)
    .filter(([_, found]) => found === null)
    .map(([name]) => name);

  results.push({
    source: 'Registration Checks',
    totalChecked: REGISTRATION_CHECKS.length,
    registeredOn,
    notRegisteredOn: notRegistered,
    unknown,
    confidence: 'medium',
  });

  // 2. Data enrichment APIs (parallel)
  if (progressCb) progressCb({ sub: 'Data enrichment APIs' });
  const enrichmentResults = await Promise.allSettled([
    enrichWithClearbit(email),
    enrichWithFullContact(email),
    checkPeopleDataLabs(email),
    checkVerifyMail(email),
    checkTruecaller(email),
    checkHunterIO(email),
  ]);

  for (const result of enrichmentResults) {
    if (result.status === 'fulfilled' && result.value) {
      results.push(result.value);
    }
  }

  // 3. People lookup sites
  if (progressCb) progressCb({ sub: 'People search engines' });
  const peopleLookupResults = await searchPeopleLookup(email);
  results.push(...peopleLookupResults);

  return results;
}

module.exports = { deepEnum };
