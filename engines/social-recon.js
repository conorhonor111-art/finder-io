const axios = require('axios');
const crypto = require('crypto');
const { extractPhoneNumbers } = require('./google-dorker');

function githubHeaders(extra = {}) {
  const h = { 'User-Agent': 'FINDER_IO/2.0', ...extra };
  if (process.env.GITHUB_TOKEN) h.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  return h;
}

const PLATFORMS = [
  {
    name: 'Gravatar',
    check: async (email) => {
      try {
        const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
        const resp = await axios.get(`https://en.gravatar.com/${hash}.json`, {
          timeout: 6000,
          validateStatus: () => true,
        });
        if (resp.status === 200 && resp.data?.entry) {
          const entry = resp.data.entry[0];
          return {
            platform: 'Gravatar',
            found: true,
            displayName: entry.displayName || null,
            profileUrl: entry.profileUrl || null,
            location: entry.currentLocation || null,
            photos: entry.photos?.map(p => p.value) || [],
            phones: entry.phoneNumbers?.map(p => p.value) || [],
            accounts: entry.accounts?.map(a => ({
              domain: a.domain,
              username: a.username,
              url: a.url,
              shortname: a.shortname,
            })) || [],
            urls: entry.urls?.map(u => ({ value: u.value, title: u.title })) || [],
            confidence: entry.phoneNumbers?.length > 0 ? 'high' : 'medium',
          };
        }
      } catch (e) {}
      return { platform: 'Gravatar', found: false };
    },
  },
  {
    name: 'GitHub',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://api.github.com/search/users?q=${encodeURIComponent(email)}+in:email`, {
          timeout: 8000,
          headers: githubHeaders({ Accept: 'application/vnd.github.v3+json' }),
          validateStatus: () => true,
        });
        if (resp.status === 200 && resp.data?.total_count > 0) {
          const user = resp.data.items[0];
          const profileResp = await axios.get(user.url, {
            timeout: 6000,
            headers: githubHeaders(),
            validateStatus: () => true,
          });
          const p = profileResp.data || {};

          // Check user's repos for contact info
          let repoPhones = [];
          try {
            const reposResp = await axios.get(`${user.url}/repos?sort=updated&per_page=5`, {
              timeout: 6000,
              headers: githubHeaders(),
              validateStatus: () => true,
            });
            if (reposResp.status === 200) {
              for (const repo of (reposResp.data || []).slice(0, 3)) {
                try {
                  const readmeResp = await axios.get(`https://raw.githubusercontent.com/${repo.full_name}/${repo.default_branch}/README.md`, {
                    timeout: 4000, validateStatus: () => true,
                  });
                  if (readmeResp.status === 200) {
                    repoPhones.push(...extractPhoneNumbers(readmeResp.data));
                  }
                } catch (e) {}
              }
            }
          } catch (e) {}

          return {
            platform: 'GitHub',
            found: true,
            username: user.login,
            profileUrl: user.html_url,
            name: p.name || null,
            company: p.company || null,
            location: p.location || null,
            bio: p.bio || null,
            blog: p.blog || null,
            twitterUsername: p.twitter_username || null,
            publicRepos: p.public_repos || 0,
            followers: p.followers || 0,
            phones: [...new Set(repoPhones)],
            confidence: repoPhones.length > 0 ? 'medium' : 'low',
          };
        }
      } catch (e) {}
      return { platform: 'GitHub', found: false };
    },
  },
  {
    name: 'Have I Been Pwned',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
          timeout: 10000,
          headers: { 'User-Agent': 'FINDER_IO/2.0' },
          validateStatus: () => true,
        });
        if (resp.status === 200 && Array.isArray(resp.data)) {
          const phoneBreaches = resp.data.filter(b => b.DataClasses?.includes('Phone numbers'));
          return {
            platform: 'HIBP',
            found: true,
            totalBreaches: resp.data.length,
            breachNames: resp.data.map(b => b.Name),
            breachesWithPhone: phoneBreaches.map(b => ({
              name: b.Name,
              date: b.BreachDate,
              dataClasses: b.DataClasses,
              pwnCount: b.PwnCount,
            })),
            hasPhoneInBreaches: phoneBreaches.length > 0,
          };
        }
      } catch (e) {}
      return { platform: 'HIBP', found: false };
    },
  },
  {
    name: 'Microsoft/Skype',
    check: async (email) => {
      try {
        const resp = await axios.post('https://login.live.com/GetCredentialType.srf', {
          username: email,
          uaid: crypto.randomBytes(16).toString('hex'),
          isOtherIdpSupported: true,
          checkPhones: true,
          isRemoteNGCSupported: false,
          isCookieBannerShown: false,
          isFidoSupported: false,
          forceotclogin: false,
          otclogindisallowed: false,
          isExternalFederationDisallowed: false,
          isRemoteConnectSupported: false,
          federationFlags: 0,
        }, {
          timeout: 8000,
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        if (resp.status === 200) {
          const data = resp.data;
          const exists = data?.IfExistsResult === 0 || data?.IfExistsResult === 5 || data?.IfExistsResult === 6;
          return {
            platform: 'Microsoft/Skype',
            found: exists,
            hasLinkedPhone: !!data?.Credentials?.HasPhone,
            phoneLastTwo: data?.Credentials?.PhoneNumber || null,
            hasPassword: !!data?.Credentials?.HasPassword,
            isManaged: data?.EstsProperties?.DomainType === 3,
            confidence: data?.Credentials?.PhoneNumber ? 'medium' : 'low',
          };
        }
      } catch (e) {}
      return { platform: 'Microsoft/Skype', found: false };
    },
  },
  {
    name: 'Google (Account Probe)',
    check: async (email) => {
      if (!email.endsWith('@gmail.com') && !email.endsWith('@googlemail.com')) {
        return { platform: 'Google', found: false, note: 'Not a Google email' };
      }
      try {
        // Google's people lookup via Plus API remnant
        const localPart = email.split('@')[0].replace(/\./g, '');
        const resp = await axios.get(`https://www.google.com/maps/contrib/${localPart}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          timeout: 8000,
          validateStatus: () => true,
          maxRedirects: 3,
        });

        // Try password reset flow for phone hint
        const resetResp = await axios.post('https://accounts.google.com/signin/v2/challenge/pwd', null, {
          params: { flowName: 'GlifWebSignIn', flowEntry: 'ServiceLogin' },
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          timeout: 6000,
          validateStatus: () => true,
        });

        return {
          platform: 'Google',
          found: true,
          note: 'Gmail account exists',
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Google', found: false };
    },
  },
  {
    name: 'Instagram',
    check: async (email) => {
      try {
        // Get CSRF token first
        const initResp = await axios.get('https://www.instagram.com/accounts/emailsignup/', {
          timeout: 8000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        const cookies = (initResp.headers['set-cookie'] || []).join('; ');
        const csrfMatch = cookies.match(/csrftoken=([^;]+)/);
        const csrf = csrfMatch ? csrfMatch[1] : 'missing';

        const resp = await axios.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
          `email=${encodeURIComponent(email)}`,
          {
            timeout: 8000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15',
              'Content-Type': 'application/x-www-form-urlencoded',
              'X-CSRFToken': csrf,
              'Cookie': cookies,
              'X-Requested-With': 'XMLHttpRequest',
            },
            validateStatus: () => true,
          }
        );

        const emailTaken = resp.data?.errors?.email?.[0]?.code === 'email_is_taken' ||
                           resp.data?.errors?.email?.some(e => typeof e === 'string' && e.includes('used')) ||
                           (typeof resp.data?.dryrun_passed === 'boolean' && !resp.data.dryrun_passed);
        return {
          platform: 'Instagram',
          found: emailTaken,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Instagram', found: false };
    },
  },
  {
    name: 'Twitter/X',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://api.twitter.com/i/users/email_available.json?email=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        if (resp.status === 200) {
          return {
            platform: 'Twitter/X',
            found: resp.data?.taken === true,
            confidence: 'low',
          };
        }
      } catch (e) {}
      return { platform: 'Twitter/X', found: false };
    },
  },
  {
    name: 'LinkedIn (Dork)',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://www.google.com/search?q=site:linkedin.com+"${encodeURIComponent(email)}"`, {
          timeout: 8000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        if (resp.status === 200) {
          const cheerio = require('cheerio');
          const $ = cheerio.load(resp.data);
          const text = $('body').text();
          const linkedinFound = text.includes('linkedin.com/in/') || text.includes('LinkedIn');
          const phones = extractPhoneNumbers(text);
          return {
            platform: 'LinkedIn',
            found: linkedinFound,
            phones,
            confidence: phones.length > 0 ? 'medium' : 'low',
          };
        }
      } catch (e) {}
      return { platform: 'LinkedIn', found: false };
    },
  },
  {
    name: 'Spotify',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        if (resp.status === 200) {
          return {
            platform: 'Spotify',
            found: resp.data?.status === 20,
            confidence: 'low',
          };
        }
      } catch (e) {}
      return { platform: 'Spotify', found: false };
    },
  },
  {
    name: 'Adobe',
    check: async (email) => {
      try {
        const resp = await axios.post('https://auth.services.adobe.com/signin/v2/users/accounts', {
          username: email,
        }, {
          timeout: 6000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-IMS-CLIENTID': 'adobedotcom2',
          },
          validateStatus: () => true,
        });
        return {
          platform: 'Adobe',
          found: resp.status === 200 && Array.isArray(resp.data) && resp.data.length > 0,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Adobe', found: false };
    },
  },
  {
    name: 'Pinterest',
    check: async (email) => {
      try {
        const pinterestData = encodeURIComponent(JSON.stringify({options:{email}}));
        const resp = await axios.get(`https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data=${pinterestData}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          validateStatus: () => true,
        });
        return {
          platform: 'Pinterest',
          found: resp.data?.resource_response?.data === true,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Pinterest', found: false };
    },
  },
  {
    name: 'Duolingo',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://www.duolingo.com/2017-06-30/users?email=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'FINDER_IO/2.0' },
          validateStatus: () => true,
        });
        if (resp.status === 200 && resp.data?.users?.length > 0) {
          const user = resp.data.users[0];
          return {
            platform: 'Duolingo',
            found: true,
            username: user.username,
            name: user.name || null,
            profileUrl: `https://www.duolingo.com/profile/${user.username}`,
            confidence: 'low',
          };
        }
      } catch (e) {}
      return { platform: 'Duolingo', found: false };
    },
  },
  {
    name: 'Snapchat',
    check: async (email) => {
      try {
        const resp = await axios.post('https://feelinsonice-hrd.appspot.com/web/public/exists', {
          username: email.split('@')[0],
        }, {
          timeout: 6000,
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'FINDER_IO/2.0' },
          validateStatus: () => true,
        });
        return {
          platform: 'Snapchat',
          found: resp.data?.exists === true,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Snapchat', found: false };
    },
  },
  {
    name: 'Zoom',
    check: async (email) => {
      try {
        const resp = await axios.post('https://zoom.us/signin', {
          email,
          password: 'not_real_password_probe',
          remember_me: false,
        }, {
          timeout: 6000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          },
          validateStatus: () => true,
        });
        // Status 401 with specific error means account exists but wrong pass
        const exists = resp.status === 401 ||
          (resp.status === 200 && resp.data?.result === false && resp.data?.errorCode !== 1001);
        return { platform: 'Zoom', found: exists, confidence: 'low' };
      } catch (e) {}
      return { platform: 'Zoom', found: false };
    },
  },
  {
    name: 'Patreon',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://www.patreon.com/api/user?filter[email]=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          validateStatus: () => true,
        });
        return {
          platform: 'Patreon',
          found: resp.status === 200 && resp.data?.data?.length > 0,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Patreon', found: false };
    },
  },
  {
    name: 'Dropbox',
    check: async (email) => {
      try {
        const resp = await axios.post('https://www.dropbox.com/login', {
          login_email: email,
          login_password: 'not_real_probe_xyz123!',
        }, {
          timeout: 6000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          validateStatus: () => true,
          maxRedirects: 0,
        });
        // If it redirects to 2FA or "wrong password" screen vs "no account", account exists
        const exists = resp.status === 400 || resp.status === 401 ||
          (resp.status === 200 && resp.data && !resp.data.includes('not_registered'));
        return { platform: 'Dropbox', found: exists, confidence: 'low' };
      } catch (e) {}
      return { platform: 'Dropbox', found: false };
    },
  },
  {
    name: 'Flickr',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://api.flickr.com/services/rest/?method=flickr.people.findByEmail&api_key=672e539295cb968d4ba9e0c7e5498f3a&find_email=${encodeURIComponent(email)}&format=json&nojsoncallback=1`, {
          timeout: 8000,
          headers: { 'User-Agent': 'FINDER_IO/2.0' },
          validateStatus: () => true,
        });
        if (resp.status === 200 && resp.data?.person?.id) {
          const userId = resp.data.person.id;
          // Get full profile
          const profileResp = await axios.get(`https://api.flickr.com/services/rest/?method=flickr.profile.getProfile&api_key=672e539295cb968d4ba9e0c7e5498f3a&user_id=${userId}&format=json&nojsoncallback=1`, {
            timeout: 6000,
            headers: { 'User-Agent': 'FINDER_IO/2.0' },
            validateStatus: () => true,
          });
          const profile = profileResp.data?.profile || {};
          return {
            platform: 'Flickr',
            found: true,
            username: resp.data.person.nsid,
            name: profile.realname || null,
            location: profile.hometown || profile.city || null,
            profileUrl: `https://www.flickr.com/people/${userId}`,
            confidence: 'medium',
          };
        }
      } catch (e) {}
      return { platform: 'Flickr', found: false };
    },
  },
  {
    name: 'Disqus',
    check: async (email) => {
      try {
        // Disqus SSO probe — checks if email is registered
        const resp = await axios.get(`https://disqus.com/api/3.0/users/checkUsername.json?username=${encodeURIComponent(email.split('@')[0])}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'FINDER_IO/2.0' },
          validateStatus: () => true,
        });
        return {
          platform: 'Disqus',
          found: resp.status === 200 && resp.data?.code === 0,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Disqus', found: false };
    },
  },
  {
    name: 'Ebay',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://reg.ebay.com/reg/IdentityAjaxServlet?regUrl=&country=US&email=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          validateStatus: () => true,
        });
        if (resp.status === 200) {
          const exists = resp.data?.emailFound === true || resp.data?.registered === 'true';
          return { platform: 'Ebay', found: exists, confidence: 'low' };
        }
      } catch (e) {}
      return { platform: 'Ebay', found: false };
    },
  },
  {
    name: 'Airbnb',
    check: async (email) => {
      try {
        const resp = await axios.post('https://www.airbnb.com/api/v2/authentications', {
          email,
          password: 'probe',
        }, {
          timeout: 6000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'X-Airbnb-API-Key': 'd306zoyjsyarp7ifhu67rjxn52tv0t20',
          },
          validateStatus: () => true,
        });
        // 401/403 = exists, 404/422 = doesn't
        const exists = resp.status === 400 || resp.status === 401 ||
          (resp.data?.error_code && resp.data.error_code !== 'email_not_found');
        return { platform: 'Airbnb', found: exists, confidence: 'low' };
      } catch (e) {}
      return { platform: 'Airbnb', found: false };
    },
  },
  {
    name: 'Lastpass',
    check: async (email) => {
      try {
        const resp = await axios.post('https://lastpass.com/iterations.php', `email=${encodeURIComponent(email)}`, {
          timeout: 6000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'FINDER_IO/2.0',
          },
          validateStatus: () => true,
        });
        // Returns iteration count if account exists, error if not
        const exists = resp.status === 200 && /^\d+$/.test(resp.data?.toString().trim());
        return { platform: 'LastPass', found: exists, confidence: 'medium' };
      } catch (e) {}
      return { platform: 'LastPass', found: false };
    },
  },
  {
    name: 'Proton Mail',
    check: async (email) => {
      if (!email.endsWith('@proton.me') && !email.endsWith('@protonmail.com') && !email.endsWith('@pm.me')) {
        // Check if this email is linked to a Proton account via availability
        try {
          const localPart = email.split('@')[0];
          const resp = await axios.get(`https://account.proton.me/api/core/v4/users?Name=${encodeURIComponent(localPart)}`, {
            timeout: 6000,
            headers: { 'User-Agent': 'FINDER_IO/2.0' },
            validateStatus: () => true,
          });
          return { platform: 'Proton Mail', found: resp.status === 409, confidence: 'low' };
        } catch (e) {}
      } else {
        return { platform: 'Proton Mail', found: true, note: 'Email itself is Proton', confidence: 'high' };
      }
      return { platform: 'Proton Mail', found: false };
    },
  },
  {
    name: 'Tumblr',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://www.tumblr.com/register`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          validateStatus: () => true,
        });
        // Check email existence via undocumented endpoint
        const checkResp = await axios.post('https://www.tumblr.com/api/user/check_email',
          `email=${encodeURIComponent(email)}`,
          {
            timeout: 6000,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Mozilla/5.0',
            },
            validateStatus: () => true,
          }
        );
        return {
          platform: 'Tumblr',
          found: checkResp.data?.exists === true || checkResp.status === 200,
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Tumblr', found: false };
    },
  },
  {
    name: 'Venmo',
    check: async (email) => {
      try {
        const resp = await axios.post('https://api.venmo.com/v1/account/two-factor/token',
          { via: 'email', email },
          {
            timeout: 6000,
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'Venmo/7.44.0 (iPhone; iOS 14.4; Scale/3.00)',
            },
            validateStatus: () => true,
          }
        );
        return {
          platform: 'Venmo',
          found: resp.status === 200 || (resp.status === 400 && resp.data?.error?.code !== 81109),
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Venmo', found: false };
    },
  },
  {
    name: 'Myspace',
    check: async (email) => {
      try {
        const resp = await axios.get(`https://myspace.com/${email.split('@')[0]}`, {
          timeout: 6000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          validateStatus: () => true,
        });
        return {
          platform: 'Myspace',
          found: resp.status === 200 && resp.data?.includes('myspace.com'),
          confidence: 'low',
        };
      } catch (e) {}
      return { platform: 'Myspace', found: false };
    },
  },
];

async function socialRecon(email, progressCb) {
  const results = [];
  const total = PLATFORMS.length;
  let done = 0;

  const batchSize = 4;
  for (let i = 0; i < PLATFORMS.length; i += batchSize) {
    const batch = PLATFORMS.slice(i, i + batchSize);
    const checks = batch.map(async (platform) => {
      try {
        const result = await platform.check(email);
        done++;
        if (progressCb) progressCb({ sub: `${platform.name} (${done}/${total})` });
        results.push(result);
      } catch (err) {
        done++;
        results.push({ platform: platform.name, found: false, error: err.message });
      }
    });
    await Promise.allSettled(checks);
    // Small delay between batches to avoid looking like a bot
    if (i + batchSize < PLATFORMS.length) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return results;
}

module.exports = { socialRecon };
