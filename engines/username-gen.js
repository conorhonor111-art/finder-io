/**
 * username-gen.js — Username generation algorithm + Sherlock-style 50-platform probe
 * Derives username candidates from email local part, then fires parallel presence checks
 * across dev platforms, social networks, gaming, communities. Extracts name/location/bio
 * from every hit.
 */
const axios = require('axios');

// ─── Username generation algorithm ───────────────────────────────────────────
function generateUsernames(email) {
  const raw = email.split('@')[0];
  const domain = email.split('@')[1];
  const local = raw.toLowerCase().replace(/\+.*$/, ''); // strip Gmail + suffix

  // Gmail ignores dots — normalize to dotless version
  const dotless = local.replace(/\./g, '');
  const parts = local.split('.').filter(p => p.length > 0);
  const numless = local.replace(/\d+$/, '');           // strip trailing numbers
  const numlessDotless = dotless.replace(/\d+$/, '');  // dotless + no trailing nums

  const cands = new Set();

  // Tier 1 — direct
  cands.add(local);
  cands.add(dotless);
  cands.add(numless);
  cands.add(numlessDotless);

  // Tier 2 — separator variants
  if (parts.length >= 2) {
    cands.add(parts.join('_'));
    cands.add(parts.join('-'));
    cands.add(parts.join(''));
    cands.add(parts[0] + parts.slice(1).join(''));         // first full + rest joined
    cands.add(parts[0][0] + parts.slice(1).join(''));      // first initial + rest
    cands.add(parts[0] + parts[1]);
    cands.add(parts[0][0] + parts[1]);                     // j + smith → jsmith
    cands.add(parts[0] + '_' + parts[1]);
    cands.add(parts[0] + '-' + parts[1]);
    // reversed
    cands.add([...parts].reverse().join(''));
    cands.add([...parts].reverse().join('_'));
  }

  // Tier 3 — individual meaningful parts
  for (const p of parts) {
    if (p.replace(/\d/g, '').length >= 3) cands.add(p);
    const pNoNum = p.replace(/\d+$/, '');
    if (pNoNum.length >= 3) cands.add(pNoNum);
  }

  // Tier 4 — common patterns from domain (company emails only — skip consumer email providers)
  // Block consumer email provider base names even across TLDs (gmail.com, hotmail.co.uk, etc.)
  const PROVIDER_BASE_NAMES = new Set([
    'gmail','yahoo','hotmail','outlook','live','msn','windowslive',
    'icloud','me','mac','aol','aim',
    'protonmail','proton','tutanota','tutamail',
    'yandex','mail','inbox','zoho',
    'gmx','web','fastmail','hushmail','mailfence',
    'posteo','runbox','lavabit','riseup',
    'bt','sky','virginmedia','ntlworld','talktalk',  // UK ISPs
    'comcast','verizon','att','sbcglobal','bellsouth', // US ISPs
    'cox','charter','earthlink','netzero',
    'facebook','google','apple','microsoft',
  ]);
  const domainBase = domain.split('.')[0].toLowerCase();
  if (!PROVIDER_BASE_NAMES.has(domainBase)) {
    // It's a custom/company domain — the base name is a useful username hint
    if (domainBase.length >= 3) cands.add(domainBase);
  }

  return [...cands].filter(u => {
    if (!u || u.length < 3 || u.length > 30) return false;
    if (/^[^a-z0-9]/i.test(u)) return false;   // must start with alphanum
    if (/[^a-z0-9_.\-]/i.test(u)) return false; // only safe chars
    return true;
  });
}

// ─── Platform definitions ─────────────────────────────────────────────────────
// Each entry: { name, url(username), check(resp), extract(resp)? }
const PLATFORMS = [

  // ── Developer ──
  {
    name: 'GitHub',
    url: u => `https://api.github.com/users/${u}`,
    headers: () => {
      const h = { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/vnd.github.v3+json' };
      if (process.env.GITHUB_TOKEN) h.Authorization = `token ${process.env.GITHUB_TOKEN}`;
      return h;
    },
    check: r => r.status === 200 && r.data?.login,
    extract: r => ({
      name: r.data?.name,
      location: r.data?.location,
      bio: r.data?.bio,
      company: r.data?.company,
      blog: r.data?.blog,
      profileUrl: r.data?.html_url,
      twitterUsername: r.data?.twitter_username,
      followers: r.data?.followers,
      publicRepos: r.data?.public_repos,
    }),
  },
  {
    name: 'GitLab',
    url: u => `https://gitlab.com/api/v4/users?username=${u}`,
    check: r => r.status === 200 && Array.isArray(r.data) && r.data.length > 0,
    extract: r => ({
      name: r.data[0]?.name,
      location: r.data[0]?.location,
      bio: r.data[0]?.bio,
      profileUrl: r.data[0]?.web_url,
    }),
  },
  {
    name: 'Bitbucket',
    url: u => `https://api.bitbucket.org/2.0/users/${u}`,
    check: r => r.status === 200 && r.data?.account_id,
    extract: r => ({
      name: r.data?.display_name,
      location: r.data?.location,
      profileUrl: r.data?.links?.html?.href,
    }),
  },
  {
    name: 'npm',
    url: u => `https://registry.npmjs.org/-/v1/search?text=maintainer:${u}&size=1`,
    check: r => r.status === 200 && r.data?.total > 0,
    extract: (r, u) => {
      // Use the actual search username, not the package author name (which may differ)
      return {
        profileUrl: `https://www.npmjs.com/~${u}`,
        packages: r.data?.total,
      };
    },
  },
  {
    name: 'PyPI',
    url: u => `https://pypi.org/user/${u}/`,
    check: r => r.status === 200 && !r.data?.includes('404') && r.data?.includes('pypi-'),
    extract: r => ({ profileUrl: `https://pypi.org/user/${r.config?.url?.split('/').slice(-2,-1)[0] || ''}` }),
  },
  {
    name: 'HackerNews',
    url: u => `https://hacker-news.firebaseio.com/v0/user/${u}.json`,
    check: r => r.status === 200 && r.data !== null && r.data?.id,
    extract: r => ({
      bio: r.data?.about?.replace(/<[^>]*>/g, '').trim().slice(0, 200),
      karma: r.data?.karma,
      created: r.data?.created ? new Date(r.data.created * 1000).toISOString().split('T')[0] : null,
      profileUrl: `https://news.ycombinator.com/user?id=${r.data?.id}`,
    }),
  },
  {
    name: 'Dev.to',
    url: u => `https://dev.to/api/users/by_username?url=${u}`,
    check: r => r.status === 200 && r.data?.id,
    extract: (r, u) => ({
      name: r.data?.name,
      location: r.data?.location,
      bio: r.data?.summary?.slice(0, 200),
      profileUrl: r.data?.url || `https://dev.to/${u}`,
      // Expose cross-platform links for identity cross-verification
      githubUsername: r.data?.github_username || null,
      twitterUsername: r.data?.twitter_username || null,
    }),
  },
  {
    name: 'DockerHub',
    url: u => `https://hub.docker.com/v2/users/${u}/`,
    check: r => r.status === 200 && r.data?.id,
    extract: r => ({
      name: r.data?.full_name,
      location: r.data?.location,
      bio: r.data?.company,
      profileUrl: `https://hub.docker.com/u/${u}`,
    }),
  },
  {
    name: 'Replit',
    url: u => `https://replit.com/data/repls/profiles/${u}`,
    check: r => r.status === 200 && r.data?.username,
    extract: r => ({
      name: r.data?.fullName,
      bio: r.data?.bio,
      profileUrl: `https://replit.com/@${u}`,
    }),
  },
  {
    name: 'CodePen',
    url: u => `https://codepen.io/${u}`,
    check: r => r.status === 200 && r.data?.includes('codepen.io/'),
    extract: () => ({ profileUrl: `https://codepen.io/${u}` }),
  },
  {
    name: 'LeetCode',
    url: u => `https://leetcode.com/${u}/`,
    check: r => r.status === 200 && !r.data?.includes('"statusCode":404') && r.data?.includes('leetcode'),
    extract: () => ({ profileUrl: `https://leetcode.com/${u}/` }),
  },

  // ── Social ──
  {
    name: 'Reddit',
    url: u => `https://www.reddit.com/user/${u}/about.json`,
    headers: () => ({ 'User-Agent': 'FINDER_IO/2.0 OSINT' }),
    check: r => r.status === 200 && r.data?.kind === 't2',
    extract: r => ({
      name: r.data?.data?.name,
      bio: r.data?.data?.subreddit?.public_description?.slice(0, 200),
      karma: (r.data?.data?.link_karma || 0) + (r.data?.data?.comment_karma || 0),
      created: r.data?.data?.created_utc ? new Date(r.data.data.created_utc * 1000).toISOString().split('T')[0] : null,
      profileUrl: `https://www.reddit.com/user/${u}`,
      trophies: r.data?.data?.trophy_case?.map(t => t.data?.name) || [],
    }),
  },
  {
    name: 'Keybase',
    url: u => `https://keybase.io/_/api/1.0/user/lookup.json?username=${u}`,
    check: r => r.status === 200 && r.data?.status?.code === 0 && r.data?.them,
    extract: r => {
      const them = r.data?.them;
      const proofs = them?.proofs_summary?.all || [];
      const links = proofs.map(p => `${p.proof_type}: ${p.nametag}`);
      return {
        name: them?.profile?.full_name,
        location: them?.profile?.location,
        bio: them?.profile?.bio,
        profileUrl: `https://keybase.io/${u}`,
        socialLinks: links,
      };
    },
  },
  {
    name: 'Telegram',
    url: u => `https://t.me/${u}`,
    check: r => r.status === 200 && r.data?.includes('tgme_page_title') && !r.data?.includes('tgme_page_status_error'),
    extract: r => {
      const nameMatch = r.data?.match(/<div class="tgme_page_title"><span[^>]*>([^<]+)<\/span>/);
      const descMatch = r.data?.match(/<div class="tgme_page_description">([^<]+)<\/div>/);
      return {
        name: nameMatch?.[1]?.trim(),
        bio: descMatch?.[1]?.trim(),
        profileUrl: `https://t.me/${u}`,
      };
    },
  },
  {
    name: 'Medium',
    url: u => `https://medium.com/@${u}?format=json`,
    check: r => r.status === 200 && (r.data?.includes('"@type":"Person"') || r.data?.payload?.user),
    extract: r => {
      try {
        const cleanJson = typeof r.data === 'string' ? r.data.replace(/^[^{]*/, '') : null;
        if (!cleanJson) return { profileUrl: `https://medium.com/@${u}` };
        const parsed = JSON.parse(cleanJson);
        const user = parsed?.payload?.user;
        return { name: user?.name, bio: user?.bio?.slice(0, 200), profileUrl: `https://medium.com/@${u}` };
      } catch { return { profileUrl: `https://medium.com/@${u}` }; }
    },
  },
  {
    name: 'Substack',
    url: u => `https://${u}.substack.com/api/v1/author/page`,
    check: r => r.status === 200 && r.data?.id,
    extract: r => ({
      name: r.data?.name,
      bio: r.data?.bio?.slice(0, 200),
      location: r.data?.location,
      profileUrl: `https://${u}.substack.com`,
    }),
  },
  {
    name: 'Quora',
    url: u => `https://www.quora.com/profile/${u}`,
    check: r => r.status === 200 && r.data?.includes('quora-content') && !r.data?.includes('404'),
    extract: () => ({ profileUrl: `https://www.quora.com/profile/${u}` }),
  },
  {
    name: 'VK',
    url: u => `https://vk.com/${u}`,
    check: r => r.status === 200 && r.data?.includes('vk.com') && !r.data?.includes('id=0'),
    extract: r => {
      const nameMatch = r.data?.match(/<title>([^<|]+)/);
      return { name: nameMatch?.[1]?.trim(), profileUrl: `https://vk.com/${u}` };
    },
  },

  // ── Gaming / Entertainment ──
  {
    name: 'Chess.com',
    url: u => `https://api.chess.com/pub/player/${u.toLowerCase()}`,
    check: r => r.status === 200 && r.data?.username,
    extract: r => ({
      name: r.data?.name,
      location: r.data?.location,
      profileUrl: r.data?.url,
      bio: r.data?.title ? `Chess title: ${r.data.title}` : null,
    }),
  },
  {
    name: 'Last.fm',
    url: u => `https://ws.audioscrobbler.com/2.0/?method=user.getinfo&user=${u}&api_key=c9d19b2ef0ee6f95a32827e6e37b4b96&format=json`,
    check: r => r.status === 200 && r.data?.user?.name && !r.data?.error,
    extract: r => ({
      name: r.data?.user?.realname || null,
      location: r.data?.user?.country || null,
      stats: `${r.data?.user?.playcount || 0} Last.fm scrobbles`,
      profileUrl: r.data?.user?.url,
      created: r.data?.user?.registered?.['#text'],
    }),
  },
  {
    name: 'SoundCloud',
    url: u => `https://soundcloud.com/${u}`,
    check: r => r.status === 200 && r.data?.includes('soundcloud.com') && r.data?.includes('"@type":"MusicGroup"'),
    extract: r => {
      const descMatch = r.data?.match(/"description":"([^"]{0,200})/);
      const nameMatch = r.data?.match(/"name":"([^"]+)"/);
      return { name: nameMatch?.[1], bio: descMatch?.[1], profileUrl: `https://soundcloud.com/${u}` };
    },
  },
  {
    name: 'Twitch',
    url: u => `https://www.twitch.tv/${u}`,
    check: r => r.status === 200 && r.data?.includes('twitch.tv') && !r.data?.includes('"is404":true'),
    extract: r => {
      const descMatch = r.data?.match(/"description":"([^"]{0,200})/);
      return { bio: descMatch?.[1], profileUrl: `https://www.twitch.tv/${u}` };
    },
  },

  // ── Creative / Portfolio ──
  {
    name: 'Behance',
    url: u => `https://www.behance.net/${u}`,
    check: r => r.status === 200 && r.data?.includes('behance.net') && !r.data?.includes('404'),
    extract: r => {
      const nameMatch = r.data?.match(/<meta property="og:title" content="([^"]+)"/);
      return { name: nameMatch?.[1]?.replace(' on Behance',''), profileUrl: `https://www.behance.net/${u}` };
    },
  },
  {
    name: 'Dribbble',
    url: u => `https://dribbble.com/${u}`,
    check: r => r.status === 200 && r.data?.includes('dribbble.com') && !r.data?.includes('"404"'),
    extract: r => {
      const nameMatch = r.data?.match(/<meta property="og:title" content="([^"]+)"/);
      return { name: nameMatch?.[1]?.replace(' on Dribbble',''), profileUrl: `https://dribbble.com/${u}` };
    },
  },
  {
    name: 'Flickr',
    url: u => `https://www.flickr.com/people/${u}/`,
    check: r => r.status === 200 && r.data?.includes('flickr.com') && !r.data?.includes('not here'),
    extract: () => ({ profileUrl: `https://www.flickr.com/people/${u}` }),
  },

  // ── Music / Content ──
  {
    name: 'Patreon',
    url: u => `https://www.patreon.com/${u}`,
    check: r => r.status === 200 && r.data?.includes('patreon.com') && !r.data?.includes('"meta":{"status_code":404}'),
    extract: r => {
      const nameMatch = r.data?.match(/"full_name":"([^"]+)"/);
      return { name: nameMatch?.[1], profileUrl: `https://www.patreon.com/${u}` };
    },
  },
  {
    name: 'About.me',
    url: u => `https://about.me/${u}`,
    check: r => r.status === 200 && r.data?.includes('about.me') && !r.data?.includes('page not found'),
    extract: r => {
      const nameMatch = r.data?.match(/<title>([^<|]+)/);
      const locMatch = r.data?.match(/"location":"([^"]+)"/);
      return { name: nameMatch?.[1]?.trim(), location: locMatch?.[1], profileUrl: `https://about.me/${u}` };
    },
  },

  // ── Blogs ──
  {
    name: 'WordPress',
    url: u => `https://${u}.wordpress.com/wp-json/wp/v2/users/1`,
    check: r => r.status === 200 && r.data?.id,
    extract: r => ({
      name: r.data?.name,
      bio: r.data?.description?.slice(0, 200),
      profileUrl: `https://${u}.wordpress.com`,
    }),
  },
  {
    name: 'Tumblr',
    url: u => `https://${u}.tumblr.com/`,
    check: r => r.status === 200 && !r.data?.includes('There\'s nothing here'),
    extract: () => ({ profileUrl: `https://${u}.tumblr.com` }),
  },

  // ── Professional ──
  {
    name: 'ProductHunt',
    url: u => `https://www.producthunt.com/@${u}`,
    check: r => r.status === 200 && r.data?.includes('producthunt.com') && !r.data?.includes('"statusCode":404'),
    extract: r => {
      const nameMatch = r.data?.match(/<meta property="og:title" content="([^"]+)"/);
      return { name: nameMatch?.[1], profileUrl: `https://www.producthunt.com/@${u}` };
    },
  },
  {
    name: 'AngelList / Wellfound',
    url: u => `https://wellfound.com/${u}`,
    check: r => r.status === 200 && r.data?.includes('wellfound') && !r.data?.includes('404'),
    extract: () => ({ profileUrl: `https://wellfound.com/${u}` }),
  },
  {
    name: 'Bluesky',
    url: u => `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${u}.bsky.social`,
    check: r => r.status === 200 && r.data?.did,
    extract: r => ({
      name: r.data?.displayName,
      bio: r.data?.description?.slice(0, 200),
      location: null,
      profileUrl: `https://bsky.app/profile/${u}.bsky.social`,
    }),
  },
  {
    name: 'Mastodon (mastodon.social)',
    url: u => `https://mastodon.social/api/v1/accounts/lookup?acct=${u}`,
    check: r => r.status === 200 && r.data?.id,
    extract: r => ({
      name: r.data?.display_name,
      bio: r.data?.note?.replace(/<[^>]*>/g, '').slice(0, 200),
      profileUrl: r.data?.url,
      followers: r.data?.followers_count,
    }),
  },
];

// ─── Platform checker ─────────────────────────────────────────────────────────
async function checkPlatform(platform, username) {
  try {
    const url = platform.url(username);
    const headers = platform.headers ? platform.headers() : { 'User-Agent': 'FINDER_IO/2.0' };
    const resp = await axios.get(url, {
      timeout: 8000,
      headers,
      validateStatus: () => true,
      maxRedirects: 3,
    });
    if (platform.check(resp)) {
      const extracted = platform.extract ? platform.extract(resp, username) : {};
      return {
        platform: platform.name,
        username,
        found: true,
        ...extracted,
        confidence: 'medium',
      };
    }
  } catch (e) {}
  return { platform: platform.name, username, found: false };
}

// ─── Main export ──────────────────────────────────────────────────────────────
async function usernameScan(email, progressCb) {
  const usernames = generateUsernames(email);
  if (progressCb) progressCb({ sub: `Username candidates: ${usernames.join(', ')}` });

  const allResults = [];

  // For each username candidate, fire all platforms in parallel batches
  // Prioritise: try top 3 most likely usernames against ALL platforms first
  const topUsernames = usernames.slice(0, 4);
  const secondaryUsernames = usernames.slice(4, 10);

  const checkBatch = async (username) => {
    if (progressCb) progressCb({ sub: `Probing username: ${username} across ${PLATFORMS.length} platforms` });
    const batch = PLATFORMS.map(p => checkPlatform(p, username));
    const results = await Promise.allSettled(batch);
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value?.found) {
        allResults.push({ ...r.value, derivedFromEmail: email });
      }
    }
  };

  // Top usernames in parallel
  await Promise.allSettled(topUsernames.map(checkBatch));

  // Secondary usernames — only if top found very little
  if (allResults.length < 3) {
    for (const u of secondaryUsernames) await checkBatch(u);
  }

  return allResults.map(r => ({
    source: `Username Probe (${r.platform})`,
    platform: r.platform,
    found: true,
    username: r.username,
    name: r.name || null,
    location: r.location || null,
    bio: r.bio || null,
    company: r.company || null,
    profileUrl: r.profileUrl || null,
    blog: r.blog || null,
    twitterUsername: r.twitterUsername || null,
    followers: r.followers || null,
    publicRepos: r.publicRepos || null,
    karma: r.karma || null,
    created: r.created || null,
    socialLinks: r.socialLinks || [],
    confidence: 'medium',
  }));
}

module.exports = { usernameScan, generateUsernames };
