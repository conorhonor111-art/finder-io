let currentReport = null;

// ═══════════════════════════════════════
// HISTORY
// ═══════════════════════════════════════

function loadHistory() {
  try {
    const history = JSON.parse(localStorage.getItem('finder_io_history') || '[]');
    const section = document.getElementById('historySection');
    const list = document.getElementById('historyList');

    if (history.length === 0) { section.style.display = 'none'; return; }

    section.style.display = 'block';
    list.innerHTML = '';
    history.slice(0, 12).forEach(item => {
      const el = document.createElement('div');
      el.className = 'history-item';
      el.innerHTML = `${esc(item.email)} <span class="history-phones">${item.phones || 0} phones</span>`;
      el.onclick = () => {
        document.getElementById('emailInput').value = item.email;
        startScan();
      };
      list.appendChild(el);
    });
  } catch (e) {}
}

function saveHistory(email, phoneCount) {
  try {
    let history = JSON.parse(localStorage.getItem('finder_io_history') || '[]');
    history = history.filter(h => h.email !== email);
    history.unshift({ email, phones: phoneCount, time: Date.now() });
    localStorage.setItem('finder_io_history', JSON.stringify(history.slice(0, 20)));
    loadHistory();
  } catch (e) {}
}

function clearHistory() {
  localStorage.removeItem('finder_io_history');
  loadHistory();
}

// ═══════════════════════════════════════
// SCAN
// ═══════════════════════════════════════

document.getElementById('emailInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startScan();
});

async function startScan() {
  const input = document.getElementById('emailInput');
  const email = input.value.trim();

  const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
  if (!email || !emailRegex.test(email) || email.length > 254) {
    input.style.borderColor = '#ff1744';
    setTimeout(() => input.style.borderColor = '', 1500);
    return;
  }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.querySelector('.btn-text').style.display = 'none';
  btn.querySelector('.btn-loading').style.display = 'inline-flex';

  document.getElementById('resultsSection').style.display = 'none';
  const progressSection = document.getElementById('progressSection');
  progressSection.style.display = 'block';

  const progressBar = document.getElementById('progressBar');
  const progressLabel = document.getElementById('progressLabel');
  const engineLog = document.getElementById('engineLog');
  const engineGrid = document.getElementById('engineGrid');
  progressBar.style.width = '0%';
  engineLog.innerHTML = '';
  engineGrid.innerHTML = '';

  const engines = [
    'DNS Reconnaissance', 'Social Media Recon', 'Deep Enumeration',
    'People Search', 'Breach Intelligence', 'Dorking'
  ];
  engines.forEach(name => {
    const tile = document.createElement('div');
    tile.className = 'engine-tile';
    tile.id = 'tile-' + name.replace(/\s+/g, '-').toLowerCase();
    tile.innerHTML = `<span class="tile-icon">○</span>${name}`;
    engineGrid.appendChild(tile);
  });

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const respData = await resp.json();
    if (!resp.ok) {
      progressLabel.textContent = `${resp.status === 429 ? '⏳ Rate limited' : '✗ Error'}: ${respData.error || 'Unknown error'}`;
      progressLabel.style.color = resp.status === 429 ? 'var(--orange)' : 'var(--red)';
      resetBtn(btn);
      return;
    }
    const { scanId } = respData;

    const eventSource = new EventSource(`/api/scan/progress/${scanId}`);

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.status === 'running') {
        progressBar.style.width = data.progress + '%';
        progressLabel.textContent = `Running: ${data.engine}...`;

        const tileId = 'tile-' + data.engine.split('(')[0].trim().replace(/\s+/g, '-').toLowerCase();
        document.querySelectorAll('.engine-tile.running').forEach(t => {
          t.className = 'engine-tile done';
          t.querySelector('.tile-icon').textContent = '✓';
        });
        const tile = document.getElementById(tileId);
        if (tile) {
          tile.className = 'engine-tile running';
          tile.querySelector('.tile-icon').textContent = '◌';
        }

        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry active';
        logEntry.textContent = `${data.engine}${data.sub ? ' → ' + data.sub : ''}`;
        engineLog.appendChild(logEntry);
        engineLog.scrollTop = engineLog.scrollHeight;
      }

      if (data.status === 'complete') {
        progressBar.style.width = '100%';
        progressLabel.textContent = 'Scan complete — building intelligence report...';

        document.querySelectorAll('.engine-tile').forEach(t => {
          t.className = 'engine-tile done';
          t.querySelector('.tile-icon').textContent = '✓';
        });

        eventSource.close();

        setTimeout(() => {
          progressSection.style.display = 'none';
          currentReport = data.report;
          renderResults(data.report);
          saveHistory(email, data.report?.summary?.totalPhonesFound || 0);
          resetBtn(btn);
        }, 600);
      }

      if (data.status === 'error') {
        progressLabel.textContent = `Error: ${data.error}`;
        progressLabel.style.color = '#ff1744';
        eventSource.close();
        resetBtn(btn);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      fallbackScan(email, btn, progressSection);
    };

  } catch (err) {
    fallbackScan(email, btn, progressSection);
  }
}

async function fallbackScan(email, btn, progressSection) {
  const progressLabel = document.getElementById('progressLabel');
  const progressBar = document.getElementById('progressBar');

  // First check status — if scan is still running server-side, poll until done
  // This handles Railway's SSE timeout cutting the connection before the scan finishes
  const MAX_WAIT_MS = 3 * 60 * 1000; // 3 minutes
  const POLL_INTERVAL = 2500;
  const started = Date.now();
  let dots = 0;

  async function poll() {
    try {
      const resp = await fetch(`/api/scan/status/${encodeURIComponent(email)}`);
      const data = await resp.json();

      if (data.status === 'complete') {
        // Got result from polling — render it
        progressBar.style.width = '100%';
        progressLabel.textContent = 'Scan complete — building intelligence report...';
        setTimeout(() => {
          progressSection.style.display = 'none';
          currentReport = data.report;
          renderResults(data.report);
          saveHistory(email, data.report?.summary?.totalPhonesFound || 0);
          resetBtn(btn);
        }, 600);
        return;
      }

      if (data.status === 'scanning') {
        // Still running — update label and keep polling
        dots = (dots + 1) % 4;
        const elapsed = Math.round((Date.now() - started) / 1000);
        progressLabel.textContent = `Scan running${'.'.repeat(dots + 1)} (${elapsed}s)`;
        // Nudge progress bar forward without exceeding 90%
        const current = parseFloat(progressBar.style.width) || 50;
        if (current < 90) progressBar.style.width = (current + 1.5) + '%';

        if (Date.now() - started < MAX_WAIT_MS) {
          setTimeout(poll, POLL_INTERVAL);
        } else {
          progressLabel.textContent = 'Scan timed out — please try again';
          progressLabel.style.color = '#ff1744';
          resetBtn(btn);
        }
        return;
      }

      // status === 'idle' means no active scan and no cache hit
      // Fall through to direct scan request
      progressLabel.textContent = 'Running full scan (direct mode)...';
      progressBar.style.width = '50%';
      const quickResp = await fetch(`/api/quick/${encodeURIComponent(email)}`);
      if (!quickResp.ok) {
        const err = await quickResp.json();
        throw new Error(err.error || `HTTP ${quickResp.status}`);
      }
      const report = await quickResp.json();
      progressBar.style.width = '100%';
      setTimeout(() => {
        progressSection.style.display = 'none';
        currentReport = report;
        renderResults(report);
        saveHistory(email, report?.summary?.totalPhonesFound || 0);
        resetBtn(btn);
      }, 500);

    } catch (err) {
      progressLabel.textContent = 'Scan failed: ' + err.message;
      progressLabel.style.color = '#ff1744';
      resetBtn(btn);
    }
  }

  progressLabel.textContent = 'Reconnecting...';
  progressBar.style.width = '50%';
  await poll();
}

function resetBtn(btn) {
  btn.disabled = false;
  btn.querySelector('.btn-text').style.display = 'inline';
  btn.querySelector('.btn-loading').style.display = 'none';
}

// ═══════════════════════════════════════
// RENDER RESULTS
// ═══════════════════════════════════════

function renderResults(report) {
  if (!report || !report.target) {
    console.error('renderResults called with invalid report:', report);
    return;
  }
  document.getElementById('resultsSection').style.display = 'block';
  document.getElementById('resultTarget').textContent = `${report.target} — ${new Date(report.timestamp).toLocaleString()}`;

  renderSummary(report);
  renderIdentity(report);
  renderPhones(report);
  renderClues(report);
  renderRegistrations(report);
  renderSocial(report);
  renderBreaches(report);
  renderVerification(report);
  renderRelatedEmails(report);
  renderDns(report);
  renderEmailVerification(report);
  renderRaw(report);
}

// ═══════════════════════════════════════
// IDENTITY — deep profile card
// ═══════════════════════════════════════

function renderIdentity(report) {
  const card = document.getElementById('identityCard');
  const body = document.getElementById('identityResults');
  body.innerHTML = '';

  const id = report.identity || {};
  const profiles = report.socialProfiles || [];

  const names = [...new Set([...(id.names || []), ...profiles.filter(p => p.name).map(p => p.name)])];
  const locations = [...new Set([...(id.locations || []), ...profiles.filter(p => p.location).map(p => p.location)])];
  const company = id.company || profiles.find(p => p.company)?.company;
  const bio = id.bio || profiles.find(p => p.bio)?.bio;
  const usernames = [...new Set(profiles.filter(p => p.username).map(p => `@${p.username} (${p.platform})`))];
  const repos = id.repos || [];

  // Name inferences from email pattern
  const nameInferences = id.nameInferences || [];

  // Deduplicate social links
  const seenLinks = new Set();
  const socialLinks = (id.socialLinks || []).filter(l => {
    const key = l.value; if (seenLinks.has(key)) return false; seenLinks.add(key); return true;
  });

  const hasData = names.length > 0 || company || locations.length > 0 || bio ||
                  usernames.length > 0 || socialLinks.length > 0 || id.jobTitle ||
                  nameInferences.length > 0 || repos.length > 0;

  if (!hasData) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  let html = '<div class="identity-grid">';

  if (names.length > 0) html += identityField('Full Name', names.join(', '));
  if (nameInferences.length > 0 && names.length === 0) {
    html += identityField('Name (Inferred)', nameInferences.map(n => n.name).join(', '),
      'Inferred from email pattern — needs verification');
  }
  if (usernames.length > 0) html += identityField('Usernames', usernames.join(', '));
  if (id.jobTitle) html += identityField('Job Title', id.jobTitle);
  if (company) html += identityField('Company', company);
  if (locations.length > 0) html += identityField('Location', locations.join(' · '));
  if (bio) html += identityField('Bio', bio);
  if (id.totalCommits) html += identityField('Git Activity', `${id.totalCommits} public commits`);
  if (repos.length > 0) html += identityField('Repositories', repos.slice(0, 5).join(', '));

  // Stealer data clues
  if (report.stealerData) {
    const s = report.stealerData;
    if (s.operatingSystem) html += identityField('Operating System', s.operatingSystem, 'From stealer log data');
    if (s.ips?.length > 0) html += identityField('Known IPs', s.ips.join(', '), 'From stealer log — may reveal location');
    if (s.dateCompromised) html += identityField('Compromise Date', s.dateCompromised, 'Machine was infected on this date');
  }

  // Partial phone from Microsoft
  if (report.partialPhone) {
    html += identityField('Phone Hint', `***-***-**${report.partialPhone}`, 'Last digits from Microsoft account recovery');
  }

  // EmailRep data
  if (report.emailReputation) {
    const rep = report.emailReputation;
    if (rep.reputation) html += identityField('Email Reputation', rep.reputation);
    if (rep.firstSeen) html += identityField('First Seen', rep.firstSeen, 'When this email first appeared online');
    if (rep.profiles?.length > 0) html += identityField('Known Profiles', rep.profiles.join(', '), 'Platforms where this email is registered');
    if (rep.dataBreaches) html += identityField('Data Breaches', 'YES', 'Email found in known data breaches');
    if (rep.darkWeb) html += identityField('Dark Web', 'YES', 'Email appeared on dark web');
  }

  html += '</div>';

  // Social links as clickable items
  if (socialLinks.length > 0) {
    html += `<div style="margin-top:14px;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-bottom:8px">LINKED ACCOUNTS</div>`;
    html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
    for (const link of socialLinks) {
      const isUrl = link.value.startsWith('http');
      if (isUrl) {
        html += `<a href="${esc(link.value)}" target="_blank" class="related-email" style="color:var(--yellow);border-color:rgba(255,215,64,0.2);background:rgba(255,215,64,0.05)">${esc(link.platform)}</a>`;
      } else {
        html += `<span class="related-email" style="color:var(--yellow);border-color:rgba(255,215,64,0.2);background:rgba(255,215,64,0.05)">${esc(link.platform)}: ${esc(link.value)}</span>`;
      }
    }
    html += '</div>';
  }

  body.innerHTML = html;
}

function identityField(label, value, hint) {
  return `<div class="identity-field">
    <div class="identity-label">${esc(label)}</div>
    <div class="identity-value">${esc(value)}${hint ? `<span class="identity-hint"> — ${esc(hint)}</span>` : ''}</div>
  </div>`;
}

// ═══════════════════════════════════════
// PHONES — with provenance
// ═══════════════════════════════════════

function renderPhones(report) {
  const card = document.getElementById('phoneCard');
  const body = document.getElementById('phoneResults');
  body.innerHTML = '';

  const phoneClues = (report.clues || []).filter(c => c.type === 'phone');

  const allPhones = [
    ...report.phones.confirmed.map(p => ({ ...p, confidence: 'high' })),
    ...report.phones.probable.map(p =>  ({ ...p, confidence: 'medium' })),
    ...report.phones.possible.map(p =>  ({ ...p, confidence: 'low' })),
  ];

  if (report.partialPhone) {
    allPhones.push({ raw: `***-***-**${report.partialPhone}`, formatted: `***-***-**${report.partialPhone}`, confidence: 'medium', note: 'Partial (Microsoft account)', flag: '', country: null, type: 'PARTIAL' });
  }

  const count = document.getElementById('phoneCount');
  count.textContent = `${allPhones.length} found`;
  card.style.display = 'block';

  if (allPhones.length === 0) {
    body.innerHTML = '<div class="no-results">No phone numbers extracted. Check the CLUES section below for leads — phone hints, platform registrations, and breach data may narrow it down.</div>';
    return;
  }

  for (const phone of allPhones) {
    const displayNum = phone.formatted || phone.raw || phone.number || '';
    const rawDigits = (phone.e164 || phone.raw || phone.number || '').replace(/[^\d]/g, '');

    // Find the clue that sourced this phone
    const clue = phoneClues.find(c => {
      const cleanClue = c.value.replace(/[^\d]/g, '');
      return cleanClue === rawDigits || (phone.e164 && cleanClue === phone.e164.replace(/[^\d]/g, ''));
    });

    const typeLabel = phone.lineType || phone.type;
    const showType = typeLabel && typeLabel !== 'UNKNOWN' && typeLabel !== 'PARTIAL';
    const carrierLine = phone.carrier ? `<div class="phone-carrier">${esc(phone.carrier)}</div>` : '';

    const item = document.createElement('div');
    item.className = `phone-item ${phone.confidence}`;
    item.onclick = () => copyToClipboard(phone.e164 || displayNum);
    item.innerHTML = `
      <div style="flex:1">
        <div class="phone-number">
          ${phone.flag ? `<span class="phone-flag">${phone.flag}</span>` : ''}
          ${esc(displayNum)}
        </div>
        ${(phone.countryName || showType) ? `
        <div class="phone-meta-row">
          ${phone.countryName ? `<span class="phone-country">${esc(phone.countryName)}</span>` : ''}
          ${showType ? `<span class="phone-type-badge">${esc(typeLabel)}</span>` : ''}
        </div>` : ''}
        ${carrierLine}
        <div class="phone-source">${clue ? esc(clue.note) : (phone.note ? esc(phone.note) : 'Click to copy')}</div>
        ${clue ? `<div class="phone-provenance">Source: ${esc(clue.source)}</div>` : ''}
      </div>
      <div class="phone-meta">
        <span class="confidence-badge confidence-${phone.confidence}">${phone.confidence}</span>
      </div>`;
    body.appendChild(item);
  }
}

// ═══════════════════════════════════════
// CLUES / EVIDENCE CHAIN
// ═══════════════════════════════════════

function renderClues(report) {
  const card = document.getElementById('cluesCard');
  const body = document.getElementById('cluesResults');
  if (!card) return;
  body.innerHTML = '';

  const clues = report.clues || [];
  if (clues.length === 0) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  document.getElementById('cluesCount').textContent = `${clues.length} clues`;

  // Group clues by type
  const groups = {};
  for (const clue of clues) {
    const group = clue.type;
    if (!groups[group]) groups[group] = [];
    groups[group].push(clue);
  }

  const typeLabels = {
    name: 'Names', name_inference: 'Name Guesses', username: 'Usernames',
    username_hint: 'Username Hints', username_pivot: 'Username Cross-Matches',
    phone: 'Phone Numbers', partial_phone: 'Phone Hints', phone_hint: 'Phone Clues',
    location: 'Locations', company: 'Companies', job_title: 'Job Titles',
    bio: 'Bios', website: 'Websites', social_link: 'Social Links',
    linked_account: 'Linked Accounts', profile_hint: 'Platform Profiles',
    registration: 'Registrations', email: 'Emails', related_email: 'Related Emails',
    repo: 'Repositories', activity: 'Activity', followers: 'Followers',
    ip: 'IP Addresses', os: 'Operating Systems', visited_url: 'Visited Sites',
    malware: 'Malware', compromise_date: 'Compromise Dates',
    reputation: 'Reputation', first_seen: 'First Seen', last_seen: 'Last Seen',
    breach_flag: 'Breach Flags', dark_web: 'Dark Web', cred_leak: 'Credential Leaks',
    auth: 'Auth Info', avatar: 'Photos', gender: 'Gender', age_range: 'Age',
    industry: 'Industry', paste: 'Pastes', registrar: 'Registrar',
    domain_created: 'Domain Dates', registrant: 'Registrant',
  };

  const typeOrder = [
    'name', 'name_inference', 'username', 'username_pivot', 'username_hint',
    'phone', 'partial_phone', 'phone_hint',
    'location', 'company', 'job_title', 'bio',
    'registration', 'profile_hint',
    'ip', 'os', 'visited_url', 'compromise_date', 'malware',
    'social_link', 'linked_account', 'website',
    'reputation', 'first_seen', 'breach_flag', 'dark_web', 'cred_leak',
    'repo', 'activity', 'followers',
    'related_email', 'paste',
    'gender', 'age_range', 'industry', 'avatar', 'auth',
    'registrar', 'domain_created', 'registrant',
  ];

  let html = '<div class="clues-container">';
  const sortedTypes = typeOrder.filter(t => groups[t]);
  // Add any remaining types not in order
  for (const t of Object.keys(groups)) {
    if (!sortedTypes.includes(t)) sortedTypes.push(t);
  }

  for (const type of sortedTypes) {
    const items = groups[type];
    const label = typeLabels[type] || type.replace(/_/g, ' ').toUpperCase();
    const confColor = items[0].confidence === 'high' ? 'var(--green)' :
                      items[0].confidence === 'medium' ? 'var(--orange)' : 'var(--text-dim)';

    html += `<div class="clue-group">`;
    html += `<div class="clue-type" style="color:${confColor}">${esc(label)}</div>`;
    for (const clue of items) {
      const badge = clue.confidence === 'high' ? '●' : clue.confidence === 'medium' ? '◐' : '○';
      html += `<div class="clue-item">
        <span class="clue-badge" style="color:${confColor}">${badge}</span>
        <span class="clue-value">${esc(clue.value)}</span>
        <span class="clue-source">${esc(clue.source)}</span>
        <span class="clue-note">${esc(clue.note)}</span>
      </div>`;
    }
    html += `</div>`;
  }
  html += '</div>';
  body.innerHTML = html;
}

// ═══════════════════════════════════════
// OTHER RENDERERS (same as before with minor improvements)
// ═══════════════════════════════════════

function renderRegistrations(report) {
  const card = document.getElementById('regCard');
  const body = document.getElementById('regResults');
  body.innerHTML = '';

  if (!report.registrations || report.registrations.totalChecked === 0) {
    card.style.display = 'none';
    return;
  }

  card.style.display = 'block';
  const reg = report.registrations;
  const count = document.getElementById('regCount');
  count.textContent = `${reg.registeredOn.length} / ${reg.totalChecked} platforms`;

  let html = '';
  if (reg.registeredOn.length > 0) {
    html += `<div style="margin-bottom:10px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--green);letter-spacing:1px">REGISTERED ON:</div>`;
    html += `<div class="reg-grid">${reg.registeredOn.map(name =>
      `<div class="reg-item found">${esc(name)}</div>`
    ).join('')}</div>`;
  }

  if (reg.notRegisteredOn.length > 0) {
    html += `<div style="margin-top:14px;margin-bottom:10px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-dim);letter-spacing:1px">NOT REGISTERED:</div>`;
    html += `<div class="reg-grid">${reg.notRegisteredOn.map(name =>
      `<div class="reg-item notfound">${esc(name)}</div>`
    ).join('')}</div>`;
  }

  if (reg.unknown?.length > 0) {
    html += `<div style="margin-top:14px;margin-bottom:10px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--orange);letter-spacing:1px">UNKNOWN (API ERROR):</div>`;
    html += `<div class="reg-grid">${reg.unknown.map(name =>
      `<div class="reg-item" style="border-color:rgba(255,152,0,0.2);color:var(--orange)">${esc(name)}</div>`
    ).join('')}</div>`;
  }

  body.innerHTML = html;
}

function renderSocial(report) {
  const card = document.getElementById('socialCard');
  const body = document.getElementById('socialResults');
  body.innerHTML = '';

  const profiles = report.socialProfiles || [];
  if (profiles.length === 0) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  document.getElementById('socialCount').textContent = `${profiles.length} found`;

  for (const p of profiles) {
    const item = document.createElement('div');
    item.className = 'social-item';
    const details = [];
    if (p.username) details.push(`@${p.username}`);
    if (p.name) details.push(p.name);
    if (p.location) details.push(p.location);
    if (p.company) details.push(p.company);
    if (p.bio) details.push(`"${p.bio.substring(0, 80)}${p.bio.length > 80 ? '...' : ''}"`);
    if (p.hasPhone) details.push('<span style="color:var(--green)">HAS PHONE</span>');
    if (p.profileUrl) details.push(`<a href="${esc(p.profileUrl)}" target="_blank">Profile</a>`);
    if (p.twitterUsername) details.push(`Twitter: @${esc(p.twitterUsername)}`);
    if (p.blog) details.push(`Web: <a href="${esc(p.blog)}" target="_blank">${esc(p.blog.replace(/https?:\/\//, ''))}</a>`);
    if (p.followers) details.push(`${p.followers} followers`);
    if (p.publicRepos) details.push(`${p.publicRepos} repos`);
    if (p.karma) details.push(`${p.karma.toLocaleString()} karma`);
    if (p.viaUsernamePivot) details.push('<span style="color:var(--cyan);font-size:10px">via username pivot</span>');
    if (p.confirmedByEmail) details.push('<span style="color:var(--green);font-size:10px;font-weight:bold">✓ EMAIL-CONFIRMED</span>');

    item.innerHTML = `
      <div class="social-platform" style="${p.confirmedByEmail ? 'color:var(--green)' : ''}">${esc(p.platform)}${p.confirmedByEmail ? ' ✓' : ''}</div>
      <div class="social-detail">${details.join(' · ')}</div>`;
    body.appendChild(item);
  }
}

function renderBreaches(report) {
  const card = document.getElementById('breachCard');
  const body = document.getElementById('breachResults');
  body.innerHTML = '';

  const breaches = report.breachData || [];
  if (breaches.length === 0) { card.style.display = 'none'; return; }

  card.style.display = 'block';

  for (const b of breaches) {
    const item = document.createElement('div');
    item.className = 'breach-item';

    if (b.platform === 'HIBP' && b.found) {
      item.innerHTML = `
        <div class="breach-name">Have I Been Pwned: ${b.totalBreaches} breach(es)</div>
        <div class="breach-detail">
          ${b.hasPhoneInBreaches
            ? `<span style="color:var(--green)">PHONE DATA:</span> ${b.breachesWithPhone.map(x => x.name).join(', ')}`
            : 'No phone numbers in breach data classes'}
          ${b.breachNames ? `<br>Breaches: ${b.breachNames.slice(0, 10).join(', ')}${b.breachNames.length > 10 ? '...' : ''}` : ''}
        </div>`;
    } else if (b.source === 'HudsonRock Cavalier' && b.found) {
      item.innerHTML = `
        <div class="breach-name">HudsonRock Cavalier: ${b.compromisedMachines} machine(s)</div>
        <div class="breach-detail">
          ${b.phones?.length > 0 ? `<span style="color:var(--green)">PHONE(S):</span> ${b.phones.join(', ')}<br>` : ''}
          ${b.usernames?.length > 0 ? `Usernames: ${b.usernames.join(', ')}<br>` : ''}
          ${b.ips?.length > 0 ? `IPs: ${b.ips.join(', ')}<br>` : ''}
          ${b.partialPasswords?.length > 0 ? `Passwords (partial): ${b.partialPasswords.join(', ')}<br>` : ''}
          ${b.urls?.length > 0 ? `Sites visited: ${b.urls.slice(0, 8).map(u => '<span class="stealer-url">' + esc(u) + '</span>').join(', ')}<br>` : ''}
          ${b.malwareFamily ? `Malware: ${esc(b.malwareFamily)}<br>` : ''}
          ${b.operatingSystem ? `OS: ${esc(b.operatingSystem)}<br>` : ''}
          ${b.dateCompromised ? `Date: ${esc(b.dateCompromised)}` : ''}
        </div>`;
    } else if (b.source === 'IntelX Phonebook') {
      item.innerHTML = `
        <div class="breach-name">IntelX Phonebook: ${b.phones.length} phone(s)</div>
        <div class="breach-detail">${b.phones.map(esc).join(', ')}</div>`;
    } else if (b.source === 'IntelX Related Emails') {
      item.innerHTML = `
        <div class="breach-name">IntelX Related Emails (${b.relatedEmails.length})</div>
        <div class="breach-detail">${b.relatedEmails.map(esc).join(', ')}</div>`;
    } else if (b.source === 'IntelX Related Domains') {
      item.innerHTML = `
        <div class="breach-name">IntelX Related Domains (${b.domains.length})</div>
        <div class="breach-detail">${b.domains.map(esc).join(', ')}</div>`;
    } else if (b.source === 'DarkSearch.io' || b.source === 'Ahmia.fi (Tor)') {
      item.style.borderLeftColor = 'var(--red)';
      item.innerHTML = `
        <div class="breach-name" style="color:var(--red)">🕵️ ${esc(b.source)}: ${b.totalResults} result(s)</div>
        <div class="breach-detail">
          ${b.phones?.length > 0 ? `<span style="color:var(--green)">PHONES FOUND:</span> ${b.phones.map(esc).join(', ')}<br>` : ''}
          ${(b.results||[]).slice(0,3).map(r => `<div style="margin:4px 0;font-size:10px;color:var(--text-dim)">${r.title ? '<b>' + esc(r.title.slice(0,70)) + '</b><br>' : ''}${esc((r.preview||'').slice(0,120))}</div>`).join('')}
        </div>`;
    } else if (b.source === 'GhostProject.fr' && b.found) {
      item.style.borderLeftColor = 'var(--red)';
      item.innerHTML = `
        <div class="breach-name" style="color:var(--red)">💀 GhostProject.fr: ${b.totalRecords} plaintext record(s)</div>
        <div class="breach-detail">
          ${b.hasPasswords ? '<span style="color:var(--red)">CLEARTEXT PASSWORDS FOUND</span><br>' : ''}
          ${b.breachSources?.length > 0 ? 'Sources: ' + b.breachSources.map(esc).join(', ') : ''}
        </div>`;
    } else if (b.source === 'HaveIBeenSold' && b.found) {
      item.innerHTML = `
        <div class="breach-name">📧 Sold to Data Brokers</div>
        <div class="breach-detail">${b.sources?.length > 0 ? 'Via: ' + b.sources.map(esc).join(', ') : 'Email sold to marketing broker networks'}</div>`;
    } else if (b.source === 'Spy.pet' && b.found) {
      item.innerHTML = `
        <div class="breach-name" style="color:var(--purple)">💬 Discord (Spy.pet breach)</div>
        <div class="breach-detail">
          ${b.username ? `Username: @${esc(b.username)}<br>` : ''}
          ${b.discordId ? `Discord ID: ${esc(b.discordId)}` : ''}
        </div>`;
    } else if (b.source === 'OpenCorporates' && b.found) {
      item.innerHTML = `
        <div class="breach-name">🏢 OpenCorporates: ${b.totalMatches} record(s)</div>
        <div class="breach-detail">
          ${(b.companies||[]).slice(0,3).map(c => `${esc(c.name||'')} ${c.role ? '(' + esc(c.role) + ')' : ''} ${c.jurisdiction ? '[' + esc(c.jurisdiction) + ']' : ''}`).join('<br>')}
        </div>`;
    } else if (b.source === 'IntelX Deep' && b.found) {
      item.innerHTML = `
        <div class="breach-name">🔎 IntelX Deep Scan: ${b.totalRecords} record(s)</div>
        <div class="breach-detail">
          ${b.darkweb > 0  ? `<span style="color:var(--red)">Dark web: ${b.darkweb}</span>&nbsp;&nbsp;` : ''}
          ${b.pastes > 0   ? `Pastes: ${b.pastes}&nbsp;&nbsp;` : ''}
          ${b.breaches > 0 ? `Breaches: ${b.breaches}` : ''}
        </div>`;
    } else if (b.source?.includes('Leak')) {
      item.innerHTML = `
        <div class="breach-name">${esc(b.source)}</div>
        <div class="breach-detail">${b.found ? 'Found in leak database' : 'Not found'}</div>`;
    } else if (b.phones?.length > 0) {
      item.innerHTML = `
        <div class="breach-name">${esc(b.source || 'Breach Data')}</div>
        <div class="breach-detail">Phones: ${b.phones.map(esc).join(', ')}</div>`;
    } else {
      item.innerHTML = `
        <div class="breach-name">${esc(b.source || 'Unknown')}</div>
        <div class="breach-detail">${b.found !== undefined ? (b.found ? 'Match found' : 'No match') : 'Data collected'}</div>`;
    }

    body.appendChild(item);
  }

  // Stealer data — only show standalone block if NOT already in breachData
  const hudsonInBreaches = breaches.some(b => b.source === 'HudsonRock Cavalier' && b.found);
  if (report.stealerData && !hudsonInBreaches) {
    const s = report.stealerData;
    const stealer = document.createElement('div');
    stealer.className = 'breach-item';
    stealer.style.borderLeftColor = 'var(--red)';
    stealer.innerHTML = `
      <div class="breach-name" style="color:var(--red)">STEALER LOG DATA</div>
      <div class="breach-detail">
        Compromised Machines: ${s.compromisedMachines}<br>
        ${s.usernames?.length > 0 ? `Usernames: ${s.usernames.map(esc).join(', ')}<br>` : ''}
        ${s.ips?.length > 0 ? `IPs: ${s.ips.map(esc).join(', ')}<br>` : ''}
        ${s.urls?.length > 0 ? `Sites: ${s.urls.slice(0, 8).map(u => '<span class="stealer-url">' + esc(u) + '</span>').join(' ')}<br>` : ''}
        ${s.partialPasswords?.length > 0 ? `Passwords (partial): ${s.partialPasswords.map(esc).join(', ')}<br>` : ''}
        ${s.malwareFamily ? `Malware: ${esc(s.malwareFamily)}<br>` : ''}
        ${s.operatingSystem ? `OS: ${esc(s.operatingSystem)}<br>` : ''}
        ${s.dateCompromised ? `Date: ${esc(s.dateCompromised)}` : ''}
      </div>`;
    body.appendChild(stealer);
  }
}

function renderRelatedEmails(report) {
  const card = document.getElementById('relatedEmailsCard');
  const body = document.getElementById('relatedEmailsResults');
  body.innerHTML = '';

  const emails = report.relatedEmails || [];
  if (emails.length === 0) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  body.innerHTML = '';
  for (const email of emails) {
    const span = document.createElement('span');
    span.className = 'related-email';
    span.textContent = email;
    span.onclick = () => { document.getElementById('emailInput').value = email; startScan(); };
    body.appendChild(span);
  }
}

function renderDns(report) {
  const card = document.getElementById('dnsCard');
  const body = document.getElementById('dnsResults');
  body.innerHTML = '';

  if (!report.dnsInfo || report.dnsInfo.length === 0) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  for (const dns of report.dnsInfo) {
    if (dns.domain) addDnsItem(body, 'Domain', dns.domain);
    if (dns.provider) addDnsItem(body, 'Provider', dns.provider);
    if (dns.isCustomDomain !== undefined) addDnsItem(body, 'Type', dns.isCustomDomain ? 'Custom / Business' : 'Free Provider');
    if (dns.mxRecords?.length > 0) addDnsItem(body, 'MX Records', dns.mxRecords.join(', '));
    if (dns.companyPhones?.length > 0) addDnsItem(body, 'Company Phones', dns.companyPhones.join(', '));
    if (dns.contactPagePhones?.length > 0) addDnsItem(body, 'Contact Phones', dns.contactPagePhones.join(', '));
  }
}

function renderEmailVerification(report) {
  const card = document.getElementById('emailVerCard');
  const body = document.getElementById('emailVerResults');
  body.innerHTML = '';

  const ver = report.emailVerification;
  if (!ver) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  const fields = [
    { label: 'Deliverable', value: ver.deliverable },
    { label: 'Disposable', value: ver.disposable },
    { label: 'Webmail', value: ver.webmail },
    { label: 'Free Provider', value: ver.freeProvider || ver.free },
    { label: 'Catch-All', value: ver.catchAll || ver.catch_all },
    { label: 'Host Exists', value: ver.hostExists || ver.host_exists },
    { label: 'MX Valid', value: ver.mxValid },
    { label: 'Score', value: ver.score != null ? `${ver.score}/100` : undefined },
  ].filter(f => f.value !== undefined && f.value !== null);

  body.innerHTML = `<div class="ver-grid">${fields.map(f => {
    // isGood: true means this state is desirable (green), false means bad (red)
    const isGood = f.label === 'Disposable' ? !f.value : f.value;
    const colorClass = isGood === true ? 'ver-yes' : isGood === false ? 'ver-no' : 'ver-unknown';
    return `<div class="ver-item">
      <span class="ver-label">${esc(f.label)}</span>
      <span class="ver-value ${colorClass}">
        ${f.value === true ? 'YES' : f.value === false ? 'NO' : esc(String(f.value))}
      </span>
    </div>`;
  }).join('')}</div>`;
}

function renderRaw(report) {
  const card = document.getElementById('rawCard');
  const body = document.getElementById('rawResults');
  card.style.display = 'block';
  body.innerHTML = `<pre class="raw-json">${esc(JSON.stringify(report.rawFindings, null, 2))}</pre>`;
}

function renderSummary(report) {
  const card = document.getElementById('summaryCard');
  const body = document.getElementById('summaryResults');
  card.style.display = 'block';

  const totalPhones = report.summary.totalPhonesFound;
  const profiles = report.socialProfiles?.length || 0;
  const engines = report.summary.enginesRan?.length || 0;
  const confidence = report.summary.highestConfidence;
  const registrations = report.registrations?.registeredOn?.length || 0;
  const breaches = report.breachData?.length || 0;
  const clueCount = report.clues?.length || 0;

  body.innerHTML = `
    <div class="summary-grid">
      <div class="summary-stat">
        <div class="stat-value" style="color:var(--green)">${totalPhones}</div>
        <div class="stat-label">Phones Found</div>
      </div>
      <div class="summary-stat">
        <div class="stat-value">${profiles}</div>
        <div class="stat-label">Social Profiles</div>
      </div>
      <div class="summary-stat">
        <div class="stat-value" style="color:var(--purple)">${registrations}/${report.registrations?.totalChecked || '?'}</div>
        <div class="stat-label">Registered</div>
      </div>
      <div class="summary-stat">
        <div class="stat-value" style="color:var(--orange)">${breaches}</div>
        <div class="stat-label">Breach Sources</div>
      </div>
      <div class="summary-stat">
        <div class="stat-value">${engines}</div>
        <div class="stat-label">Intel Sources</div>
      </div>
      <div class="summary-stat">
        <div class="stat-value" style="color:var(--cyan)">${clueCount}</div>
        <div class="stat-label">Total Clues</div>
      </div>
    </div>
    <div style="margin-top:14px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-dim)">
      Sources: ${(report.summary.enginesRan || []).join(' · ')}
    </div>`;
}

// ═══════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════

function addDnsItem(container, label, value) {
  const item = document.createElement('div');
  item.className = 'dns-item';
  item.innerHTML = `<div class="dns-label">${esc(label)}</div><div class="dns-value">${esc(value)}</div>`;
  container.appendChild(item);
}

function toggleRaw() {
  const body = document.getElementById('rawResults');
  const arrow = document.getElementById('rawArrow');
  const show = body.style.display === 'none';
  body.style.display = show ? 'block' : 'none';
  arrow.classList.toggle('open', show);
}

function toggleClues() {
  const body = document.getElementById('cluesResults');
  const arrow = document.getElementById('cluesArrow');
  const show = body.style.display === 'none';
  body.style.display = show ? 'block' : 'none';
  arrow.classList.toggle('open', show);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text.replace(/[^\d+]/g, '')).then(() => {
    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = `Copied: ${text}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
  });
}

function formatPhone(raw) {
  let cleaned = raw.replace(/\./g, ' ').trim();
  const digits = cleaned.replace(/[^\d+]/g, '');
  if (digits.startsWith('+1') && digits.length === 12) {
    return `+1 (${digits.slice(2,5)}) ${digits.slice(5,8)}-${digits.slice(8)}`;
  }
  if (digits.length === 11 && digits.startsWith('1')) {
    return `+1 (${digits.slice(1,4)}) ${digits.slice(4,7)}-${digits.slice(7)}`;
  }
  if (digits.length === 10) {
    return `(${digits.slice(0,3)}) ${digits.slice(3,6)}-${digits.slice(6)}`;
  }
  if (digits.startsWith('+') && digits.length >= 11) return cleaned;
  return cleaned;
}

function esc(str) {
  if (typeof str !== 'string') return String(str || '');
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return str.replace(/[&<>"']/g, c => map[c]);
}

// ═══════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════

function exportJSON() {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `FINDER_IO_${currentReport.target}_${Date.now()}.json`);
}

function exportCSV() {
  if (!currentReport) return;
  const lines = ['Type,Value,Confidence,Source,Note'];

  // Export all clues
  for (const clue of (currentReport.clues || [])) {
    lines.push(`"${clue.type}","${(clue.value || '').replace(/"/g, '""')}","${clue.confidence}","${clue.source}","${(clue.note || '').replace(/"/g, '""')}"`);
  }

  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  downloadBlob(blob, `FINDER_IO_${currentReport.target}_${Date.now()}.csv`);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

function exportTXT() {
  if (!currentReport) return;
  const r = currentReport;
  const sep = '═'.repeat(60);
  const lines = [
    'FINDER_IO Intelligence Report',
    sep,
    `Target  : ${r.target}`,
    `Scanned : ${new Date(r.timestamp).toLocaleString()}`,
    `Engines : ${(r.summary?.enginesRan||[]).length}  |  Clues: ${(r.clues||[]).length}`,
    '',
    sep, 'IDENTITY', sep,
    `Full Name  : ${(r.identity?.names||[]).join(', ') || 'None found'}`,
    `Locations  : ${(r.identity?.locations||[]).join(', ') || 'None found'}`,
    `Company    : ${r.identity?.company || 'None found'}`,
    `Job Title  : ${r.identity?.jobTitle || 'None found'}`,
    `Bio        : ${r.identity?.bio || 'None found'}`,
    '',
    sep, 'PHONE NUMBERS', sep,
    'Confirmed (high confidence):',
    ...(r.phones?.confirmed||[]).map(p => `  ${p.flag||''} ${p.formatted||p.raw}  ${p.countryName ? '| ' + p.countryName : ''}  ${p.carrier ? '| ' + p.carrier : ''}  ${p.lineType ? '| ' + p.lineType : ''}`),
    (r.phones?.confirmed?.length === 0 ? '  None' : ''),
    'Probable (medium confidence):',
    ...(r.phones?.probable||[]).map(p => `  ${p.flag||''} ${p.formatted||p.raw}`),
    (r.phones?.probable?.length === 0 ? '  None' : ''),
    'Possible (low confidence):',
    ...(r.phones?.possible||[]).map(p => `  ${p.formatted||p.raw}`),
    (r.phones?.possible?.length === 0 ? '  None' : ''),
    '',
    sep, 'SOCIAL PROFILES', sep,
    ...(r.socialProfiles||[]).map(p => `  ${(p.platform||'').padEnd(25)} @${(p.username||'?').padEnd(20)} ${p.name||''} ${p.profileUrl ? '→ '+p.profileUrl : ''}`),
    '',
    sep, 'REGISTRATIONS', sep,
    `  Registered on: ${(r.registrations?.registeredOn||[]).join(', ')||'None'}`,
    '',
    sep, 'BREACH & DARK WEB DATA', sep,
    ...(r.breachData||[]).filter(b => b.found || b.totalRecords > 0).map(b => `  ${b.source||b.platform}: ${b.totalRecords||b.totalResults||b.totalBreaches||'found'}`),
    '',
    sep, 'RELATED EMAILS', sep,
    ...(r.relatedEmails||[]).map(e => `  ${e}`),
    '',
    sep, `ALL CLUES (${(r.clues||[]).length} total)`, sep,
    ...(r.clues||[]).map(c => `  [${(c.confidence||'?').toUpperCase().padEnd(6)}] ${(c.type||'').padEnd(20)} ${String(c.value||'').slice(0,60).padEnd(60)} ← ${c.source||''}`),
  ];
  const blob = new Blob([lines.filter(l => l !== undefined).join('\n')], { type: 'text/plain;charset=utf-8' });
  downloadBlob(blob, `FINDER_IO_${r.target}_${Date.now()}.txt`);
}

// ═══════════════════════════════════════
// VERIFICATION CARD
// ═══════════════════════════════════════

function renderVerification(report) {
  const card = document.getElementById('verCard');
  const body = document.getElementById('verResults');
  if (!card || !body) return;

  const v = report.verification;
  // Show single-source-downgrade info even if full verification didn't run
  const pendingPhones = (report.phones?.probable||[]).filter(p => p.corrobPending);
  if ((!v || !v.ran) && pendingPhones.length === 0) {
    card.style.display = 'none';
    return;
  }
  if ((!v || !v.ran) && pendingPhones.length > 0) {
    card.style.display = 'block';
    body.innerHTML = `<div class="ver-summary"><span class="ver-stat neutral">⚠ ${pendingPhones.length} single-source phone(s) held in Probable tier pending 2nd-source confirmation</span></div>
      <div class="ver-section" style="font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace">${pendingPhones.map(p => esc(p.formatted||p.raw)).join(' · ')}</div>`;
    return;
  }

  const statusIcon = (v.phonesRejected > 0 || v.profilesDead > 0) ? '⚠' : '✓';
  let html = `<div class="ver-summary">
    <span class="ver-stat good">✓ ${v.phonesVerified} phone${v.phonesVerified !== 1 ? 's' : ''} verified</span>
    <span class="ver-stat ${v.phonesRejected > 0 ? 'bad' : 'neutral'}">✗ ${v.phonesRejected} rejected</span>
    <span class="ver-stat neutral">🔗 ${v.corroborationUpgrades.length} confidence upgrade${v.corroborationUpgrades.length !== 1 ? 's' : ''}</span>
    <span class="ver-stat neutral">🌐 ${v.profilesChecked} profile${v.profilesChecked !== 1 ? 's' : ''} checked (${v.profilesDead} dead)</span>
  </div>`;

  if (v.rejectedPhones && v.rejectedPhones.length > 0) {
    html += `<div class="ver-section"><span class="ver-label">Rejected phones:</span><ul>`;
    for (const r of v.rejectedPhones) {
      html += `<li class="ver-reject"><span class="badge-bad">INVALID</span> ${esc(r.phone)} — <em>${esc(r.reason)}</em></li>`;
    }
    html += `</ul></div>`;
  }

  if (v.enrichedPhones && v.enrichedPhones.length > 0) {
    html += `<div class="ver-section"><span class="ver-label">Verified phone enrichment:</span><ul>`;
    for (const e of v.enrichedPhones) {
      const parts = [e.carrier, e.lineType, e.callerName].filter(Boolean).join(' · ');
      html += `<li><span class="badge-good">✓</span> ${esc(e.phone)}${parts ? ' — ' + esc(parts) : ''}</li>`;
    }
    html += `</ul></div>`;
  }

  if (v.deadProfiles && v.deadProfiles.length > 0) {
    html += `<div class="ver-section"><span class="ver-label">Dead profile URLs (${v.deadProfiles.length}):</span><ul>`;
    for (const d of v.deadProfiles) {
      html += `<li><span class="badge-bad">404</span> ${esc(d.platform)} — <a href="${esc(d.url)}" target="_blank">${esc(d.url)}</a></li>`;
    }
    html += `</ul></div>`;
  }

  if (v.corroborationUpgrades && v.corroborationUpgrades.length > 0) {
    html += `<div class="ver-section"><span class="ver-label">Confidence upgrades (${v.corroborationUpgrades.length}):</span><ul>`;
    for (const u of v.corroborationUpgrades.slice(0, 8)) {
      html += `<li>${esc(u.type)}: <strong>${esc(String(u.value).slice(0,60))}</strong> <span class="conf-up">${u.oldConfidence} → ${u.newConfidence}</span> (${u.sourceCount} sources)</li>`;
    }
    html += `</ul></div>`;
  }

  body.innerHTML = html;
  card.style.display = 'block';
}

// Init
loadHistory();
