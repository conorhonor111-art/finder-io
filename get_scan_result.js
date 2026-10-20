/**
 * get_scan_result.js — start a scan and stream SSE until complete
 * Usage: node get_scan_result.js <email>
 */
require('dotenv').config();
const http = require('http');

const email = process.argv[2] || 'abusecomplaints@markmonitor.com';
const BASE = 'http://localhost:3700';

async function postScan(email) {
  return new Promise((res, rej) => {
    const body = JSON.stringify({ email });
    const opts = { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } };
    const req = http.request(BASE + '/api/scan', opts, (r) => {
      let data = '';
      r.on('data', d => data += d);
      r.on('end', () => { try { res(JSON.parse(data)); } catch(e) { rej(e); } });
    });
    req.on('error', rej);
    req.write(body);
    req.end();
  });
}

function streamSSE(scanId) {
  return new Promise((resolve, reject) => {
    const req = http.request(BASE + `/api/scan/progress/${scanId}`, { method: 'GET' }, (r) => {
      let buf = '';
      r.on('data', chunk => {
        buf += chunk;
        const lines = buf.split('\n');
        buf = lines.pop(); // keep incomplete line
        for (const line of lines) {
          if (!line.startsWith('data:')) continue;
          const raw = line.slice(5).trim();
          if (!raw) continue;
          let evt;
          try { evt = JSON.parse(raw); } catch { continue; }

          if (evt.status === 'progress') {
            process.stdout.write(`  [${evt.progress || 0}%] ${evt.step || ''} — ${evt.sub || ''}\r`);
          } else if (evt.status === 'complete') {
            console.log('\n');
            resolve(evt.report || evt.result || {});
            req.destroy();
          } else if (evt.status === 'error') {
            reject(new Error(evt.error || 'Scan error'));
            req.destroy();
          }
        }
      });
      r.on('end', () => reject(new Error('SSE stream ended before complete')));
    });
    req.on('error', reject);
    req.setTimeout(300000, () => { req.destroy(); reject(new Error('SSE timeout')); });
    req.end();
  });
}

function printReport(report) {
  // Phones live in report.phones.{confirmed,probable,possible}
  const confirmed = report.phones?.confirmed || [];
  const probable  = report.phones?.probable  || [];
  const possible  = report.phones?.possible  || [];
  const total = confirmed.length + probable.length + possible.length;

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  PHONES FOUND: ${total}  (conf=${confirmed.length}  prob=${probable.length}  poss=${possible.length})`);
  console.log('═'.repeat(60));

  if (total === 0) {
    console.log('  (none)');
  } else {
    const printTier = (label, phones) => {
      if (!phones.length) return;
      console.log(`  ── ${label} ──`);
      for (const p of phones) {
        console.log(`  ${p.formatted || p.e164 || p.raw} | ${p.country || '?'} | type=${p.type || '?'} | src=${p.corrobPending ? 'single-src' : 'multi-src'}`);
      }
    };
    printTier('CONFIRMED', confirmed);
    printTier('PROBABLE', probable);
    printTier('POSSIBLE', possible);
  }

  console.log(`\n${'─'.repeat(60)}`);
  console.log('  ALL ENGINE RESULTS');
  console.log('─'.repeat(60));
  // Show every engine that returned a result (not just the original 6)
  const SKIP_GENERIC = new Set(['People Search Brokers','Proxynova COMB (partial)']);
  let found = false;
  for (const f of (report.rawFindings || [])) {
    if (SKIP_GENERIC.has(f.source)) continue;
    found = true;
    const status = f.found !== undefined ? f.found : (f.exists !== undefined ? f.exists : '?');
    const label = f.source || f.platform || '(unknown)';
    console.log(`  [${label}] → ${status}`);
    if (f.phones?.length) console.log(`    📱 phones: ${f.phones.join(', ')}`);
    if (f.maskedPhone) console.log(`    🔒 masked: ${f.maskedPhone}`);
    if (f.note) console.log(`    ℹ  ${f.note}`);
    if (f.platforms?.length) console.log(`    platforms: ${f.platforms.slice(0,6).join(', ')}`);
    if (f.ips?.length) console.log(`    ips: ${f.ips.join(', ')}`);
    if (f.profiles?.length) console.log(`    profiles: ${f.profiles.join(', ')}`);
  }
  if (!found) console.log('  (none fired or all returned null)');

  console.log(`\n${'─'.repeat(60)}`);
  console.log('  ALL PHONE CLUES');
  console.log('─'.repeat(60));
  const phoneClues = (report.clues || []).filter(c => ['phone','partial_phone','phone_hint'].includes(c.type));
  if (phoneClues.length === 0) {
    console.log('  (none)');
  } else {
    for (const c of phoneClues) {
      console.log(`  ${c.type.toUpperCase()} | ${c.source} | ${c.value} | conf=${c.confidence}`);
    }
  }

  const regClues = (report.clues || []).filter(c => c.type === 'registration');
  if (regClues.length) {
    console.log(`\n${'─'.repeat(60)}`);
    console.log('  REGISTRATION HITS');
    console.log('─'.repeat(60));
    for (const c of regClues) console.log(`  ${c.value} | ${c.source}`);
  }
}

(async () => {
  console.log(`Scanning: ${email}`);
  const { scanId, cached } = await postScan(email);
  console.log(`Scan ID: ${scanId}${cached ? ' (cached)' : ''} — connecting to SSE...`);
  const report = await streamSSE(scanId);
  printReport(report);
  process.exit(0);
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
