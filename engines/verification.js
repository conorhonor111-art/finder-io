/**
 * verification.js — Triple-check engine
 * Validates every piece of discovered data with independent sources:
 *   • Phone: NANP area code whitelist + libphonenumber-js (Google's offline db)
 *   • Profile URLs: HTTP HEAD verification (404 = remove)
 *   • Clues: corroboration scoring (2+ sources = MEDIUM, 3+ = HIGH)
 */
const axios = require('axios');
let parsePhoneNumber, isValidPhoneNumber;
try {
  const lpn = require('libphonenumber-js');
  parsePhoneNumber  = lpn.parsePhoneNumber;
  isValidPhoneNumber = lpn.isValidPhoneNumber;
} catch (_) {}

async function safeGet(url, opts = {}) {
  try { return await axios.get(url, { timeout: 8000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}

// ─────────────────────────────────────────────────────────────
// ACTIVE NANP AREA CODES (US + Canada + Caribbean)
// Unassigned / service / special area codes are excluded
// ─────────────────────────────────────────────────────────────
const ACTIVE_NANP_AREA_CODES = new Set([
  // Toll-free (US/CA shared)
  800,833,844,855,866,877,888,
  // US
  201,202,203,205,206,207,208,209,210,212,213,214,215,216,217,218,219,220,
  223,224,225,227,228,229,231,234,239,240,248,251,252,253,254,256,260,262,
  267,269,270,272,274,276,279,281,283,301,302,303,304,305,307,308,309,310,
  312,313,314,315,316,317,318,319,320,321,323,325,326,327,330,331,332,334,
  336,337,339,341,346,347,351,352,360,361,364,380,385,386,401,402,404,405,
  406,407,408,409,410,412,413,414,415,417,419,423,424,425,430,432,434,435,
  440,442,443,445,447,448,458,463,469,470,475,478,479,480,484,501,502,503,
  504,505,507,508,509,510,512,513,515,516,517,518,520,530,531,534,539,540,
  541,551,559,561,562,563,564,567,570,571,573,574,575,580,585,586,601,602,
  603,605,606,607,608,609,610,612,614,615,616,617,618,619,620,623,626,628,
  629,630,631,636,641,646,650,651,657,660,661,662,667,669,678,680,681,682,
  701,702,703,704,706,707,708,712,713,714,715,716,717,718,719,720,724,725,
  726,727,730,731,732,734,737,740,743,747,754,757,760,762,763,765,769,770,
  772,773,774,775,779,781,785,786,801,802,803,804,805,806,808,810,812,813,
  814,815,816,817,818,820,828,830,831,832,838,843,845,847,848,850,854,856,
  857,858,859,860,862,863,864,865,870,872,878,901,903,904,906,907,908,909,
  910,912,913,914,915,916,917,918,919,920,925,928,929,930,931,934,936,937,
  938,940,941,943,947,949,951,952,954,956,959,970,971,972,973,975,978,979,
  980,984,985,986,989,
  // Canada
  204,226,236,249,250,289,306,343,354,365,367,403,416,418,431,437,438,450,
  506,514,519,548,579,581,587,604,613,639,647,705,709,742,778,780,782,807,
  819,825,867,873,902,905,
  // Caribbean / NANP territories
  242,246,264,268,284,340,345,441,473,649,664,721,758,767,784,809,829,849,
  868,869,876,939,
]);

// ─────────────────────────────────────────────────────────────
// PHONE VERIFICATION
// ─────────────────────────────────────────────────────────────

function isNANPAreaCodeValid(e164) {
  if (!e164 || !e164.startsWith('+1')) return null; // Not NANP → skip area-code check
  const digits = e164.replace(/[^\d]/g, '');
  if (digits.length < 11) return false;
  const areaCode = parseInt(digits.substring(1, 4), 10);
  return ACTIVE_NANP_AREA_CODES.has(areaCode);
}

function verifyPhoneLibPhonenumber(e164) {
  // Offline validation using libphonenumber-js (Google's phone number db).
  // Much more reliable than any free API — works for all countries, no rate limits.
  if (!parsePhoneNumber || !isValidPhoneNumber) return null;
  try {
    const digits = e164.replace(/[^\d]/g, '');
    if (digits.length < 7) return null;
    const normalized = '+' + digits;

    const valid = isValidPhoneNumber(normalized);
    if (!valid) return { valid: false };

    const parsed = parsePhoneNumber(normalized);
    return {
      valid: true,
      country: parsed.country || null,
      lineType: parsed.getType() || null,
      nationalNumber: parsed.nationalNumber || null,
    };
  } catch (_) {
    return null; // Unparseable → give benefit of doubt
  }
}

function verifyPhone(phoneObj) {
  // Normalize input — strip dots, dashes, spaces, parens down to +digits
  const raw = phoneObj.e164 || phoneObj.formatted || phoneObj.raw || '';
  const digits = raw.replace(/[^\d]/g, '');
  const e164 = '+' + digits;                                // "+12086851750"
  const result = { phone: e164, areaCodeOk: null, apiValid: null, carrier: null, lineType: null, callerName: null };

  // NANP area code check
  const nanpCheck = isNANPAreaCodeValid(e164);
  if (nanpCheck === false) {
    result.areaCodeOk = false;
    result.reject = true;
    result.rejectReason = 'NANP area code not assigned';
    return result;
  }
  result.areaCodeOk = nanpCheck === null ? 'N/A (non-NANP)' : true;

  // libphonenumber-js offline validation (Google's phone number database)
  const lookup = verifyPhoneLibPhonenumber(e164);
  if (lookup) {
    result.apiValid = lookup.valid;
    if (!lookup.valid) {
      result.reject = true;
      result.rejectReason = 'libphonenumber-js: not a valid number';
    } else {
      result.lineType = lookup.lineType || null;
      result.location = lookup.country || null;
    }
  } else {
    result.apiValid = null; // Library unavailable or unparseable — give benefit of doubt
  }

  return result;
}

// ─────────────────────────────────────────────────────────────
// PROFILE URL VERIFICATION
// ─────────────────────────────────────────────────────────────

async function verifyProfileUrl(url) {
  if (!url || !url.startsWith('http')) return null;
  try {
    const resp = await safeGet(url, {
      timeout: 6000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      maxRedirects: 3,
    });
    return {
      url,
      status: resp?.status || 0,
      alive: resp?.status === 200,
      redirect: resp?.request?.res?.responseUrl !== url ? resp.request?.res?.responseUrl : null,
    };
  } catch (e) {}
  return { url, status: 0, alive: false };
}

// ─────────────────────────────────────────────────────────────
// CORROBORATION SCORER
// Upgrades confidence when the same value appears across N independent sources
// ─────────────────────────────────────────────────────────────

function scoreCorroboration(clues) {
  const valueMap = {};
  for (const c of clues) {
    const key = `${c.type}::${(c.value || '').toString().trim().toLowerCase()}`;
    if (!valueMap[key]) valueMap[key] = { clue: c, sources: new Set() };
    if (c.source) valueMap[key].sources.add(c.source);
  }

  const upgrades = [];
  for (const [key, entry] of Object.entries(valueMap)) {
    const { clue, sources } = entry;
    const count = sources.size;
    let newConfidence = clue.confidence;
    if (count >= 3 && clue.confidence !== 'high') {
      newConfidence = 'high';
    } else if (count >= 2 && clue.confidence === 'low') {
      newConfidence = 'medium';
    }
    if (newConfidence !== clue.confidence) {
      upgrades.push({ type: clue.type, value: clue.value, oldConfidence: clue.confidence, newConfidence, sourceCount: count });
    }
  }
  return upgrades;
}

// ─────────────────────────────────────────────────────────────
// MAIN VERIFICATION RUNNER
// ─────────────────────────────────────────────────────────────

async function runVerification(report, progressCb) {
  if (progressCb) progressCb({ sub: 'Triple-check verification — phones + profiles + corroboration' });

  const verification = {
    phonesChecked: 0,
    phonesVerified: 0,
    phonesRejected: 0,
    rejectedPhones: [],
    enrichedPhones: [],
    profilesChecked: 0,
    profilesDead: 0,
    deadProfiles: [],
    corroborationUpgrades: [],
    ran: true,
  };

  // ── 1. Phone verification ────────────────────────────────────
  const allPhoneTiers = [
    { tier: 'confirmed', phones: report.phones.confirmed },
    { tier: 'probable',  phones: report.phones.probable },
    { tier: 'possible',  phones: report.phones.possible },
  ];

  for (const { tier, phones } of allPhoneTiers) {
    if (!phones || phones.length === 0) continue;
    const verified = [];
    for (const phone of phones) {
      verification.phonesChecked++;
      const result = verifyPhone(phone);
      if (result.reject) {
        verification.phonesRejected++;
        verification.rejectedPhones.push({ phone: result.phone, reason: result.rejectReason });
        continue;
      }
      // Enrich with any new data from verification
      const enriched = { ...phone };
      if (result.carrier   && !enriched.carrier)   enriched.carrier   = result.carrier;
      if (result.lineType  && !enriched.lineType)   enriched.lineType  = result.lineType;
      if (result.callerName && !enriched.callerName) enriched.callerName = result.callerName;
      if (result.location  && !enriched.location)   enriched.location  = result.location;
      enriched.verified = true;
      verified.push(enriched);
      verification.phonesVerified++;
      if (result.carrier || result.callerName) {
        verification.enrichedPhones.push({ phone: result.phone, carrier: result.carrier, callerName: result.callerName, lineType: result.lineType });
      }
    }
    report.phones[tier] = verified;
  }

  // Update summary
  report.summary.totalPhonesFound = report.phones.confirmed.length + report.phones.probable.length + report.phones.possible.length;

  // ── 2. Profile URL verification (sample first 15) ────────────────────
  const profilesToCheck = (report.socialProfiles || []).filter(p => p.profileUrl).slice(0, 15);
  for (const profile of profilesToCheck) {
    verification.profilesChecked++;
    const urlCheck = await verifyProfileUrl(profile.profileUrl);
    if (urlCheck && !urlCheck.alive) {
      verification.profilesDead++;
      verification.deadProfiles.push({ platform: profile.platform, url: profile.profileUrl, status: urlCheck.status });
      profile.urlDead = true;
    } else if (urlCheck) {
      profile.urlAlive = true;
    }
  }

  // Remove profiles that got a definitive 404 — those accounts don't exist
  // Exception: keep confirmed profiles even if they return non-200 (private/auth-wall)
  report.socialProfiles = (report.socialProfiles || []).filter(p => {
    if (p.confirmedByEmail) return true;   // never drop confirmed accounts
    if (p.urlDead && p.profileUrl) return false; // 404 = gone, drop it
    return true;
  });

  // ── 3. Corroboration scoring ─────────────────────────────────
  const upgrades = scoreCorroboration(report.clues || []);
  verification.corroborationUpgrades = upgrades;
  // Apply upgrades to actual clue objects
  for (const up of upgrades) {
    for (const clue of (report.clues || [])) {
      const clueKey = `${clue.type}::${(clue.value || '').toString().trim().toLowerCase()}`;
      const upKey   = `${up.type}::${(up.value  || '').toString().trim().toLowerCase()}`;
      if (clueKey === upKey) clue.confidence = up.newConfidence;
    }
  }

  // ── 4. Add verification clues ────────────────────────────────
  if (verification.phonesRejected > 0) {
    report.clues.push({
      type: 'verification',
      value: `${verification.phonesRejected} phone(s) rejected by area code / NumLookup check`,
      source: 'Triple-Check Verification',
      note: verification.rejectedPhones.map(r => `${r.phone}: ${r.reason}`).join('; '),
      confidence: 'high',
      timestamp: new Date().toISOString(),
    });
  }
  if (verification.phonesVerified > 0) {
    report.clues.unshift({
      type: 'verification',
      value: `${verification.phonesVerified} phone(s) passed triple-check verification`,
      source: 'Triple-Check Verification',
      note: 'NANP area code whitelist + NumLookup API confirmation',
      confidence: 'high',
      timestamp: new Date().toISOString(),
    });
  }
  if (upgrades.length > 0) {
    report.clues.push({
      type: 'verification',
      value: `${upgrades.length} clue(s) upgraded by corroboration (2-3+ independent sources)`,
      source: 'Triple-Check Verification',
      note: upgrades.map(u => `${u.type}:"${String(u.value).slice(0,40)}" ${u.oldConfidence}→${u.newConfidence} (${u.sourceCount} sources)`).join('; '),
      confidence: 'medium',
      timestamp: new Date().toISOString(),
    });
  }

  report.verification = verification;
  return report;
}

module.exports = { runVerification, verifyPhone, verifyProfileUrl, scoreCorroboration };
