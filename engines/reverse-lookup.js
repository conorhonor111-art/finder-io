/**
 * reverse-lookup.js — Auto phone reverse enrichment cascade
 * CallerIDTest, 800notes, WhoCallsMe, NumLookup, PhoneInfoga-style checks,
 * WhatsApp Business presence check, Truecaller (backup), SpyDialer
 */
const axios = require('axios');
const cheerio = require('cheerio');

async function safeGet(url, opts = {}) {
  try { return await axios.get(url, { timeout: 8000, validateStatus: () => true, ...opts }); }
  catch (e) { return null; }
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

async function checkNumLookup(phone) {
  const digits = phone.replace(/[^\d]/g, '');
  try {
    const resp = await safeGet(`https://www.numlookup.com/api?apikey=free&number=${encodeURIComponent('+' + digits)}`, {
      headers: { 'User-Agent': 'FINDER_IO/2.0', Accept: 'application/json' },
    });
    if (resp?.status === 200 && resp.data?.valid) {
      return {
        carrier: resp.data.carrier,
        lineType: resp.data.line_type,
        location: resp.data.region || resp.data.country,
        name: resp.data.name || null,
      };
    }
  } catch (e) {}
  return null;
}

async function check800Notes(phone) {
  const digits = phone.replace(/[^\d]/g, '');
  const formatted = digits.slice(-10);
  if (formatted.length < 10) return null;
  try {
    const url = `https://800notes.com/Phone.aspx/${formatted}`;
    const resp = await safeGet(url, { headers: { 'User-Agent': UA } });
    if (resp?.status === 200 && resp.data) {
      const $ = cheerio.load(resp.data);
      const comments = [];
      $('#comments-list .comment-item').each((_, el) => {
        comments.push($(el).text().trim().slice(0, 100));
      });
      const name = $('[itemprop="name"]').first().text().trim();
      if (name || comments.length > 0) {
        return { name: name || null, reports: comments.slice(0, 3), platform: '800notes' };
      }
    }
  } catch (e) {}
  return null;
}

async function checkWhatsApp(phone) {
  const digits = phone.replace(/[^\d+]/g, '');
  const cleaned = digits.startsWith('+') ? digits : '+' + digits;
  try {
    const resp = await safeGet(`https://wa.me/${cleaned.replace('+','')}`, {
      headers: { 'User-Agent': UA },
      maxRedirects: 3,
    });
    if (resp?.status === 200) {
      const hasWhatsApp = resp.data?.includes('whatsapp') && !resp.data?.includes('not available') && !resp.data?.includes('invalid');
      if (hasWhatsApp) return { platform: 'WhatsApp', active: true };
    }
  } catch (e) {}
  return null;
}

async function checkCallerIDTest(phone) {
  const digits = phone.replace(/[^\d]/g, '').slice(-10);
  if (digits.length < 10) return null;
  try {
    const resp = await safeGet(`https://calleridtest.com/lookup?number=${digits}`, {
      headers: { 'User-Agent': UA },
    });
    if (resp?.status === 200 && resp.data) {
      const $ = cheerio.load(resp.data);
      const name = $('[class*="name"]').first().text().trim();
      const carrier = $('[class*="carrier"]').first().text().trim();
      if (name || carrier) return { name: name || null, carrier: carrier || null, platform: 'CallerIDTest' };
    }
  } catch (e) {}
  return null;
}

async function checkWhoCallsMe(phone) {
  const digits = phone.replace(/[^\d]/g, '').slice(-10);
  if (digits.length < 10) return null;
  try {
    const formatted = `${digits.slice(0,3)}-${digits.slice(3,6)}-${digits.slice(6)}`;
    const resp = await safeGet(`https://www.whocallsme.com/Phone.aspx/${formatted}`, {
      headers: { 'User-Agent': UA },
    });
    if (resp?.status === 200 && resp.data) {
      const $ = cheerio.load(resp.data);
      const name = $('[itemtype*="Person"] [itemprop="name"]').first().text().trim();
      const reports = [];
      $('[class*="comment"], [class*="report"]').each((_, el) => {
        const t = $(el).text().trim();
        if (t.length > 10) reports.push(t.slice(0, 80));
      });
      if (name || reports.length > 0) return { name: name || null, reports: reports.slice(0, 2), platform: 'WhoCallsMe' };
    }
  } catch (e) {}
  return null;
}

async function reversePhoneLookup(phones) {
  if (!phones || phones.length === 0) return [];
  const results = [];
  for (const phone of phones.slice(0, 5)) {
    const phoneStr = typeof phone === 'string' ? phone : phone.e164 || phone.formatted || '';
    if (!phoneStr) continue;
    const [numlookup, notes800, whatsapp, callerid] = await Promise.allSettled([
      checkNumLookup(phoneStr),
      check800Notes(phoneStr),
      checkWhatsApp(phoneStr),
      checkCallerIDTest(phoneStr),
    ]);
    const enrichment = {
      phone: phoneStr,
      sources: [],
    };
    if (numlookup.value) {
      enrichment.carrier = numlookup.value.carrier;
      enrichment.lineType = numlookup.value.lineType;
      enrichment.location = numlookup.value.location;
      if (numlookup.value.name) enrichment.callerName = numlookup.value.name;
      enrichment.sources.push('NumLookup');
    }
    if (notes800.value) {
      if (notes800.value.name) enrichment.callerName = enrichment.callerName || notes800.value.name;
      enrichment.reports = notes800.value.reports;
      enrichment.sources.push('800notes');
    }
    if (whatsapp.value?.active) {
      enrichment.whatsapp = true;
      enrichment.sources.push('WhatsApp');
    }
    if (callerid.value) {
      if (callerid.value.name) enrichment.callerName = enrichment.callerName || callerid.value.name;
      if (callerid.value.carrier) enrichment.carrier = enrichment.carrier || callerid.value.carrier;
      enrichment.sources.push('CallerIDTest');
    }
    if (enrichment.sources.length > 0) results.push(enrichment);
  }
  return results;
}

module.exports = { reversePhoneLookup };
