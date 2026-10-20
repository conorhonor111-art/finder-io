const axios = require('axios');
const { extractPhoneNumbers } = require('./google-dorker');

async function mxLookup(domain) {
  try {
    const resp = await axios.get(`https://dns.google/resolve?name=${domain}&type=MX`, {
      timeout: 5000,
      validateStatus: () => true,
    });
    if (resp.status === 200) {
      return resp.data.Answer?.map(a => a.data) || [];
    }
  } catch (e) {}
  return [];
}

async function checkEmailProvider(email) {
  const domain = email.split('@')[1];
  const result = {
    source: 'DNS Recon',
    domain,
    provider: 'unknown',
    mxRecords: [],
    isCustomDomain: false,
    companyInfo: null,
  };

  const freeProviders = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
    'zoho.com', 'yandex.com', 'gmx.com', 'live.com',
  ];

  if (freeProviders.includes(domain.toLowerCase())) {
    result.provider = domain;
    result.isCustomDomain = false;
  } else {
    result.isCustomDomain = true;
    result.provider = domain;

    // Look up company website for phone numbers
    try {
      const siteResp = await axios.get(`https://${domain}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        timeout: 8000,
        validateStatus: () => true,
        maxRedirects: 5,
      });

      if (siteResp.status === 200) {
        const phones = extractPhoneNumbers(siteResp.data);
        if (phones.length > 0) {
          result.companyPhones = phones;
          result.confidence = 'low';
          result.note = 'Phone numbers from company website (may be main line, not personal)';
        }

        // Check contact/about pages
        for (const path of ['/contact', '/about', '/contact-us', '/about-us']) {
          try {
            const pageResp = await axios.get(`https://${domain}${path}`, {
              headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
              timeout: 6000,
              validateStatus: () => true,
            });
            if (pageResp.status === 200) {
              const pagePhones = extractPhoneNumbers(pageResp.data);
              if (pagePhones.length > 0) {
                result.contactPagePhones = pagePhones;
              }
            }
          } catch (e) {}
        }
      }
    } catch (e) {}
  }

  result.mxRecords = await mxLookup(domain);

  return result;
}

async function dnsRecon(email) {
  return [await checkEmailProvider(email)];
}

module.exports = { dnsRecon };
