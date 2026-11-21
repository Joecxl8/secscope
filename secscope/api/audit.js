const tls = require('tls');
const dns = require('dns').promises;

const DOMAIN_REGEX = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

function isPrivateIP(ip) {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip === '::1' ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80')
  );
}

function checkTLS(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: 5000 },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        socket.end();

        if (!cert || !cert.valid_to) {
          return resolve({ ok: false, error: 'No certificate returned' });
        }

        const expiryDate = new Date(cert.valid_to);
        const daysRemaining = Math.floor((expiryDate - Date.now()) / (1000 * 60 * 60 * 24));

        resolve({
          ok: authorized && daysRemaining > 0,
          authorized,
          protocol,
          issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          validTo: cert.valid_to,
          daysRemaining,
        });
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, error: 'TLS handshake timed out' });
    });

    socket.on('error', (err) => {
      resolve({ ok: false, error: err.message });
    });
  });
}

async function checkHttpRedirect(domain) {
  try {
    const res = await fetch(`http://${domain}`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(4000),
      headers: { 'User-Agent': 'SecScope-Auditor/1.0' },
    });
    const location = res.headers.get('location') || '';
    const isRedirect = res.status >= 300 && res.status < 400 && location.toLowerCase().startsWith('https://');
    return { ok: isRedirect, status: res.status, location };
  } catch {
    return { ok: false, status: null, location: null };
  }
}

function parseCookies(rawCookies) {
  return rawCookies.map((str) => {
    const parts = str.split(';').map((p) => p.trim());
    const name = parts[0]?.split('=')[0] || 'unknown';
    const lower = parts.map((p) => p.toLowerCase());
    const sameSitePart = lower.find((p) => p.startsWith('samesite='));

    return {
      name,
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: sameSitePart ? sameSitePart.split('=')[1] : 'None/Unset',
    };
  });
}

async function checkHeaders(domain) {
  try {
    const res = await fetch(`https://${domain}`, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'SecScope-Auditor/1.0' },
    });

    const get = (name) => res.headers.get(name);
    const rawCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];

    return {
      ok: true,
      statusCode: res.status,
      finalUrl: res.url,
      headers: {
        hsts: get('strict-transport-security'),
        csp: get('content-security-policy'),
        xfo: get('x-frame-options'),
        xcto: get('x-content-type-options'),
        referrer: get('referrer-policy'),
        permissions: get('permissions-policy'),
      },
      leaks: {
        server: get('server'),
        poweredBy: get('x-powered-by'),
      },
      cookies: parseCookies(rawCookies),
    };
  } catch (err) {
    return { ok: false, error: err.message, cookies: [] };
  }
}

async function checkDNS(domain) {
  const safeResolve = async (fn) => {
    try {
      return await fn();
    } catch {
      return [];
    }
  };

  const [ips, txtRecords, dmarcRecords, caaRecords] = await Promise.all([
    safeResolve(() => dns.resolve4(domain)),
    safeResolve(() => dns.resolveTxt(domain)),
    safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`)),
    safeResolve(() => dns.resolveCaa(domain)),
  ]);

  const flatTxt = txtRecords.map((r) => r.join(''));
  const flatDmarc = dmarcRecords.map((r) => r.join(''));

  return {
    ips,
    spf: flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null,
    dmarc: flatDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null,
    caa: caaRecords.map((c) => c.issue || c.issuewild).filter(Boolean),
  };
}

function calculateScore(ssl, http, dnsData) {
  let score = 0;
  if (ssl.ok) score += 20;
  if (ssl.httpRedirect?.ok) score += 5;
  if (http.ok) {
    if (http.headers.hsts) score += 15;
    if (http.headers.csp) score += 20;
    if (http.headers.xfo) score += 10;
    if (http.headers.xcto?.toLowerCase().includes('nosniff')) score += 10;
    if (http.headers.referrer) score += 5;
    if (http.headers.permissions) score += 5;
  }
  if (dnsData.spf) score += 5;
  if (dnsData.dmarc) score += 5;

  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 45) grade = 'D';

  return { score, grade };
}

module.exports = async (req, res) => {
  const raw = (req.query.domain || '').trim().toLowerCase();
  const domain = raw
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split(':')[0];

  if (!domain || !DOMAIN_REGEX.test(domain)) {
    return res.status(400).json({ error: 'Enter a valid domain name (e.g. github.com)' });
  }

  try {
    const dnsData = await checkDNS(domain);
    if (dnsData.ips.length === 0) {
      return res.status(404).json({ error: `Could not resolve DNS for ${domain}` });
    }
    if (dnsData.ips.some(isPrivateIP)) {
      return res.status(403).json({ error: 'Private or local IP addresses are blocked.' });
    }

    const [ssl, httpRedirect, http] = await Promise.all([
      checkTLS(domain),
      checkHttpRedirect(domain),
      checkHeaders(domain),
    ]);

    ssl.httpRedirect = httpRedirect;
    const { score, grade } = calculateScore(ssl, http, dnsData);

    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');
    return res.status(200).json({ domain, timestamp: new Date().toISOString(), score, grade, ssl, http, dns: dnsData });
  } catch (err) {
    return res.status(500).json({ error: 'Audit failed: ' + err.message });
  }
};
