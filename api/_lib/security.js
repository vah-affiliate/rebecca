function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',    'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('X-XSS-Protection',          '1; mode=block');
  res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control',             'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma',                    'no-cache');
  res.setHeader('Expires',                   '0');
}

const ALLOWED_ORIGINS = [
  'https://rebecca-lake.vercel.app',
  'https://rebecca.art-baetes.com',
];

function setCORS(res, req) {
  const origin = req && req.headers && req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods',     'POST');
  res.setHeader('Access-Control-Allow-Headers',     'Content-Type');
  res.setHeader('Access-Control-Max-Age',           '86400');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
}

function checkEnvVars(vars) {
  for (const v of vars) {
    if (!process.env[v] || process.env[v].trim() === '') throw new Error(`Missing: ${v}`);
  }
}

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) { const first = forwarded.split(',')[0].trim(); if (first) return first; }
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

function checkBodySize(req, maxBytes = 1024) {
  const cl = req.headers['content-length'];
  if (!cl) return true;
  const size = parseInt(cl, 10);
  return !isNaN(size) && size <= maxBytes;
}

function checkContentType(req) {
  return (req.headers['content-type'] || '').toLowerCase().includes('application/json');
}

module.exports = { setSecurityHeaders, setCORS, checkEnvVars, getClientIP, checkBodySize, checkContentType };
