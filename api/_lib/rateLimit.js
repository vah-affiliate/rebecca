const store = new Map();

function rateLimit({ windowMs, max }) {
  return function check(ip) {
    const now = Date.now();
    const key = normaliseIP(ip);
    if (!store.has(key)) { store.set(key, { count: 1, resetAt: now + windowMs }); return { ok: true }; }
    const entry = store.get(key);
    if (now > entry.resetAt) { store.set(key, { count: 1, resetAt: now + windowMs }); return { ok: true }; }
    if (entry.count >= max) return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    entry.count++;
    return { ok: true };
  };
}

function normaliseIP(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip.toLowerCase().trim();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store.entries()) { if (now > entry.resetAt) store.delete(key); }
}, 5 * 60 * 1000);

module.exports = { rateLimit };
