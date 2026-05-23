const { rateLimit }                                          = require('./_lib/rateLimit');
const { setSecurityHeaders, setCORS, checkEnvVars,
        getClientIP, checkBodySize, checkContentType }       = require('./_lib/security');

const PAYPAL_API = 'https://api-m.paypal.com';

// PayPal order IDs: uppercase alphanumeric, 8-20 chars
const ORDERID_REGEX = /^[A-Z0-9]{8,20}$/;

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  setCORS(res);

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).end();

  const ip      = getClientIP(req);
  const limited = limiter(ip);
  if (!limited.ok) {
    res.setHeader('Retry-After', String(limited.retryAfter));
    return res.status(429).json({ error: 'Too many requests.' });
  }

  if (!checkBodySize(req, 256))   return res.status(413).json({ error: 'Request too large' });
  if (!checkContentType(req))     return res.status(415).json({ error: 'Invalid content type' });

  try { checkEnvVars(['PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET']); }
  catch { return res.status(500).json({ error: 'Server error' }); }

  // ── VALIDATE orderID — strict format check ───────────────
  const orderID = req.body && req.body.orderID;
  if (!orderID || typeof orderID !== 'string' || !ORDERID_REGEX.test(orderID)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    const authRes = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(
          process.env.PAYPAL_CLIENT_ID + ':' + process.env.PAYPAL_CLIENT_SECRET
        ).toString('base64'),
      },
      body: 'grant_type=client_credentials',
    });

    if (!authRes.ok) throw new Error('PayPal auth failed');
    const { access_token } = await authRes.json();

    const captureRes = await fetch(
      `${PAYPAL_API}/v2/checkout/orders/${orderID}/capture`,
      {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${access_token}`,
        },
      }
    );

    const capture = await captureRes.json();

    // Only tell client success/failure — never expose capture details
    if (capture.status === 'COMPLETED') {
      return res.status(200).json({ status: 'COMPLETED' });
    } else {
      throw new Error(`Capture status: ${capture.status}`);
    }

  } catch (err) {
    console.error('[capture-paypal-order]', err.message);
    return res.status(500).json({ error: 'Payment capture failed. Please contact support.' });
  }
};
