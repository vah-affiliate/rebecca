const crypto = require('crypto');
const { rateLimit }                                          = require('./_lib/rateLimit');
const { setSecurityHeaders, setCORS, checkEnvVars,
        getClientIP, checkBodySize, checkContentType }       = require('./_lib/security');

const PLANS = {
  full:        { amount: '549.00', label: 'View at Home — Full Year'       },
  installment: { amount: '299.00', label: 'View at Home — Installment 1/2' },
};
const CURRENCY   = 'EUR';
const RETURN_URL = 'https://rebecca.art-baetes.com/book';
const CANCEL_URL = 'https://rebecca-lake.vercel.app/';
const PAYPAL_API = 'https://api-m.paypal.com';

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

  if (!checkBodySize(req, 512))   return res.status(413).json({ error: 'Request too large' });
  if (!checkContentType(req))     return res.status(415).json({ error: 'Invalid content type' });

  try { checkEnvVars(['PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET']); }
  catch { return res.status(500).json({ error: 'Server error' }); }

  const plan = req.body && req.body.plan;
  if (!plan || !Object.prototype.hasOwnProperty.call(PLANS, plan)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const selected = PLANS[plan];

  // ── IDEMPOTENCY KEY for PayPal ───────────────────────────
  // PayPal-Request-Id prevents duplicate orders from double-clicks
  const timeWindow     = Math.floor(Date.now() / (10 * 60 * 1000));
  const idempotencyKey = crypto
    .createHash('sha256')
    .update(`paypal:${ip}:${plan}:${timeWindow}`)
    .digest('hex');

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

    const orderRes = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Content-Type':     'application/json',
        'Authorization':    `Bearer ${access_token}`,
        'PayPal-Request-Id': idempotencyKey, // ← PayPal deduplicates on this
      },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: CURRENCY,
            value:         selected.amount,
          },
          description: selected.label,
          custom_id:   `rebecca_knoerr_${plan}`,
        }],
        application_context: {
          brand_name:   'View at Home',
          landing_page: 'NO_PREFERENCE',
          user_action:  'PAY_NOW',
          return_url:   RETURN_URL,
          cancel_url:   CANCEL_URL,
        },
      }),
    });

    const order = await orderRes.json();
    if (!order.id) throw new Error('No order ID returned');

    return res.status(200).json({ orderID: order.id });

  } catch (err) {
    console.error('[create-paypal-order]', err.message);
    return res.status(500).json({ error: 'Could not create order. Please try again.' });
  }
};
