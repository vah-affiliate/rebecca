const Stripe = require('stripe');
const { setSecurityHeaders, checkEnvVars } = require('./_lib/security');

export const config = { api: { bodyParser: false } };

const processedEvents = new Set();
setInterval(() => { if (processedEvents.size > 10000) processedEvents.clear(); }, 60 * 60 * 1000);

const INST_AMOUNT     = 29900;
const COMMISSION_RATE = 0.15;
const COMMISSION      = Math.floor(INST_AMOUNT * COMMISSION_RATE);

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data',  c => chunks.push(c));
    req.on('end',   () => resolve(Buffer.concat(chunks)));
    req.on('error', e  => reject(e));
  });
}

module.exports = async (req, res) => {
  setSecurityHeaders(res);

  if (req.method !== 'POST') return res.status(405).end();

  try { checkEnvVars(['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_REBECCA_ACCOUNT']); }
  catch { return res.status(500).end(); }

  const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

  let event;
  try {
    const rawBody = await getRawBody(req);
    const sig     = req.headers['stripe-signature'];
    if (!sig) return res.status(400).end();
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).end();
  }

  if (event.type !== 'invoice.payment_succeeded') return res.status(200).json({ received: true });

  const invoice = event.data.object;
  if (!invoice.subscription || !invoice.charge) return res.status(200).json({ received: true });
  if (processedEvents.has(event.id)) return res.status(200).json({ received: true });

  try {
    const subscription = await stripe.subscriptions.retrieve(invoice.subscription);

    if (subscription.metadata.affiliate !== 'rebecca_knoerr' || subscription.metadata.plan !== 'installment') {
      return res.status(200).json({ received: true });
    }

    processedEvents.add(event.id);

    await stripe.transfers.create({
      amount:             COMMISSION,
      currency:           'eur',
      destination:        process.env.STRIPE_REBECCA_ACCOUNT,
      source_transaction: invoice.charge,
      metadata:           { event_id: event.id, invoice_id: invoice.id },
    });

  } catch (err) {
    console.error('[wh]', err.message);
    if (!processedEvents.has(event.id)) return res.status(500).end();
  }

  return res.status(200).json({ received: true });
};
