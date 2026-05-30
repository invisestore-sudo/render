// Força TODAS as conexões TCP a usar IPv4 (corrige ENETUNREACH no Render free tier)
const dns = require('dns');
const origLookup = dns.lookup;
dns.lookup = function(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = { family: 4 };
  } else if (typeof options === 'number') {
    options = { family: 4 };
  } else {
    options = Object.assign({}, options, { family: 4 });
  }
  return origLookup.call(this, hostname, options, callback);
};

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'invise123';

// Token de acesso do Mercado Pago (Access Token de produção).
// Necessário para consultar os pagamentos recebidos via webhook e confirmar
// que foram aprovados. Configure em Render → Environment → MP_ACCESS_TOKEN.
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || '';
// Segredo opcional para validar a assinatura dos webhooks do Mercado Pago.
// Se não configurado, a validação de assinatura fica desativada.
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || '';
// URL publica deste backend (usada nas telas de retorno do checkout).
const PUBLIC_URL = (process.env.PUBLIC_URL || 'https://invisestore-backend.onrender.com').replace(/\/$/, '');
// URL da loja (opcional) para o botao "Voltar a loja" nas telas de retorno.
const STORE_URL = process.env.STORE_URL || '';

if (!process.env.DATABASE_URL) {
  console.error('ERRO: variável DATABASE_URL não definida.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGINT PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      date TIMESTAMPTZ NOT NULL DEFAULT now(),
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT,
      products JSONB NOT NULL DEFAULT '[]',
      total NUMERIC(10, 2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'Pendente',
      payment_method TEXT NOT NULL DEFAULT 'PIX',
      ip TEXT
    );
    CREATE TABLE IF NOT EXISTS meetings (
      id BIGINT PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      date TIMESTAMPTZ NOT NULL DEFAULT now(),
      product TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      budget TEXT NOT NULL DEFAULT '',
      start_when TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Aguardando contato',
      ip TEXT
    );
    CREATE TABLE IF NOT EXISTS license_keys (
      key TEXT PRIMARY KEY,
      app TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      order_id BIGINT,
      plan TEXT NOT NULL DEFAULT 'lifetime',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ,
      last_seen_at TIMESTAMPTZ,
      device_count INT NOT NULL DEFAULT 0,
      devices JSONB NOT NULL DEFAULT '[]',
      notes TEXT NOT NULL DEFAULT ''
    );
  `);
  // Colunas para o fluxo de confirmação de pagamento via webhook do Mercado Pago.
  // paid_at: quando o pagamento foi aprovado | mp_payment_id: id do pagamento no MP
  // acknowledged: se o admin já viu a notificação desse pagamento no painel.
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS mp_payment_id TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS acknowledged BOOLEAN NOT NULL DEFAULT TRUE;
  `);
  console.log('✅ Tabelas verificadas/criadas.');
}

const VALID_APPS = ['habitos', 'finapp', 'treino', 'all'];

function generateKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chunk = () => Array.from({ length: 4 }, () =>
    alphabet[crypto.randomInt(0, alphabet.length)]).join('');
  return `INVS-${chunk()}-${chunk()}-${chunk()}`;
}

function makeKeyData({ app = 'all', email = '', orderId = null, plan = 'lifetime', expiresAt = null, notes = '' }) {
  if (!VALID_APPS.includes(app)) throw new Error('app inválido');
  return {
    key: generateKey(),
    app,
    email: String(email || '').trim().toLowerCase(),
    orderId: orderId || null,
    plan,
    status: 'active',
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt || null,
    notes: String(notes || '')
  };
}

function rowToOrder(r) {
  return {
    id: Number(r.id),
    receivedAt: r.received_at,
    date: r.date,
    name: r.name,
    email: r.email,
    phone: r.phone,
    products: r.products || [],
    total: Number(r.total),
    status: r.status,
    paymentMethod: r.payment_method,
    paidAt: r.paid_at,
    mpPaymentId: r.mp_payment_id,
    acknowledged: r.acknowledged,
    ip: r.ip
  };
}

function rowToMeeting(r) {
  return {
    id: Number(r.id),
    receivedAt: r.received_at,
    date: r.date,
    product: r.product,
    name: r.name,
    email: r.email,
    phone: r.phone,
    tier: r.budget,
    startWhen: r.start_when,
    status: r.status,
    ip: r.ip
  };
}

function rowToKey(r) {
  return {
    key: r.key,
    app: r.app,
    email: r.email,
    orderId: r.order_id,
    plan: r.plan,
    status: r.status,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    lastSeenAt: r.last_seen_at,
    deviceCount: r.device_count,
    devices: r.devices || [],
    notes: r.notes
  };
}

const app = express();
app.use(cors({ origin: true, credentials: false }));
app.options('*', cors());
app.use(express.json({ limit: '1mb' }));

// Endpoint de health-check para keep-alive externo (cron-job.org / UptimeRobot).
// Não toca no banco — só responde 200 para manter a instância do Render acordada.
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// =====================================================
// Public API
// =====================================================

app.post('/api/orders', async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.name || !b.email) {
      return res.status(400).json({ error: 'name e email são obrigatórios' });
    }
    const id = b.id || Date.now();
    const now = new Date().toISOString();
    await pool.query(
      `INSERT INTO orders (id, received_at, date, name, email, phone, products, total, status, payment_method, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (id) DO NOTHING`,
      [
        id, now, b.date || now,
        String(b.name).trim(), String(b.email).trim(), String(b.phone || '').trim(),
        JSON.stringify(Array.isArray(b.products) ? b.products : []),
        Number(b.total) || 0,
        b.status || 'Pendente',
        b.paymentMethod || 'PIX',
        req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
      ]
    );
    console.log(`[NOVO PEDIDO] #${id} - ${b.name} (${b.email}) - R$ ${b.total}`);
    res.json({ ok: true, id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar pedido' });
  }
});

// =====================================================
// Checkout: cria o pedido (Pendente) e gera a preferencia do Mercado Pago
// JA AMARRADA a este pedido (external_reference). Assim o pagamento conecta
// sozinho ao pedido certo, mantendo os dados do cliente, e o cliente volta
// para as telas de retorno (/compra/sucesso, /compra/falha).
// =====================================================
app.post('/api/checkout', async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.name || !b.email) {
      return res.status(400).json({ error: 'name e email são obrigatórios' });
    }
    const items = (Array.isArray(b.items) ? b.items : [])
      .map(it => ({
        title: String(it.title || 'Produto').slice(0, 250),
        quantity: Math.max(1, parseInt(it.quantity, 10) || 1),
        currency_id: 'BRL',
        unit_price: Math.round((Number(it.price) || 0) * 100) / 100
      }))
      .filter(it => it.unit_price > 0);
    if (items.length === 0) {
      return res.status(400).json({ error: 'nenhum item com preço válido' });
    }

    const id = b.id || Date.now();
    const now = new Date().toISOString();
    const products = items.map(it => it.title);
    const total = items.reduce((s, it) => s + it.unit_price * it.quantity, 0);

    await pool.query(
      `INSERT INTO orders (id, received_at, date, name, email, phone, products, total, status, payment_method, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Pendente', $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [
        id, now, now,
        String(b.name).trim(), String(b.email).trim(), String(b.phone || '').trim(),
        JSON.stringify(products), total,
        b.paymentMethod || 'Mercado Pago',
        req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
      ]
    );
    console.log(`[NOVO PEDIDO] #${id} - ${b.name} (${b.email}) - R$ ${total}`);

    if (!MP_ACCESS_TOKEN) {
      return res.status(503).json({ error: 'MP_ACCESS_TOKEN não configurado', id });
    }

    const prefBody = {
      items,
      payer: { name: String(b.name).trim(), email: String(b.email).trim() },
      external_reference: String(id),
      notification_url: `${PUBLIC_URL}/api/mp/webhook`,
      back_urls: {
        success: `${PUBLIC_URL}/compra/sucesso`,
        pending: `${PUBLIC_URL}/compra/pendente`,
        failure: `${PUBLIC_URL}/compra/falha`
      },
      auto_return: 'approved',
      metadata: { order_id: id }
    };
    const r = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(prefBody)
    });
    if (!r.ok) {
      console.error(`[CHECKOUT] falha ao criar preferência: ${r.status} ${await r.text().catch(() => '')}`);
      return res.status(502).json({ error: 'falha ao criar checkout', id });
    }
    const pref = await r.json();
    console.log(`[CHECKOUT] pedido #${id} → preferência ${pref.id}`);
    res.json({ ok: true, id, init_point: pref.init_point, sandbox_init_point: pref.sandbox_init_point });
  } catch (err) {
    console.error('[CHECKOUT] erro:', err);
    res.status(500).json({ error: 'erro ao criar checkout' });
  }
});

// =====================================================
// Mercado Pago — Webhook de confirmação de pagamento
//
// O Mercado Pago chama esta URL automaticamente sempre que um pagamento
// muda de status. Quando o pagamento é aprovado, marcamos o pedido
// correspondente como "Pago" e geramos uma notificação no painel.
//
// Configuração necessária (uma vez):
//   1. Mercado Pago → Suas integrações → Webhooks/Notificações:
//      URL: https://invisestore-backend.onrender.com/api/mp/webhook
//      Evento: "Pagamentos" (payment)
//   2. Render → Environment: defina MP_ACCESS_TOKEN (Access Token de produção).
//      Opcional: MP_WEBHOOK_SECRET (assinatura secreta do webhook).
// =====================================================

// Valida a assinatura do webhook (x-signature) quando MP_WEBHOOK_SECRET existe.
function verifyMpSignature(req) {
  if (!MP_WEBHOOK_SECRET) return true; // validação desativada
  const sig = req.headers['x-signature'] || '';
  const reqId = req.headers['x-request-id'] || '';
  const parts = {};
  sig.split(',').forEach(p => {
    const [k, v] = p.split('=');
    if (k && v) parts[k.trim()] = v.trim();
  });
  if (!parts.ts || !parts.v1) return false;
  const dataId = String(
    req.query['data.id'] || (req.body && req.body.data && req.body.data.id) || ''
  ).toLowerCase();
  const manifest = `id:${dataId};request-id:${reqId};ts:${parts.ts};`;
  const hmac = crypto.createHmac('sha256', MP_WEBHOOK_SECRET).update(manifest).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(parts.v1));
  } catch {
    return false;
  }
}

// Extrai o tipo de notificação e o id do pagamento dos vários formatos do MP.
function extractPaymentNotification(req) {
  const q = req.query || {};
  const b = req.body || {};
  const type = b.type || q.type || q.topic || b.topic || '';
  const id =
    (b.data && b.data.id) ||
    q['data.id'] ||
    q.id ||
    (b.resource && String(b.resource).split('/').pop()) ||
    null;
  return { type: String(type), id: id ? String(id) : null };
}

// Consulta os detalhes do pagamento na API do Mercado Pago.
async function fetchMpPayment(paymentId) {
  if (!MP_ACCESS_TOKEN) return null;
  const r = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
    headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` }
  });
  if (!r.ok) {
    console.error(`[MP] Falha ao consultar pagamento ${paymentId}: ${r.status} ${await r.text().catch(() => '')}`);
    return null;
  }
  return r.json();
}

// Marca o pedido como pago a partir de um pagamento aprovado do MP.
// Tenta casar com um pedido existente por external_reference (id) ou e-mail;
// se não achar, cria um novo registro de pedido já "Pago".
async function markOrderPaidFromMp(payment) {
  const paymentId = String(payment.id);

  // Idempotência: se esse pagamento já foi processado, não faz nada.
  const dup = await pool.query('SELECT id FROM orders WHERE mp_payment_id = $1 LIMIT 1', [paymentId]);
  if (dup.rows[0]) return { matched: dup.rows[0].id, already: true };

  let email = String((payment.payer && payment.payer.email) || '').trim().toLowerCase();
  // O MP as vezes mascara o e-mail (ex: "XXXXXXXX"). Nesse caso, ignora.
  if (!email.includes('@') || /x{4,}/i.test(email)) email = '';
  const amount = Number(payment.transaction_amount) || 0;
  const extRef = payment.external_reference;
  const now = new Date().toISOString();

  let order = null;
  // 1) Casa pelo external_reference (id do pedido), se o checkout enviou um.
  if (extRef && /^\d+$/.test(String(extRef))) {
    const r = await pool.query('SELECT * FROM orders WHERE id = $1', [Number(extRef)]);
    order = r.rows[0] || null;
  }
  // 2) Casa pelo e-mail do comprador (pedido ainda sem pagamento; prioriza
  //    o de mesmo valor).
  if (!order && email) {
    const r = await pool.query(
      `SELECT * FROM orders WHERE lower(email) = $1 AND mp_payment_id IS NULL
       ORDER BY (ABS(total - $2) < 0.01) DESC, received_at DESC LIMIT 1`,
      [email, amount]
    );
    order = r.rows[0] || null;
  }
  // 2b) Sem e-mail batendo: casa por valor + recencia (pedido pendente recente,
  //     mesmo valor, ainda sem pagamento). Cobre o caso de o cliente usar um
  //     e-mail diferente no Mercado Pago.
  if (!order && amount > 0) {
    const r = await pool.query(
      `SELECT * FROM orders
       WHERE mp_payment_id IS NULL AND status <> 'Pago'
         AND ABS(total - $1) < 0.01
         AND received_at > now() - interval '3 days'
       ORDER BY received_at DESC LIMIT 1`,
      [amount]
    );
    order = r.rows[0] || null;
  }

  if (order) {
    // Preserva o e-mail que o cliente digitou no site; so preenche pelo
    // pagamento se o pedido estiver sem e-mail valido.
    const orderEmail = String(order.email || '').trim();
    const finalEmail = (!orderEmail || !orderEmail.includes('@')) && email ? email : orderEmail;
    await pool.query(
      `UPDATE orders SET status = 'Pago', paid_at = $1, mp_payment_id = $2, email = $3, acknowledged = FALSE
       WHERE id = $4`,
      [now, paymentId, finalEmail, order.id]
    );
    return { matched: order.id, created: false };
  }

  // 3) Sem pedido correspondente: cria um registro novo já pago, para o admin ver.
  const id = Date.now();
  const name =
    (payment.payer && (payment.payer.first_name || payment.payer.name)) ||
    'Cliente Mercado Pago';
  await pool.query(
    `INSERT INTO orders (id, received_at, date, name, email, phone, products, total, status, payment_method, ip, paid_at, mp_payment_id, acknowledged)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Pago', $9, $10, $11, $12, FALSE)`,
    [
      id, now, now, name, email, '',
      JSON.stringify(payment.description ? [payment.description] : []),
      amount,
      payment.payment_type_id || 'mercadopago',
      '', now, paymentId
    ]
  );
  return { matched: id, created: true };
}

// =====================================================
// Reconciliacao automatica com a API do Mercado Pago
//
// Como os links de pagamento sao fixos, o MP nao dispara o webhook para eles.
// Entao, periodicamente (e quando o painel e aberto), consultamos os pagamentos
// aprovados da conta e marcamos os pedidos correspondentes como "Pago".
// =====================================================
let _reconcileRunning = false;
let _lastReconcile = 0;

async function reconcilePayments() {
  if (!MP_ACCESS_TOKEN || _reconcileRunning) return;
  _reconcileRunning = true;
  try {
    const url = 'https://api.mercadopago.com/v1/payments/search'
      + '?sort=date_created&criteria=desc'
      + '&range=date_created&begin_date=NOW-30DAYS&end_date=NOW'
      + '&status=approved&limit=50';
    const r = await fetch(url, { headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` } });
    if (!r.ok) {
      console.error(`[RECONCILE] busca de pagamentos falhou: ${r.status} ${await r.text().catch(() => '')}`);
      return;
    }
    const data = await r.json();
    const results = Array.isArray(data.results) ? data.results : [];
    const approved = results.filter(p => p.status === 'approved');
    if (approved.length === 0) return;

    // Pula pagamentos ja processados (idempotencia em lote).
    const ids = approved.map(p => String(p.id));
    const done = await pool.query(
      'SELECT mp_payment_id FROM orders WHERE mp_payment_id = ANY($1)', [ids]
    );
    const doneSet = new Set(done.rows.map(x => String(x.mp_payment_id)));

    let novos = 0;
    for (const p of approved) {
      if (doneSet.has(String(p.id))) continue;
      // Busca o detalhe completo para obter o e-mail real do comprador
      // (a busca em lote do MP costuma mascarar o e-mail).
      const full = await fetchMpPayment(p.id) || p;
      const res = await markOrderPaidFromMp(full);
      if (res && !res.already) novos++;
    }
    if (novos > 0) console.log(`💰 [RECONCILE] ${novos} pagamento(s) aprovado(s) vinculado(s) a pedidos.`);
  } catch (err) {
    console.error('[RECONCILE] erro:', err);
  } finally {
    _reconcileRunning = false;
    _lastReconcile = Date.now();
  }
}

// GET é usado pelo MP apenas para validar a URL.
app.get('/api/mp/webhook', (req, res) => res.sendStatus(200));

app.post('/api/mp/webhook', async (req, res) => {
  // Responde 200 imediatamente para o MP não reenviar a notificação.
  if (!verifyMpSignature(req)) {
    console.warn('[MP WEBHOOK] assinatura inválida — ignorado');
    return res.sendStatus(401);
  }
  res.sendStatus(200);

  try {
    const { type, id } = extractPaymentNotification(req);
    if (!id) return;
    // Só nos interessam notificações de pagamento.
    if (type && !/payment/i.test(type)) return;

    if (!MP_ACCESS_TOKEN) {
      console.warn(`[MP WEBHOOK] pagamento ${id} recebido, mas MP_ACCESS_TOKEN não está configurado — não dá para confirmar.`);
      return;
    }

    const payment = await fetchMpPayment(id);
    if (!payment) return;
    if (payment.status !== 'approved') {
      console.log(`[MP WEBHOOK] pagamento ${id} status="${payment.status}" — ignorado (só notificamos aprovados).`);
      return;
    }

    const result = await markOrderPaidFromMp(payment);
    if (result.already) {
      console.log(`[MP WEBHOOK] pagamento ${id} já havia sido processado (pedido #${result.matched}).`);
    } else {
      console.log(`💰 [PAGAMENTO APROVADO] MP ${id} → pedido #${result.matched} ${result.created ? '(novo registro)' : '(atualizado para Pago)'}`);
    }
  } catch (err) {
    console.error('[MP WEBHOOK] erro ao processar:', err);
  }
});

app.post('/api/meetings', async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.name || !b.email || !b.phone || !b.product) {
      return res.status(400).json({ error: 'name, email, phone e product são obrigatórios' });
    }
    const id = b.id || Date.now();
    const now = new Date().toISOString();
    await pool.query(
      `INSERT INTO meetings (id, received_at, date, product, name, email, phone, budget, start_when, status, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (id) DO NOTHING`,
      [
        id, now, b.date || now,
        String(b.product).trim(),
        String(b.name).trim(), String(b.email).trim(), String(b.phone).trim(),
        String(b.tier || b.budget || '').trim(),
        String(b.startWhen || '').trim(),
        b.status || 'Aguardando contato',
        req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
      ]
    );
    console.log(`[NOVA REUNIÃO] #${id} - ${b.name} (${b.email}) - ${b.product}`);
    res.json({ ok: true, id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar reunião' });
  }
});

app.post('/api/validate-key', async (req, res) => {
  try {
    const { key, app: appReq, deviceId } = req.body || {};
    if (!key) return res.json({ valid: false, reason: 'missing_key' });

    const { rows } = await pool.query(
      'SELECT * FROM license_keys WHERE key = $1',
      [String(key).trim().toUpperCase()]
    );
    const k = rows[0];
    if (!k) return res.json({ valid: false, reason: 'not_found' });
    if (k.status !== 'active') return res.json({ valid: false, reason: 'revoked' });
    if (k.expires_at && new Date(k.expires_at) < new Date()) {
      return res.json({ valid: false, reason: 'expired' });
    }
    if (appReq && k.app !== 'all' && k.app !== appReq) {
      return res.json({ valid: false, reason: 'wrong_app' });
    }

    const devices = Array.isArray(k.devices) ? k.devices : [];
    if (deviceId && !devices.includes(deviceId)) devices.push(deviceId);

    await pool.query(
      'UPDATE license_keys SET last_seen_at = $1, devices = $2, device_count = $3 WHERE key = $4',
      [new Date().toISOString(), JSON.stringify(devices), devices.length, k.key]
    );

    res.json({ valid: true, app: k.app, email: k.email, plan: k.plan, expiresAt: k.expires_at });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao validar chave' });
  }
});

// =====================================================
// Admin auth (HTTP Basic)
// =====================================================
function adminAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [type, b64] = header.split(' ');
  if (type === 'Basic' && b64) {
    const decoded = Buffer.from(b64, 'base64').toString();
    const idx = decoded.indexOf(':');
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    const a = Buffer.from(user + ':' + pass);
    const b = Buffer.from(ADMIN_USER + ':' + ADMIN_PASS);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="InviseStore Admin"');
  res.status(401).send('Acesso restrito');
}

// =====================================================
// Admin: pedidos
// =====================================================
app.get('/admin/api/orders', adminAuth, async (req, res) => {
  try {
    // Antes de listar, reconcilia com o Mercado Pago (no maximo 1x a cada 15s)
    // para que pedidos pagos virem "Pago" automaticamente ao abrir/atualizar.
    if (Date.now() - _lastReconcile > 15000) await reconcilePayments();
    const { rows } = await pool.query('SELECT * FROM orders ORDER BY received_at DESC');
    res.json(rows.map(rowToOrder));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar pedidos' });
  }
});

app.patch('/admin/api/orders/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows } = await pool.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [String(req.body.status || 'Pendente'), id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'não encontrado' });
    res.json(rowToOrder(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar pedido' });
  }
});

app.delete('/admin/api/orders/:id', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE id = $1', [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar pedido' });
  }
});

app.get('/admin/api/export.csv', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM orders ORDER BY received_at DESC');
    const orders = rows.map(rowToOrder);
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = 'id,date,name,email,phone,products,total,status,paymentMethod\n';
    const body = orders.map(o => [
      o.id, o.date, o.name, o.email, o.phone,
      (o.products || []).join(' | '),
      o.total, o.status, o.paymentMethod
    ].map(esc).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="pedidos.csv"');
    res.send(head + body);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao exportar' });
  }
});

app.post('/admin/api/orders/:id/key', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'pedido não encontrado' });
    const order = rows[0];
    const appName = (req.body && req.body.app) ? req.body.app : 'all';
    if (!VALID_APPS.includes(appName)) return res.status(400).json({ error: 'app inválido' });

    const kd = makeKeyData({
      app: appName,
      email: order.email,
      orderId: order.id,
      plan: (req.body && req.body.plan) ? req.body.plan : 'lifetime',
      expiresAt: (req.body && req.body.expiresAt) ? req.body.expiresAt : null,
      notes: `Gerada do pedido #${order.id} (${order.name})`
    });

    await pool.query(
      `INSERT INTO license_keys (key, app, email, order_id, plan, status, created_at, expires_at, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [kd.key, kd.app, kd.email, kd.orderId, kd.plan, kd.status, kd.createdAt, kd.expiresAt, kd.notes]
    );
    res.json(kd);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao gerar chave' });
  }
});

// =====================================================
// Admin: notificações de pagamento (pedidos pagos via MP ainda não vistos)
// =====================================================
app.get('/admin/api/notifications', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM orders WHERE status = 'Pago' AND acknowledged = FALSE
       ORDER BY paid_at DESC NULLS LAST, received_at DESC`
    );
    res.json({ count: rows.length, orders: rows.map(rowToOrder) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar notificações' });
  }
});

// Marca notificações como vistas. Sem body: marca todas; com { id }: marca uma.
app.post('/admin/api/notifications/ack', adminAuth, async (req, res) => {
  try {
    if (req.body && req.body.id) {
      await pool.query('UPDATE orders SET acknowledged = TRUE WHERE id = $1', [Number(req.body.id)]);
    } else {
      await pool.query('UPDATE orders SET acknowledged = TRUE WHERE acknowledged = FALSE');
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao marcar notificações' });
  }
});

// =====================================================
// Admin: reuniões (serviços)
// =====================================================
app.get('/admin/api/meetings', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM meetings ORDER BY received_at DESC');
    res.json(rows.map(rowToMeeting));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar reuniões' });
  }
});

app.patch('/admin/api/meetings/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows } = await pool.query(
      'UPDATE meetings SET status = $1 WHERE id = $2 RETURNING *',
      [String(req.body.status || 'Aguardando contato'), id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'não encontrado' });
    res.json(rowToMeeting(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar reunião' });
  }
});

app.delete('/admin/api/meetings/:id', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM meetings WHERE id = $1', [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar reunião' });
  }
});

app.get('/admin/api/meetings/export.csv', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM meetings ORDER BY received_at DESC');
    const meetings = rows.map(rowToMeeting);
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = 'id,date,product,name,email,phone,tier,startWhen,status\n';
    const body = meetings.map(m => [
      m.id, m.date, m.product, m.name, m.email, m.phone, m.tier, m.startWhen, m.status
    ].map(esc).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="reunioes.csv"');
    res.send(head + body);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao exportar' });
  }
});

// =====================================================
// Admin: chaves
// =====================================================
app.get('/admin/api/keys', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM license_keys ORDER BY created_at DESC');
    res.json(rows.map(rowToKey));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar chaves' });
  }
});

app.post('/admin/api/keys', adminAuth, async (req, res) => {
  try {
    const kd = makeKeyData(req.body || {});
    await pool.query(
      `INSERT INTO license_keys (key, app, email, order_id, plan, status, created_at, expires_at, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [kd.key, kd.app, kd.email, kd.orderId, kd.plan, kd.status, kd.createdAt, kd.expiresAt, kd.notes]
    );
    res.json(kd);
  } catch (err) {
    if (err.message === 'app inválido') return res.status(400).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar chave' });
  }
});

app.patch('/admin/api/keys/:key', adminAuth, async (req, res) => {
  try {
    const key = String(req.params.key).toUpperCase();
    const fieldMap = { status: 'status', plan: 'plan', expiresAt: 'expires_at', notes: 'notes', app: 'app', email: 'email' };
    const sets = [];
    const vals = [];
    for (const [bodyField, col] of Object.entries(fieldMap)) {
      if (req.body && Object.prototype.hasOwnProperty.call(req.body, bodyField)) {
        sets.push(`${col} = $${sets.length + 1}`);
        vals.push(req.body[bodyField]);
      }
    }
    if (sets.length === 0) {
      const { rows } = await pool.query('SELECT * FROM license_keys WHERE key = $1', [key]);
      if (!rows[0]) return res.status(404).json({ error: 'chave não encontrada' });
      return res.json(rowToKey(rows[0]));
    }
    vals.push(key);
    const { rows } = await pool.query(
      `UPDATE license_keys SET ${sets.join(', ')} WHERE key = $${vals.length} RETURNING *`,
      vals
    );
    if (!rows[0]) return res.status(404).json({ error: 'chave não encontrada' });
    res.json(rowToKey(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar chave' });
  }
});

app.delete('/admin/api/keys/:key', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM license_keys WHERE key = $1', [String(req.params.key).toUpperCase()]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar chave' });
  }
});

app.get('/admin/api/keys/export.csv', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM license_keys ORDER BY created_at DESC');
    const keys = rows.map(rowToKey);
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = 'key,app,email,orderId,plan,status,createdAt,expiresAt,lastSeenAt,deviceCount\n';
    const body = keys.map(k => [
      k.key, k.app, k.email, k.orderId, k.plan, k.status,
      k.createdAt, k.expiresAt, k.lastSeenAt, k.deviceCount
    ].map(esc).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="chaves.csv"');
    res.send(head + body);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao exportar' });
  }
});

// =====================================================
// Painel + raiz
// =====================================================
app.get('/admin', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Consulta publica do status de um pedido (usada pela tela de retorno
// para atualizar sozinha quando o pagamento for confirmado).
app.get('/api/order-status/:id', async (req, res) => {
  try {
    if (Date.now() - _lastReconcile > 15000) reconcilePayments(); // nudge (sem await)
    const { rows } = await pool.query('SELECT status FROM orders WHERE id = $1', [Number(req.params.id)]);
    res.json({ status: rows[0] ? rows[0].status : null });
  } catch (err) {
    res.status(500).json({ status: null });
  }
});

// =====================================================
// Telas de retorno do checkout (back_urls do Mercado Pago)
// Atualizam sozinhas: se voltar como "pendente", consultam o pedido a cada
// 3s e mudam para "aprovado" assim que o pagamento for confirmado.
// =====================================================
const RETURN_CFG = {
  approved: { titulo: 'Pagamento aprovado!', emoji: '✅', cor: '#43e97b', msg: 'Recebemos a confirmação do seu pagamento. Seu produto será enviado para o seu e-mail em instantes — confira também a caixa de spam. Obrigado pela compra! 🎉' },
  pending:  { titulo: 'Pagamento em processamento', emoji: '⏳', cor: '#f59e0b', msg: 'Seu pagamento está sendo processado. Esta página atualiza sozinha assim que ele for confirmado.' },
  failure:  { titulo: 'Compra não concluída', emoji: '❌', cor: '#ef4444', msg: 'O pagamento não foi concluído, então sua compra não foi realizada. Você pode tentar novamente quando quiser.' }
};

function compraPage(kind, orderId) {
  const c = RETURN_CFG[kind] || RETURN_CFG.pending;
  const voltar = STORE_URL
    ? `<a href="${STORE_URL}" style="display:inline-block;margin-top:24px;background:#6c63ff;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:600;">Voltar à loja</a>`
    : '';
  const aprovadoJson = JSON.stringify(RETURN_CFG.approved);
  const poll = (kind === 'pending' && orderId)
    ? `<script>(function(){var oid=${JSON.stringify(String(orderId))},ap=${aprovadoJson},n=0;`
      + `var t=setInterval(function(){n++;fetch('/api/order-status/'+oid).then(function(r){return r.json();})`
      + `.then(function(d){if(d&&d.status==='Pago'){clearInterval(t);`
      + `document.getElementById('e').textContent=ap.emoji;`
      + `var h=document.getElementById('t');h.textContent=ap.titulo;h.style.color=ap.cor;`
      + `document.getElementById('m').textContent=ap.msg;}}).catch(function(){});`
      + `if(n>40)clearInterval(t);},3000);})();</script>`
    : '';
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>${c.titulo} — InviseStore</title><style>`
    + `body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;`
    + `background:#0a0a0f;color:#f0f0f5;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px;}`
    + `.box{max-width:440px;text-align:center;background:#13131e;border:1px solid rgba(255,255,255,.08);`
    + `border-radius:16px;padding:40px 28px;}.emoji{font-size:54px;line-height:1;}`
    + `h1{font-size:22px;margin:18px 0 10px;}p{color:#b8b8c8;font-size:15px;line-height:1.6;margin:0;}`
    + `</style></head><body><div class="box"><div class="emoji" id="e">${c.emoji}</div>`
    + `<h1 id="t" style="color:${c.cor}">${c.titulo}</h1><p id="m">${c.msg}</p>${voltar}</div>${poll}</body></html>`;
}

// Decide o estado real pela query que o Mercado Pago anexa (status/collection_status).
function returnKind(req, fallbackKind) {
  const s = String(req.query.status || req.query.collection_status || '').toLowerCase();
  if (s === 'approved') return 'approved';
  if (s === 'rejected' || s === 'cancelled') return 'failure';
  if (s === 'pending' || s === 'in_process') return 'pending';
  return fallbackKind;
}

app.get('/compra/sucesso', (req, res) => res.send(compraPage(returnKind(req, 'approved'), req.query.external_reference || '')));
app.get('/compra/pendente', (req, res) => res.send(compraPage(returnKind(req, 'pending'), req.query.external_reference || '')));
app.get('/compra/falha', (req, res) => res.send(compraPage(returnKind(req, 'failure'), req.query.external_reference || '')));

app.get('/', (req, res) => {
  res.send('InviseStore backend ativo. Painel: <a href="/admin">/admin</a>');
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n✅ InviseStore backend rodando em http://localhost:${PORT}`);
      console.log(`   Painel:  http://localhost:${PORT}/admin`);
      console.log(`   Login:   ${ADMIN_USER} / ${ADMIN_PASS}`);
      console.log(`   Webhook MP: POST /api/mp/webhook`);
      if (!MP_ACCESS_TOKEN) {
        console.warn('   ⚠️  MP_ACCESS_TOKEN não configurado — os pagamentos do Mercado Pago NÃO serão confirmados automaticamente.');
      } else {
        console.log('   ✅ MP_ACCESS_TOKEN configurado — confirmação automática de pagamentos ativa.');
      }
      console.log('');
    });
    if (MP_ACCESS_TOKEN) {
      reconcilePayments();
      setInterval(reconcilePayments, 60000);
      console.log('🔄 Reconciliação automática de pagamentos ativa (a cada 60s).');
    }
  })
  .catch(err => {
    console.error('ERRO ao inicializar banco:', err);
    process.exit(1);
  });
