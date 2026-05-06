const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'invise123';

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
  console.log('✅ Tabelas verificadas/criadas.');
}

const VALID_APPS = ['habitos', 'finapp', 'all'];

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

app.get('/', (req, res) => {
  res.send('InviseStore backend ativo. Painel: <a href="/admin">/admin</a>');
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n✅ InviseStore backend rodando em http://localhost:${PORT}`);
      console.log(`   Painel:  http://localhost:${PORT}/admin`);
      console.log(`   Login:   ${ADMIN_USER} / ${ADMIN_PASS}\n`);
    });
  })
  .catch(err => {
    console.error('ERRO ao inicializar banco:', err);
    process.exit(1);
  });
