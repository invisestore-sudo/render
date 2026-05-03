const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'invise123';

const DATA_DIR = path.join(__dirname, 'data');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');
if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, '[]');

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const readOrders = () => readJson(ORDERS_FILE, []);
const writeOrders = (d) => writeJson(ORDERS_FILE, d);
const readKeys = () => readJson(KEYS_FILE, []);
const writeKeys = (d) => writeJson(KEYS_FILE, d);

// Apps válidos (cada chave libera 1 ou mais)
const VALID_APPS = ['habitos', 'finapp', 'all'];

function generateKey() {
  // Formato: INVS-XXXX-XXXX-XXXX (alfanum maiúsculo, sem 0/O/1/I)
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chunk = () => Array.from({ length: 4 }, () =>
    alphabet[crypto.randomInt(0, alphabet.length)]).join('');
  return `INVS-${chunk()}-${chunk()}-${chunk()}`;
}

function makeKey({ app = 'all', email = '', orderId = null, plan = 'lifetime', expiresAt = null, notes = '' }) {
  if (!VALID_APPS.includes(app)) throw new Error('app inválido');
  const key = generateKey();
  return {
    key,
    app,
    email: String(email || '').trim().toLowerCase(),
    orderId: orderId || null,
    plan,
    status: 'active',
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt || null,
    lastSeenAt: null,
    deviceCount: 0,
    devices: [],
    notes: String(notes || '')
  };
}

const app = express();
// CORS — libera tudo (mais simples para webapps estáticos públicos)
// Se quiser restringir, troque por: cors({ origin: ['https://invise-store.vercel.app', ...] })
app.use(cors({ origin: true, credentials: false }));
app.options('*', cors());
app.use(express.json({ limit: '1mb' }));

// =====================================================
// ============ Public API (sem auth) ==================
// =====================================================

app.post('/api/orders', (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.email) {
    return res.status(400).json({ error: 'name e email são obrigatórios' });
  }
  const order = {
    id: b.id || Date.now(),
    receivedAt: new Date().toISOString(),
    date: b.date || new Date().toISOString(),
    name: String(b.name).trim(),
    email: String(b.email).trim(),
    phone: String(b.phone || '').trim(),
    products: Array.isArray(b.products) ? b.products : [],
    total: Number(b.total) || 0,
    status: b.status || 'Pendente',
    paymentMethod: b.paymentMethod || 'PIX',
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
  };
  const orders = readOrders();
  orders.unshift(order);
  writeOrders(orders);
  console.log(`[NOVO PEDIDO] #${order.id} - ${order.name} (${order.email}) - R$ ${order.total}`);
  res.json({ ok: true, id: order.id });
});

// Valida chave única do cliente (chamado pelos webapps)
app.post('/api/validate-key', (req, res) => {
  const { key, app: appReq, deviceId } = req.body || {};
  if (!key) return res.json({ valid: false, reason: 'missing_key' });
  const keys = readKeys();
  const k = keys.find(x => x.key === String(key).trim().toUpperCase());
  if (!k) return res.json({ valid: false, reason: 'not_found' });
  if (k.status !== 'active') return res.json({ valid: false, reason: 'revoked' });
  if (k.expiresAt && new Date(k.expiresAt) < new Date()) {
    return res.json({ valid: false, reason: 'expired' });
  }
  if (appReq && k.app !== 'all' && k.app !== appReq) {
    return res.json({ valid: false, reason: 'wrong_app' });
  }
  // Telemetria simples de device
  if (deviceId) {
    if (!Array.isArray(k.devices)) k.devices = [];
    if (!k.devices.includes(deviceId)) {
      k.devices.push(deviceId);
      k.deviceCount = k.devices.length;
    }
  }
  k.lastSeenAt = new Date().toISOString();
  writeKeys(keys);
  res.json({
    valid: true,
    app: k.app,
    email: k.email,
    plan: k.plan,
    expiresAt: k.expiresAt
  });
});

// =====================================================
// ============ Admin auth (HTTP Basic) ================
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
// ============ Admin: pedidos =========================
// =====================================================
app.get('/admin/api/orders', adminAuth, (req, res) => {
  res.json(readOrders());
});

app.patch('/admin/api/orders/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  const orders = readOrders();
  const i = orders.findIndex(o => Number(o.id) === id);
  if (i === -1) return res.status(404).json({ error: 'não encontrado' });
  if (req.body.status) orders[i].status = String(req.body.status);
  writeOrders(orders);
  res.json(orders[i]);
});

app.delete('/admin/api/orders/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  const orders = readOrders().filter(o => Number(o.id) !== id);
  writeOrders(orders);
  res.json({ ok: true });
});

app.get('/admin/api/export.csv', adminAuth, (req, res) => {
  const orders = readOrders();
  const head = 'id,date,name,email,phone,products,total,status,paymentMethod\n';
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = orders.map(o => [
    o.id, o.date, o.name, o.email, o.phone,
    (o.products || []).join(' | '),
    o.total, o.status, o.paymentMethod
  ].map(esc).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="pedidos.csv"');
  res.send(head + rows);
});

// Gera chave a partir de um pedido (admin clica "Gerar chave" no painel)
app.post('/admin/api/orders/:id/key', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  const orders = readOrders();
  const order = orders.find(o => Number(o.id) === id);
  if (!order) return res.status(404).json({ error: 'pedido não encontrado' });
  const appName = req.body && req.body.app ? req.body.app : 'all';
  if (!VALID_APPS.includes(appName)) return res.status(400).json({ error: 'app inválido' });
  const keys = readKeys();
  const k = makeKey({
    app: appName,
    email: order.email,
    orderId: order.id,
    plan: req.body && req.body.plan ? req.body.plan : 'lifetime',
    expiresAt: req.body && req.body.expiresAt ? req.body.expiresAt : null,
    notes: `Gerada do pedido #${order.id} (${order.name})`
  });
  keys.unshift(k);
  writeKeys(keys);
  res.json(k);
});

// =====================================================
// ============ Admin: chaves ==========================
// =====================================================
app.get('/admin/api/keys', adminAuth, (req, res) => {
  res.json(readKeys());
});

app.post('/admin/api/keys', adminAuth, (req, res) => {
  try {
    const k = makeKey(req.body || {});
    const keys = readKeys();
    keys.unshift(k);
    writeKeys(keys);
    res.json(k);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/admin/api/keys/:key', adminAuth, (req, res) => {
  const key = String(req.params.key).toUpperCase();
  const keys = readKeys();
  const i = keys.findIndex(k => k.key === key);
  if (i === -1) return res.status(404).json({ error: 'chave não encontrada' });
  const allowed = ['status', 'plan', 'expiresAt', 'notes', 'app', 'email'];
  for (const f of allowed) {
    if (req.body && Object.prototype.hasOwnProperty.call(req.body, f)) {
      keys[i][f] = req.body[f];
    }
  }
  writeKeys(keys);
  res.json(keys[i]);
});

app.delete('/admin/api/keys/:key', adminAuth, (req, res) => {
  const key = String(req.params.key).toUpperCase();
  const keys = readKeys().filter(k => k.key !== key);
  writeKeys(keys);
  res.json({ ok: true });
});

app.get('/admin/api/keys/export.csv', adminAuth, (req, res) => {
  const keys = readKeys();
  const head = 'key,app,email,orderId,plan,status,createdAt,expiresAt,lastSeenAt,deviceCount\n';
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = keys.map(k => [
    k.key, k.app, k.email, k.orderId, k.plan, k.status,
    k.createdAt, k.expiresAt, k.lastSeenAt, k.deviceCount
  ].map(esc).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="chaves.csv"');
  res.send(head + rows);
});

// =====================================================
// ============ Painel + raiz ==========================
// =====================================================
app.get('/admin', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/', (req, res) => {
  res.send('InviseStore backend ativo. Painel: <a href="/admin">/admin</a>');
});

app.listen(PORT, () => {
  console.log(`\n✅ InviseStore backend rodando em http://localhost:${PORT}`);
  console.log(`   Painel:  http://localhost:${PORT}/admin`);
  console.log(`   Login:   ${ADMIN_USER} / ${ADMIN_PASS}\n`);
});
