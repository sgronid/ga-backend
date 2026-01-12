require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');

const { readDB, writeDB } = require('./store');
const { nowISO, id, slugify, clampInt } = require('./util');
const {
  ensureSuperadmin,
  signSession,
  clearSession,
  readAuth,
  requireAuth,
  requireRole,
  requireTenantScope
} = require('./auth');
const { requireDuty } = require('./rbac');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(morgan('dev'));

const corsOrigins = String(process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true); // curl / same-origin
      if (corsOrigins.length === 0) return cb(null, true);
      if (corsOrigins.includes(origin)) return cb(null, true);
      return cb(new Error('CORS_BLOCKED'));
    },
    credentials: true
  })
);

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// Attach auth to every request if present
app.use(async (req, _res, next) => {
  req.auth = await readAuth(req);
  next();
});

app.get('/ga-api/ping', (_req, res) => {
  res.json({ ok: true, at: nowISO() });
});

// --- Bootstrap: ensure superadmin exists
app.use(async (_req, _res, next) => {
  const db = await readDB();
  const changed = await ensureSuperadmin(db);
  if (changed) await writeDB(db);
  next();
});

// -----------------------------------------
// AUTH
// -----------------------------------------
app.post('/ga-api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });

  const db = await readDB();
  const user = db.users.find((u) => u.email && u.email.toLowerCase() === String(email).toLowerCase());
  if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  const bcrypt = require('bcryptjs');
  const ok = await bcrypt.compare(String(password), user.passwordHash || '');
  if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

  // Determine role: prefer superadmin flag, otherwise need an active membership
  let role = user.role || null;
  let membership = null;
  if (!role || role === 'guest') {
    // pick first active membership
    membership = db.memberships.find((m) => m.userId === user.id && m.status === 'active');
    role = membership?.role || 'guest';
  }

  const sessionPayload = {
    uid: user.id,
    role,
    tenantId: membership?.tenantId || null,
    providerId: membership?.providerId || null,
    membershipId: membership?.id || null,
    duties: membership?.duties || []
  };

  signSession(res, sessionPayload);
  user.lastLoginAt = nowISO();
  await writeDB(db);

  res.json({ ok: true, role, tenantId: sessionPayload.tenantId, providerId: sessionPayload.providerId });
});

app.post('/ga-api/auth/logout', async (_req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get('/ga-api/auth/me', requireAuth, async (req, res) => {
  const db = await readDB();
  const user = db.users.find((u) => u.id === req.auth.uid);
  if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });
  res.json({
    ok: true,
    user: { id: user.id, email: user.email, name: user.name || '', surname: user.surname || '' },
    session: req.auth
  });
});

// -----------------------------------------
// PUBLIC TENANT SELF-REGISTRATION
// -----------------------------------------
app.post('/ga-api/public/tenants/register', async (req, res) => {
  if (String(process.env.ALLOW_PUBLIC_TENANT_REGISTRATION || '1') !== '1') {
    return res.status(403).json({ error: 'REGISTRATION_DISABLED' });
  }

  const { tenantName, city, email, password } = req.body || {};
  if (!tenantName || !email || !password) {
    return res.status(400).json({ error: 'MISSING_FIELDS' });
  }

  const db = await readDB();
  const existing = db.users.find((u) => (u.email || '').toLowerCase() === String(email).toLowerCase());
  if (existing) return res.status(409).json({ error: 'EMAIL_ALREADY_USED' });

  const tenantId = id('t');
  const tenantSlug = slugify(tenantName) || tenantId;

  // create tenant pending
  const tenant = {
    id: tenantId,
    slug: tenantSlug,
    name: tenantName,
    city: city || '',
    status: 'pending', // pending -> approved
    visible: false,
    planId: 'free',
    createdAt: nowISO(),
    approvedAt: null
  };
  db.tenants.push(tenant);

  // create user + membership as tenant_admin
  const bcrypt = require('bcryptjs');
  const userId = id('u');
  const passwordHash = await bcrypt.hash(String(password), 10);
  const user = {
    id: userId,
    email,
    passwordHash,
    role: null,
    createdAt: nowISO(),
    lastLoginAt: null
  };
  db.users.push(user);

  const membership = {
    id: id('m'),
    userId,
    tenantId,
    providerId: null,
    role: 'tenant_admin',
    duties: ['tenant_admin_all'],
    status: 'active',
    createdAt: nowISO()
  };
  db.memberships.push(membership);

  // create a starter draft config (editable even while pending)
  db.configs.draft[tenantSlug] = db.configs.draft[tenantSlug] || {
    id: tenantSlug,
    name: tenantName,
    city: city || '',
    status: 'DRAFT',
    updatedAt: nowISO(),
    ui: {
      labels: {
        providers: 'Attività locali (terze parti)'
      }
    }
  };

  await writeDB(db);

  // auto-login
  signSession(res, {
    uid: userId,
    role: 'tenant_admin',
    tenantId,
    providerId: null,
    membershipId: membership.id,
    duties: membership.duties
  });

  res.json({ ok: true, tenant: { id: tenantId, slug: tenantSlug, status: tenant.status } });
});

// -----------------------------------------
// INVITES (tenant creates; staff/provider accepts)
// -----------------------------------------
app.post('/ga-api/tenant/invites', requireAuth, requireRole(['tenant_admin', 'superadmin']), async (req, res) => {
  const { email, role, duties } = req.body || {};
  if (!email || !role) return res.status(400).json({ error: 'MISSING_FIELDS' });

  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.auth.tenantId) || null;
  if (req.auth.role !== 'superadmin' && !tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });

  const invite = {
    token: id('inv'),
    email,
    tenantId: req.auth.role === 'superadmin' ? (req.body.tenantId || null) : req.auth.tenantId,
    providerId: req.body.providerId || null,
    role,
    duties: Array.isArray(duties) ? duties : [],
    status: 'pending',
    createdAt: nowISO(),
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString() // 7 days
  };

  if (!invite.tenantId) return res.status(400).json({ error: 'TENANT_ID_REQUIRED' });

  db.invites.push(invite);
  await writeDB(db);

  res.json({ ok: true, invite: { token: invite.token, expiresAt: invite.expiresAt } });
});

app.post('/ga-api/invites/accept', async (req, res) => {
  const { token, password, name, surname } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });

  const db = await readDB();
  const invite = db.invites.find((i) => i.token === token);
  if (!invite) return res.status(404).json({ error: 'INVITE_NOT_FOUND' });
  if (invite.status !== 'pending') return res.status(409).json({ error: 'INVITE_ALREADY_USED' });
  if (invite.expiresAt && Date.parse(invite.expiresAt) < Date.now()) return res.status(410).json({ error: 'INVITE_EXPIRED' });

  // create user if not exists
  const existing = db.users.find((u) => (u.email || '').toLowerCase() === String(invite.email).toLowerCase());
  if (existing) return res.status(409).json({ error: 'EMAIL_ALREADY_USED' });

  const bcrypt = require('bcryptjs');
  const userId = id('u');
  const passwordHash = await bcrypt.hash(String(password), 10);
  const user = {
    id: userId,
    email: invite.email,
    name: name || '',
    surname: surname || '',
    passwordHash,
    role: null,
    createdAt: nowISO(),
    lastLoginAt: null
  };
  db.users.push(user);

  const membership = {
    id: id('m'),
    userId,
    tenantId: invite.tenantId,
    providerId: invite.providerId || null,
    role: invite.role,
    duties: invite.duties || [],
    status: 'active',
    createdAt: nowISO()
  };
  db.memberships.push(membership);

  invite.status = 'accepted';
  invite.acceptedAt = nowISO();

  await writeDB(db);

  signSession(res, {
    uid: userId,
    role: membership.role,
    tenantId: membership.tenantId,
    providerId: membership.providerId,
    membershipId: membership.id,
    duties: membership.duties
  });

  res.json({ ok: true, role: membership.role, tenantId: membership.tenantId, providerId: membership.providerId });
});

// -----------------------------------------
// SUPERADMIN
// -----------------------------------------
app.get('/ga-api/superadmin/tenants', requireAuth, requireRole(['superadmin']), async (_req, res) => {
  const db = await readDB();
  res.json({ ok: true, tenants: db.tenants });
});

app.post('/ga-api/superadmin/tenants/:tenantId/approve', requireAuth, requireRole(['superadmin']), async (req, res) => {
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.params.tenantId);
  if (!tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
  tenant.status = 'approved';
  tenant.visible = true;
  tenant.approvedAt = nowISO();
  await writeDB(db);
  res.json({ ok: true, tenant });
});

app.post('/ga-api/superadmin/tenants/:tenantId/plan', requireAuth, requireRole(['superadmin']), async (req, res) => {
  const { planId } = req.body || {};
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.params.tenantId);
  if (!tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
  const plan = db.plans.find((p) => p.id === planId);
  if (!plan) return res.status(404).json({ error: 'PLAN_NOT_FOUND' });
  tenant.planId = planId;
  await writeDB(db);
  res.json({ ok: true, tenant });
});

app.post('/ga-api/superadmin/platform/commission', requireAuth, requireRole(['superadmin']), async (req, res) => {
  const { type, value } = req.body || {};
  const db = await readDB();
  if (type !== 'percent' && type !== 'fixed') return res.status(400).json({ error: 'INVALID_TYPE' });
  const v = Number(value);
  if (!Number.isFinite(v) || v < 0) return res.status(400).json({ error: 'INVALID_VALUE' });
  db.platform.commission = { type, value: v };
  await writeDB(db);
  res.json({ ok: true, commission: db.platform.commission });
});

// -----------------------------------------
// TENANT CONFIG (draft/publish)
// -----------------------------------------
app.get('/ga-api/tenant/config/draft', requireAuth, requireTenantScope, async (req, res) => {
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.auth.tenantId);
  if (!tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
  const key = tenant.slug;
  const draft = db.configs.draft[key] || null;
  res.json({ ok: true, draft });
});

app.put('/ga-api/tenant/config/draft', requireAuth, requireTenantScope, async (req, res) => {
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.auth.tenantId);
  if (!tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
  const key = tenant.slug;
  const payload = req.body || {};
  db.configs.draft[key] = { ...payload, id: key, updatedAt: nowISO() };
  await writeDB(db);
  res.json({ ok: true, draft: db.configs.draft[key] });
});

app.post('/ga-api/tenant/config/publish', requireAuth, requireTenantScope, async (req, res) => {
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.id === req.auth.tenantId);
  if (!tenant) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
  const key = tenant.slug;
  const draft = db.configs.draft[key];
  if (!draft) return res.status(400).json({ error: 'NO_DRAFT' });

  // Publish is allowed even while pending (for preview), but public endpoints won't expose until approved.
  db.configs.published[key] = { ...draft, status: 'PUBLISHED', publishedAt: nowISO() };
  await writeDB(db);
  res.json({ ok: true, published: db.configs.published[key], visible: tenant.status === 'approved' });
});

// -----------------------------------------
// GA_CONFIG COMPAT (served by backend)
// -----------------------------------------
app.get('/GA_CONFIG/directory.json', async (_req, res) => {
  const db = await readDB();
  const tenants = db.tenants.filter((t) => t.status === 'approved' && t.visible);
  const items = tenants.map((t) => ({
    id: t.slug,
    tenantId: t.id,
    name: t.name,
    city: t.city || '',
    configUrl: `/GA_CONFIG/${t.slug}.json`
  }));
  res.json({ ok: true, items, updatedAt: nowISO() });
});

app.get('/GA_CONFIG/:tenantSlug.json', async (req, res) => {
  const tenantSlug = req.params.tenantSlug;
  const db = await readDB();
  const tenant = db.tenants.find((t) => t.slug === tenantSlug);
  if (!tenant || tenant.status !== 'approved' || !tenant.visible) return res.status(404).json({ error: 'NOT_FOUND' });
  const config = db.configs.published[tenantSlug] || null;
  if (!config) return res.status(404).json({ error: 'NO_PUBLISHED_CONFIG' });

  // Attach plan features
  const plan = db.plans.find((p) => p.id === (tenant.planId || 'free')) || db.plans[0];
  res.json({ ...config, plan: { id: plan.id, name: plan.name, features: plan.features }, tenant: { id: tenant.id, slug: tenant.slug, name: tenant.name, city: tenant.city } });
});

// -----------------------------------------
// STAFF DUTY EXAMPLE: ARRIVALS (placeholder)
// -----------------------------------------
app.get('/ga-api/staff/arrivals', requireAuth, requireDuty('arrivals'), async (req, res) => {
  // For now this is a placeholder. Next step: connect PMS.
  const days = clampInt(req.query.days, 7, 1, 180);
  res.json({
    ok: true,
    days,
    items: [],
    note: 'TODO: PMS integration. This endpoint exists so the Staff Portal can be wired now.'
  });
});

// -----------------------------------------
// Errors
// -----------------------------------------
app.use((err, req, res, _next) => {
  console.error('ERR', err);
  const code = err && err.message === 'CORS_BLOCKED' ? 403 : 500;
  res.status(code).json({ error: code === 403 ? 'CORS_BLOCKED' : 'SERVER_ERROR' });
});

const port = clampInt(process.env.PORT, 3030, 1, 65535);
app.listen(port, () => {
  console.log(`GA backend listening on :${port}`);
});
