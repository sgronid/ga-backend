# Guest App Backend (Node) — v0.1

Questo backend è pensato per **dare persistenza reale** (server-side) a:
- **Tenants/Strutture** (multi-tenant)
- **Utenti/Staff/Provider** (RBAC + duties)
- **Inviti** (staff e provider via token)
- **Directory/Config** serviti via endpoint compatibili con la Guest App (`/GA_CONFIG/...`)

È intenzionalmente **piccolo** e parte con uno storage **file-based** (`data/db.json`) per rendere il deploy semplice.

> Nota: è un *bootstrap* sicuro quanto basta per demo e iterazioni. Per produzione è consigliato passare a Postgres + audit completo + hardening ulteriore.

---

## 1) Requisiti
- Node.js **18+** (consigliato 20 LTS)
- npm

---

## 2) Setup rapido

```bash
cd ga_backend_v0_1
cp .env.example .env
npm install
npm run start
```

Verifica:
- http://localhost:3030/health
- http://localhost:3030/GA_CONFIG/directory.json

---

## 3) Reverse proxy consigliato (stesso dominio della Guest App)

Se la Guest App è su `https://www.muradeltempo.it/APP3734F/dist/`, conviene esporre:
- API: `https://www.muradeltempo.it/ga-api/...`
- Config: `https://www.muradeltempo.it/GA_CONFIG/...`  (compatibile con il loader già presente)

### Esempio Apache (schematico)

```apache
ProxyPreserveHost On
ProxyPass /ga-api http://127.0.0.1:3030/ga-api
ProxyPassReverse /ga-api http://127.0.0.1:3030/ga-api

ProxyPass /GA_CONFIG http://127.0.0.1:3030/GA_CONFIG
ProxyPassReverse /GA_CONFIG http://127.0.0.1:3030/GA_CONFIG
```

---

## 4) Credenziali superadmin
Definite in `.env`:
- `SUPERADMIN_EMAIL`
- `SUPERADMIN_PASSWORD`

Al primo avvio, se non esiste, viene creato automaticamente.

---

## 5) Storage
File: `data/db.json`
Contiene tenants, users, invites, configs (draft/published), auditEvents.

---

## 6) Endpoints principali

### Health
- `GET /health`

### Auth
- `POST /ga-api/auth/login`  `{ email, password }`
- `POST /ga-api/auth/logout`
- `GET /ga-api/auth/me`

### Tenant self-registration (public)
- `POST /ga-api/public/tenants/register`  `{ tenantName, tenantSlug, city, email, password }`
  - crea tenant **PENDING**
  - crea utente **tenant_admin**
  - tenant può entrare nel suo portal e preparare config **draft**
  - NON compare nel `/GA_CONFIG/directory.json` finché non viene approvato dal superadmin.

### Superadmin
- `GET /ga-api/superadmin/tenants`
- `POST /ga-api/superadmin/tenants/:tenantId/approve`
- `POST /ga-api/superadmin/tenants/:tenantId/plan` `{ planId }`
- `POST /ga-api/superadmin/commission` `{ type: "percent"|"fixed", value: number }`

### Config (directory + tenant)
- `GET /GA_CONFIG/directory.json`
- `GET /GA_CONFIG/:tenantSlug.json`

### Tenant portal
- `GET /ga-api/tenant/me`
- `GET /ga-api/tenant/config/draft`
- `PUT /ga-api/tenant/config/draft`
- `POST /ga-api/tenant/config/publish`

### Invites (staff/provider)
- `POST /ga-api/tenant/invites` `{ email, role, duties, providerName? }`
- `GET /ga-api/tenant/invites`
- `POST /ga-api/invites/accept` `{ token, name, password }`

---

## 7) Roadmap backend (successivi step)
- Migrazione storage -> Postgres
- Audit trail normalizzato e query/export
- Stripe Connect (commissioni reali su transazioni)
- Policy/retention e privacy (GDPR)

