const fs = require('fs');
const path = require('path');

const DEFAULT_DB = {
  version: 1,
  createdAt: new Date().toISOString(),
  tenants: [],
  users: [],
  memberships: [],
  invites: [],
  plans: [
    {
      id: 'free',
      name: 'Free',
      features: {
        docsUpload: true,
        docsQueue: false,
        staffArrivals: false,
        providers: true,
        shop: true,
        payments: false,
        commissions: false
      },
      limits: {
        maxStaff: 3,
        maxProviders: 5
      }
    },
    {
      id: 'pro',
      name: 'Pro',
      features: {
        docsUpload: true,
        docsQueue: true,
        staffArrivals: true,
        providers: true,
        shop: true,
        payments: true,
        commissions: true
      },
      limits: {
        maxStaff: 50,
        maxProviders: 100
      }
    }
  ],
  platform: {
    commissionDefault: { type: 'percent', value: 10 },
    commissionPerTenant: {}
  },
  configs: {
    draft: {},
    published: {}
  },
  auditEvents: []
};

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function atomicWriteJson(filePath, data) {
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function loadJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function createStore({ dataDir }) {
  const absDataDir = path.isAbsolute(dataDir) ? dataDir : path.join(process.cwd(), dataDir);
  ensureDir(absDataDir);

  const dbPath = path.join(absDataDir, 'db.json');

  // Serialize writes so we don't corrupt the JSON
  let writeQueue = Promise.resolve();

  function readDB() {
    const db = loadJson(dbPath);
    if (!db) {
      atomicWriteJson(dbPath, DEFAULT_DB);
      return JSON.parse(JSON.stringify(DEFAULT_DB));
    }
    return db;
  }

  function writeDB(nextDB) {
    writeQueue = writeQueue.then(() => {
      atomicWriteJson(dbPath, nextDB);
    });
    return writeQueue;
  }

  function withDB(mutator) {
    const db = readDB();
    const result = mutator(db);
    return writeDB(db).then(() => result);
  }

  return {
    dbPath,
    readDB,
    writeDB,
    withDB
  };
}

module.exports = {
  createStore
};
