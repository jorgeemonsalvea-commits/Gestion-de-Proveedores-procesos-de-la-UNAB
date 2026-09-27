// ==========================================
// SPRINT 4 TESTS — 4-0: Cache-Control no-store en /api (HALL-044)
// ==========================================
jest.setTimeout(30000);
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3998';
process.env.APP_URL = 'http://localhost:3998';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-sprint4-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db, serverInstance;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  serverInstance = app.listen(0);
}, 60000);

afterAll(async () => {
  if (serverInstance) await new Promise(r => serverInstance.close(r));
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
}, 15000);

describe('Sprint 4-0 — HALL-044 Cache-Control en /api', () => {
  test('GET /api/me (sin sesión) lleva no-store', async () => {
    const res = await request(app).get('/api/me');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toContain('no-store');
    expect(res.headers['pragma']).toBe('no-cache');
  });

  test('GET /api/admin/proveedores (con sesión) lleva no-store', async () => {
    const agent = request.agent(app);
    const login = await agent.post('/api/login').send({ email: 'admin@test.local', password: 'AdminTest123!' });
    expect(login.status).toBe(200);
    const res = await agent.get('/api/admin/proveedores');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toContain('no-store');
  });

  test('estáticos NO reciben no-store (caché larga preservada)', async () => {
    const res = await request(app).get('/admin.html');
    expect(res.status).toBe(200);
    const cc = res.headers['cache-control'] || '';
    expect(cc).not.toContain('no-store');
  });
});