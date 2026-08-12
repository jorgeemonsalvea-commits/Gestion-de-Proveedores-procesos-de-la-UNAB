// ==========================================
// 💾 TESTS: GESTIÓN DE BACKUPS (solo admin)
// ==========================================
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3997';
process.env.APP_URL = 'http://localhost:3997';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');

// BD aislada en temp (no toca tu BD real)
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-backups-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db, agent;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  agent = request.agent(app); // conserva la cookie de sesión
  const login = await agent.post('/api/login').send({
    email: 'admin@test.local',
    password: 'AdminTest123!'
  });
  if (login.status !== 200) throw new Error('No se pudo loguear el admin de prueba');
});

afterAll(async () => {
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
});

describe('💾 Endpoints de backups', () => {
  let nombreBackup = null;

  test('sin sesión devuelve 403', async () => {
    const res = await request(app).get('/api/admin/backups');
    expect(res.status).toBe(403);
  });

  test('lista backups como array', async () => {
    const res = await agent.get('/api/admin/backups');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.backups)).toBe(true);
  });

  test('crear backup manual', async () => {
    const res = await agent.post('/api/admin/backups/crear');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.nombre).toMatch(/^proveedores_\d{4}-\d{2}-\d{2}_\d{4}\.db$/);
    nombreBackup = res.body.nombre;
  });

  test('el backup creado aparece en la lista', async () => {
    const res = await agent.get('/api/admin/backups');
    expect(res.body.backups.some(b => b.nombre === nombreBackup)).toBe(true);
  });

  test('verificar integridad del backup', async () => {
    const res = await agent.get(`/api/admin/backups/${nombreBackup}/verificar`);
    expect(res.status).toBe(200);
    expect(res.body.integro).toBe(true);
    expect(res.body.conteos.usuarios).toBeGreaterThanOrEqual(1);
  });

  test('descargar backup como adjunto', async () => {
    const res = await agent.get(`/api/admin/backups/${nombreBackup}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toContain('attachment');
    expect(res.headers['content-type']).toContain('application/octet-stream');
  });

  test('rechaza nombres inválidos (anti path-traversal)', async () => {
    const res = await agent.get('/api/admin/backups/..%2F..%2Fetc/verificar');
    expect(res.status).toBe(400);
  });

  // 📌 /restaurar NO se prueba en unitarios: cierra la BD y ejecuta process.exit(0)
  // (reinicio intencional en Railway). Ese flujo se valida manual/E2E en staging.
});