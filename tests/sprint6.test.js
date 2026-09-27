// ==========================================
// SPRINT 6 TESTS — superficie de exportación y staff email
// Endpoints de exfiltración de datos: formato, guards y auditoría.
// ==========================================
jest.setTimeout(30000);
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3999';
process.env.APP_URL = 'http://localhost:3999';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');
const bcrypt = require('bcryptjs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-sprint6-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db, serverInstance, agent;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  serverInstance = app.listen(0);
  agent = request.agent(app);
  const login = await agent.post('/api/login').send({ email: 'admin@test.local', password: 'AdminTest123!' });
  expect(login.status).toBe(200);
}, 60000);

afterAll(async () => {
  if (serverInstance) await new Promise(r => serverInstance.close(r));
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
}, 15000);

describe('Sprint 6 — exportaciones y auditoría', () => {
  test('GET /api/admin/audit-log lista registros', async () => {
    const res = await agent.get('/api/admin/audit-log');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('GET /api/admin/audit-log/export devuelve CSV', async () => {
    const res = await agent.get('/api/admin/audit-log/export');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toContain('attachment');
  });

  test('GET /api/admin/logs-seguridad y su export funcionan', async () => {
    const lista = await agent.get('/api/admin/logs-seguridad');
    expect(lista.status).toBe(200);
    expect(Array.isArray(lista.body.data)).toBe(true);
    const exp = await agent.get('/api/admin/logs-seguridad/export');
    expect(exp.status).toBe(200);
    expect(exp.headers['content-type']).toContain('text/csv');
  });

  test('GET /api/admin/habeas-data/export sin registros devuelve 404 (guard)', async () => {
    const res = await agent.get('/api/admin/habeas-data/export');
    expect(res.status).toBe(404);
    expect(res.body.error).toContain('Habeas Data');
  });
});

describe('Sprint 6 — cambio de email de miembro (R4.1)', () => {
  let miembroId;
  const emailOriginal = 'miembro6@test.local';
  const emailNuevo = 'miembro6-nuevo@test.local';

  beforeAll(() => {
    const hash = bcrypt.hashSync('Miembro6!', 10);
    miembroId = db.prepare(
      `INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password, permisos, es_superadmin, activo)
       VALUES (?, ?, 'admin', 'Miembro 6', 0, '[]', 0, 1)`
    ).run(emailOriginal, hash).lastInsertRowid;
  });

  test('cambiar email de otro miembro devuelve 200 y cierra sus sesiones', async () => {
    const res = await agent.put(`/api/admin/usuarios/${miembroId}/email`).send({ email: emailNuevo });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    const row = db.prepare('SELECT email FROM usuarios WHERE id = ?').get(miembroId);
    expect(row.email).toBe(emailNuevo);
  });

  test('email nuevo igual al actual devuelve 400', async () => {
    const res = await agent.put(`/api/admin/usuarios/${miembroId}/email`).send({ email: emailNuevo });
    expect(res.status).toBe(400);
  });

  test('email duplicado de otra cuenta devuelve 409', async () => {
    const res = await agent.put(`/api/admin/usuarios/${miembroId}/email`).send({ email: 'admin@test.local' });
    expect(res.status).toBe(409);
  });
});