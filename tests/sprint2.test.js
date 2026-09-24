// ==========================================
// SPRINT 2 TESTS
// Backups + plantillas + validaciones
// ==========================================

jest.setTimeout(30000);

process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3991';
process.env.APP_URL = 'http://localhost:3991';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-sprint2-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let serverInstance = null;
let db = null;
let app = null;
let agent = null;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;

  serverInstance = app.listen(0);
  agent = request.agent(app);

  const login = await agent
    .post('/api/login')
    .send({
      email: 'admin@test.local',
      password: 'AdminTest123!'
    });

  if (login.status !== 200) {
    throw new Error('No se pudo loguear el admin de prueba');
  }
});

afterAll(async () => {
  if (serverInstance) {
    await new Promise(resolve => serverInstance.close(resolve));
  }

  try {
    if (db && typeof db.close === 'function') {
      db.close();
    }
  } catch (e) {
    // ignorar
  }

  try {
    fs.rmSync(dataDir, { recursive: true, force: true });
  } catch (e) {
    // ignorar
  }
});

describe('Sprint 2 — Backups seguros', () => {
  test('restaurar backup sin contraseña devuelve 400', async () => {
    const res = await agent
      .post('/api/admin/backups/proveedores_fake.db/restaurar')
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Contraseña requerida');
  });

  test('restaurar backup con contraseña incorrecta devuelve 403', async () => {
    const res = await agent
      .post('/api/admin/backups/proveedores_fake.db/restaurar')
      .send({ password: 'ClaveIncorrecta123!' });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Contraseña incorrecta');
  });
});

describe('Sprint 2 — Plantillas seguras', () => {
  test('rechaza plantilla XLSX falsa', async () => {
    const res = await agent
      .post('/api/admin/plantilla')
      .field('tipo', 'rut')
      .attach('archivo', Buffer.from('esto no es un xlsx real'), {
        filename: 'falso.xlsx',
        contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });

    expect(res.status).toBe(400);
  });
});