const request = require('supertest');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Variables de entorno de prueba
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3998';
process.env.APP_URL = 'http://localhost:3998';

// Directorio temporal único
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-auth-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let serverInstance = null;
let db = null;
let app = null;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  serverInstance = app.listen(0);

  // Crear admin de prueba
  const existe = db.prepare('SELECT id FROM usuarios WHERE email = ?').get('admin@test.local');
  if (!existe) {
    const hash = bcrypt.hashSync('AdminTest123!', 12);
    db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password)
      VALUES (?, ?, 'admin', 'Admin Test', 0)
    `).run('admin@test.local', hash);
  }
});

afterAll(async () => {
  if (serverInstance) {
    await new Promise(resolve => serverInstance.close(resolve));
  }
  try {
    if (db && typeof db.close === 'function') db.close();
  } catch (e) { /* ignorar */ }
  try {
    fs.rmSync(dataDir, { recursive: true, force: true });
  } catch (e) { /* ignorar */ }
});

describe('🔑 Endpoints de autenticación', () => {
  describe('POST /api/login', () => {
    test('rechaza credenciales inválidas', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ email: 'noexiste@test.com', password: 'Cualquiera123!' });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Credenciales inválidas');
    });

    test('admin entra con contraseña correcta', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ email: 'admin@test.local', password: 'AdminTest123!' });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.rol).toBe('admin');
    });

    test('valida formato de email', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ email: 'mal-formato', password: 'test' });
      expect(res.status).toBeGreaterThanOrEqual(400);
    });
  });

  describe('POST /api/recuperar-password', () => {
    test('responde 200 aunque el email no exista (anti-enumeración)', async () => {
      const res = await request(app)
        .post('/api/recuperar-password')
        .send({ email: 'inexistente@test.com' });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    test('rechaza email con formato inválido', async () => {
      const res = await request(app)
        .post('/api/recuperar-password')
        .send({ email: 'no-es-email' });
      expect(res.status).toBe(400);
    });
  });

  describe('Protección de rutas', () => {
    test('GET /api/me sin sesión devuelve usuario null', async () => {
      const res = await request(app).get('/api/me');
      expect(res.body.usuario).toBeNull();
    });

    test('GET /api/admin/proveedores sin sesión devuelve 403', async () => {
      const res = await request(app).get('/api/admin/proveedores');
      expect(res.status).toBe(403);
    });
  });
});