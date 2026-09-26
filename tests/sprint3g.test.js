// ==========================================
// SPRINT 3G TESTS (parte A)
// Consolidación staff + dry_run forzar vencimientos
// ==========================================
jest.setTimeout(30000);
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3992';
process.env.APP_URL = 'http://localhost:3992';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');
const bcrypt = require('bcryptjs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-sprint3g-test-'));
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
    .send({ email: 'admin@test.local', password: 'AdminTest123!' });
  if (login.status !== 200) {
    throw new Error('No se pudo loguear el admin de prueba');
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

describe('Sprint 3G — staff consolidado', () => {
  test('GET /api/admin/usuarios devuelve catálogo del bloque consolidado', async () => {
    const res = await agent.get('/api/admin/usuarios');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    // Solo el bloque V2 (consolidado) envía el catálogo R4:
    expect(Array.isArray(res.body.catalogo)).toBe(true);
    expect(res.body.catalogo.length).toBeGreaterThan(0);
  });

  test('promover a superadmin un miembro INACTIVO devuelve 409 (candado D8 de V2)', async () => {
    const hash = bcrypt.hashSync('Inactivo3G!', 12);
    db.prepare('DELETE FROM usuarios WHERE email = ?').run('inactivo3g@test.local');
    const r = db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password, permisos, es_superadmin, activo)
      VALUES (?, ?, 'admin', 'Inactivo 3G', 0, '[]', 0, 0)
    `).run('inactivo3g@test.local', hash);

    const res = await agent
      .put(`/api/admin/usuarios/${r.lastInsertRowid}/superadmin`)
      .send({ es_superadmin: 1 });

    expect(res.status).toBe(409);
    expect(res.body.error).toContain('Activa primero');
  });
});

describe('Sprint 3G — forzar vencimientos con dry_run', () => {
  test('dry_run cuenta sin archivar nada', async () => {
    const prov = await agent.post('/api/admin/proveedor').send({
      email: `prov-3g-${Date.now()}@test.com`,
      nombre_empresa: 'Prov 3G',
      razon_social: 'Prov 3G',
      rfc: '900333444',
      tipo_proveedor: 'juridica'
    });
    expect(prov.status).toBe(200);
    const pid = prov.body.proveedorId;

    const na = await agent
      .post(`/api/admin/proveedor/${pid}/documento/0/no-aplica`)
      .send({ no_aplica: true, tipo: 'calidad' });
    expect(na.status).toBe(200);

    const dry = await agent
      .post('/api/admin/forzar-vencimientos')
      .send({ dry_run: true });

    expect(dry.status).toBe(200);
    expect(dry.body.dry_run).toBe(true);
    expect(dry.body.documentos).toBeGreaterThanOrEqual(1);

    // Nada se archivó:
    const detalle = await agent.get(`/api/admin/proveedor/${pid}`);
    const doc = detalle.body.documentos.find(d => d.tipo === 'calidad');
    expect(doc.es_historico).toBe(0);
  });
});