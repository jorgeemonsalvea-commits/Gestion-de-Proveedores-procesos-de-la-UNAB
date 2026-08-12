// ==========================================
// 📦 TESTS: CICLOS / HISTÓRICOS / ZIP
// ==========================================
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3995';
process.env.APP_URL = 'http://localhost:3995';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const { cifrarArchivo } = require('../security');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-ciclos-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db, agent, provId, cicloId;
const NUM_REG = 'CICLO-TEST-001';

function crearProveedorDB(email, etapa) {
  const hash = bcrypt.hashSync('Proveedor2026!', 10);
  const u = db.prepare(`INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password)
    VALUES (?, ?, 'proveedor', ?, 0)`).run(email, hash, 'Prov ' + email);
  return db.prepare(`INSERT INTO proveedores (usuario_id, razon_social, rfc, etapa, tipo_proveedor)
    VALUES (?, ?, '900123', ?, 'juridica')`).run(u.lastInsertRowid, 'Razon ' + email, etapa).lastInsertRowid;
}

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  agent = request.agent(app);
  const login = await agent.post('/api/login').send({ email: 'admin@test.local', password: 'AdminTest123!' });
  if (login.status !== 200) throw new Error('Login admin falló');

  // Setup directo: proveedor registrado + ciclo activo + documento aprobado con archivo físico
  provId = crearProveedorDB('prov-ciclos@test.com', 'registrado');
  cicloId = db.prepare(`INSERT INTO ciclos_actualizacion (proveedor_id, numero_registro, estado)
    VALUES (?, ?, 'activo')`).run(provId, NUM_REG).lastInsertRowid;
  const enc = cifrarArchivo(Buffer.from('%PDF-1.4\ntest\n%%EOF'), process.env.ENCRYPTION_KEY);
  const carpeta = path.join(dataDir, 'uploads', String(provId));
  fs.mkdirSync(carpeta, { recursive: true });
  const nombre = 'rut_123_abcd.enc';
  fs.writeFileSync(path.join(carpeta, nombre), enc);
  db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, ciclo, es_historico)
    VALUES (?, 'rut', ?, 'rut.pdf', 'aprobado', ?, 0)`).run(provId, `${provId}/${nombre}`, NUM_REG);
});

afterAll(async () => {
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
});

describe('📦 Ciclos e históricos', () => {
  test('sin sesión devuelve 403', async () => {
    const res = await request(app).get('/api/admin/ciclos');
    expect(res.status).toBe(403);
  });

  test('lista ciclos con el ciclo creado', async () => {
    const res = await agent.get('/api/admin/ciclos');
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    expect(res.body.data.some(c => c.numero_registro === NUM_REG)).toBe(true);
  });

  test('filtro por estado excluye correctamente', async () => {
    const res = await agent.get('/api/admin/ciclos?estado=cerrado');
    expect(res.status).toBe(200);
    expect(res.body.data.every(c => c.estado === 'cerrado')).toBe(true);
  });

  test('devuelve años disponibles', async () => {
    const res = await agent.get('/api/admin/ciclos/anos');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
  });

  test('documentos del ciclo', async () => {
    const res = await agent.get(`/api/admin/ciclos/${cicloId}/documentos`);
    expect(res.status).toBe(200);
    expect(res.body.ciclo.numero_registro).toBe(NUM_REG);
    expect(res.body.documentos.length).toBe(1);
  });

  test('documentos de ciclo inexistente → 404', async () => {
    const res = await agent.get('/api/admin/ciclos/999999/documentos');
    expect(res.status).toBe(404);
  });

  test('ZIP del ciclo se genera', async () => {
    const res = await agent.get(`/api/admin/ciclos/${cicloId}/zip`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('zip');
  });

  test('ZIP de ciclo inexistente → 404', async () => {
    const res = await agent.get('/api/admin/ciclos/999999/zip');
    expect(res.status).toBe(404);
  });
});