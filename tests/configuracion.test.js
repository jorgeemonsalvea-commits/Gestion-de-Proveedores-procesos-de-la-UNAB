// ==========================================
// ⚙️ TESTS: CONFIGURACIÓN + VENCIMIENTOS
// ==========================================
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3994';
process.env.APP_URL = 'http://localhost:3994';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');
const bcrypt = require('bcryptjs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-config-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db, agent, provRecalc, provVenc, provForzar, docRecalc, docVenc, docForzar;

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

  provRecalc = crearProveedorDB('prov-recalc@test.com', 'inscripcion');
  provVenc = crearProveedorDB('prov-venc@test.com', 'inscripcion');
  provForzar = crearProveedorDB('prov-forzar@test.com', 'verificacion');
  
  // Crear archivos dummy en disco para que moverDocumentoAHistorico pueda moverlos
  const uploadsDir = path.join(dataDir, 'uploads');
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
  
  const archivos = ['no_aplica_x.enc', 'no_aplica_y.enc', 'no_aplica_z.enc'];
  archivos.forEach(nombre => {
    fs.writeFileSync(path.join(uploadsDir, nombre), Buffer.from('dummy content'));
  });
  
  docRecalc = db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, es_historico)
    VALUES (?, 'rut', 'no_aplica_x.enc', 'rut.pdf', 'aprobado', 0)`).run(provRecalc).lastInsertRowid;
  docVenc = db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, es_historico, fecha_vencimiento)
    VALUES (?, 'rut', 'no_aplica_y.enc', 'rut.pdf', 'aprobado', 0, '2020-01-01 00:00:00')`).run(provVenc).lastInsertRowid;
  docForzar = db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, es_historico)
    VALUES (?, 'rut', 'no_aplica_z.enc', 'rut.pdf', 'pendiente', 0)`).run(provForzar).lastInsertRowid;
});

describe('⚙️ Configuración y vencimientos', () => {
  test('obtener configuración actual', async () => {
    const res = await agent.get('/api/admin/configuracion');
    expect(res.status).toBe(200);
    expect(res.body.clave).toBe('fecha_vencimiento_fija');
  });

  test('PUT sin valor → 400', async () => {
    const res = await agent.put('/api/admin/configuracion').send({});
    expect(res.status).toBe(400);
  });

  test('PUT con formato inválido → 400', async () => {
    const res = await agent.put('/api/admin/configuracion').send({ valor: 'no-es-fecha' });
    expect(res.status).toBe(400);
  });

  test('PUT válido actualiza la fecha fija', async () => {
    const res = await agent.put('/api/admin/configuracion').send({ valor: '2027-06-30T23:59' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    const get = await agent.get('/api/admin/configuracion');
    expect(get.body.valor.startsWith('2027-06-30 23:59')).toBe(true);
  });

  // 🔄 EJECUTAR VENCIMIENTOS (antes de recalcular, para que el documento siga vencido)
  test('ejecutar vencimientos mueve documentos vencidos a histórico', async () => {
    const res = await agent.post('/api/admin/ejecutar-vencimientos');
    expect(res.status).toBe(200);
    expect(res.body.movidos).toBeGreaterThanOrEqual(1);
    const doc = db.prepare('SELECT es_historico, estado FROM documentos WHERE id = ?').get(docVenc);
    expect(doc.es_historico).toBe(1);
    expect(doc.estado).toBe('rechazado');
  });

  // 🔄 RECALCULAR VENCIMIENTOS (después, ya no afecta al documento vencido)
  test('recalcular vencimientos asigna fecha a aprobados sin fecha', async () => {
    const res = await agent.post('/api/admin/recalcular-vencimientos');
    expect(res.status).toBe(200);
    expect(res.body.actualizados).toBeGreaterThanOrEqual(1);
    const doc = db.prepare('SELECT fecha_vencimiento FROM documentos WHERE id = ?').get(docRecalc);
    expect(doc.fecha_vencimiento).toBeTruthy();
  });

  test('forzar vencimientos archiva todos los activos', async () => {
    const res = await agent.post('/api/admin/forzar-vencimientos');
    expect(res.status).toBe(200);
    const doc = db.prepare('SELECT es_historico FROM documentos WHERE id = ?').get(docForzar);
    expect(doc.es_historico).toBe(1);
  });
});