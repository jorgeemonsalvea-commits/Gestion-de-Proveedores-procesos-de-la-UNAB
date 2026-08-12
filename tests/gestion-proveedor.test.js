// ==========================================
// 🧾 TESTS: GESTIÓN (tipo persona, evaluación, notas, recordatorios)
// ==========================================
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3993';
process.env.APP_URL = 'http://localhost:3993';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');
const bcrypt = require('bcryptjs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-gestion-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

const PDF_VALIDO = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n');

let app, db, agent, provLibre, provConDocs, provEval, provNoAprobacion;

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

  provLibre = crearProveedorDB('prov-libre@test.com', 'verificacion');
  provConDocs = crearProveedorDB('prov-condocs@test.com', 'verificacion');
  provEval = crearProveedorDB('prov-eval@test.com', 'aprobacion');
  provNoAprobacion = crearProveedorDB('prov-noaprob@test.com', 'verificacion');
  db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, es_historico)
    VALUES (?, 'rut', 'x.enc', 'rut.pdf', 'pendiente', 0)`).run(provConDocs);
  db.prepare(`INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, es_historico)
    VALUES (?, 'rut', 'y.enc', 'rut.pdf', 'pendiente', 0)`).run(provEval);
});

afterAll(async () => {
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
});

describe('🧾 Gestión de proveedor', () => {
  test('tipo-persona inválido → 400', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provLibre}/tipo-persona`).send({ tipo_proveedor: 'otro' });
    expect(res.status).toBe(400);
  });

  test('definir tipo-persona sin documentos → ok', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provLibre}/tipo-persona`).send({ tipo_proveedor: 'natural' });
    expect(res.status).toBe(200);
    const p = db.prepare('SELECT tipo_proveedor FROM proveedores WHERE id = ?').get(provLibre);
    expect(p.tipo_proveedor).toBe('natural');
  });

  test('cambio de tipo con documentos activos → 409 sin forzar', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provConDocs}/tipo-persona`).send({ tipo_proveedor: 'natural' });
    expect(res.status).toBe(409);
    expect(res.body.requiere_confirmacion).toBe(true);
  });

  test('cambio de tipo forzado → ok', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provConDocs}/tipo-persona`).send({ tipo_proveedor: 'natural', forzar: true });
    expect(res.status).toBe(200);
  });

  test('subir evaluación fuera de aprobación → 400', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provNoAprobacion}/evaluacion`)
      .attach('archivo', PDF_VALIDO, { filename: 'eval.pdf', contentType: 'application/pdf' });
    expect(res.status).toBe(400);
  });

  test('subir evaluación en aprobación → ok y queda pendiente', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provEval}/evaluacion`)
      .attach('archivo', PDF_VALIDO, { filename: 'eval.pdf', contentType: 'application/pdf' });
    expect(res.status).toBe(200);
    const get = await agent.get(`/api/admin/proveedor/${provEval}/evaluacion`);
    expect(get.body.evaluacion_estado).toBe('pendiente');
  });

  test('aprobar evaluación con documentos pendientes → 400', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provEval}/evaluacion/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(400);
  });

  test('rechazar evaluación → proveedor pasa a rechazado', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provEval}/evaluacion/estado`).send({ estado: 'rechazado', comentario: 'Prueba' });
    expect(res.status).toBe(200);
    const p = db.prepare('SELECT etapa FROM proveedores WHERE id = ?').get(provEval);
    expect(p.etapa).toBe('rechazado');
  });

  test('reiniciar proceso desde rechazado → vuelve a verificación', async () => {
    const res = await agent.post(`/api/admin/proveedor/${provEval}/reiniciar-proceso`);
    expect(res.status).toBe(200);
    const p = db.prepare('SELECT etapa FROM proveedores WHERE id = ?').get(provEval);
    expect(p.etapa).toBe('verificacion');
  });

  test('nota sin contenido → 400; nota válida → ok y aparece en lista', async () => {
    const bad = await agent.post(`/api/admin/proveedor/${provLibre}/nota`).send({ titulo: 'T' });
    expect(bad.status).toBe(400);
    const ok = await agent.post(`/api/admin/proveedor/${provLibre}/nota`).send({ titulo: 'Nota', nota: 'Detalle de prueba' });
    expect(ok.status).toBe(200);
    const lista = await agent.get(`/api/admin/proveedor/${provLibre}/notas`);
    expect(lista.body.length).toBeGreaterThanOrEqual(1);
  });

  test('recordatorio sin mensaje → 400; válido → ok', async () => {
    const bad = await agent.post(`/api/admin/proveedor/${provLibre}/recordatorio`).send({});
    expect(bad.status).toBe(400);
    const ok = await agent.post(`/api/admin/proveedor/${provLibre}/recordatorio`).send({ mensaje: 'Sube tus documentos' });
    expect(ok.status).toBe(200);
  });

  test('gestión con tipo_gestion inválido → 400; válido → ok', async () => {
    const bad = await agent.post(`/api/admin/proveedor/${provLibre}/gestion`)
      .send({ numero_registro: 'X', tipo_gestion: 'invalido' });
    expect(bad.status).toBe(400);
    const ok = await agent.post(`/api/admin/proveedor/${provLibre}/gestion`)
      .send({ numero_registro: 'Fecha Movimiento 01012026', tipo_gestion: 'inscripcion', notas_gestion: 'ok' });
    expect(ok.status).toBe(200);
  });
});