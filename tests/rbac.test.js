// ==========================================
// 🛡️ TESTS: RBAC COMPOSABLE (Sprint 8 R5)
// 403 cruzados por perfil · candados D8 · filtro revisor (D6)
// [INC-002] El perfil visualizador (docs.ver sin claves de acción) ve TODAS
// las etapas en modo lectura (listado, detalle, ZIP, ciclos/historial).
// Las ESCRITURAS siguen bloqueadas por clave (docs.verificar/aprobar/...).
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
const bcrypt = require('bcryptjs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-rbac-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let app, db;
let agentSuper, agentVerif, agentAprob, agentRevisor;
let provRegistrado, provVerificacion, docVerificado, cicloVerificacion, superId, verifId;

// Admin de prueba con catálogo concreto (es_superadmin=0: el backfill ya corrió al arranque)
function crearAdminDB(email, permisos) {
  const hash = bcrypt.hashSync('Perfil2026!', 10);
  return db.prepare(
    `INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password, permisos, es_superadmin, activo) VALUES (?, ?, 'admin', ?, 0, ?, 0, 1)`
  ).run(email, hash, 'Perfil ' + email, JSON.stringify(permisos)).lastInsertRowid;
}

function crearProveedorDB(email, etapa) {
  const hash = bcrypt.hashSync('Proveedor2026!', 10);
  const u = db.prepare(
    `INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password) VALUES (?, ?, 'proveedor', ?, 0)`
  ).run(email, hash, 'Prov ' + email);
  return db.prepare(
    `INSERT INTO proveedores (usuario_id, razon_social, rfc, etapa, tipo_proveedor) VALUES (?, ?, '900123', ?, 'juridica')`
  ).run(u.lastInsertRowid, 'Razon ' + email, etapa).lastInsertRowid;
}

async function loginAgent(email, password) {
  const a = request.agent(app);
  const r = await a.post('/api/login').send({ email, password });
  if (r.status !== 200) throw new Error('Login falló para ' + email);
  return a;
}

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  agentSuper = await loginAgent('admin@test.local', 'AdminTest123!');
  verifId = crearAdminDB('verificador@test.local', ['docs.ver', 'docs.verificar']);
  crearAdminDB('aprobador@test.local', ['docs.ver', 'docs.aprobar', 'docs.rechazar']);
  crearAdminDB('revisor@test.local', ['docs.ver']);
  superId = db.prepare(`SELECT id FROM usuarios WHERE email = 'admin@test.local'`).get().id;
  provRegistrado = crearProveedorDB('prov-registrado@test.com', 'registrado');
  provVerificacion = crearProveedorDB('prov-verificacion@test.com', 'verificacion');
  docVerificado = db.prepare(
    `INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, verificado) VALUES (?, 'rut', 'rut_rbac.enc', 'rut.pdf', 'pendiente', 1)`
  ).run(provVerificacion).lastInsertRowid;
  // [INC-002] Ciclo del proveedor en verificación: permite probar que el
  // visualizador ve el HISTORIAL (ciclos) de proveedores en cualquier etapa.
  cicloVerificacion = db.prepare(
    `INSERT INTO ciclos_actualizacion (proveedor_id, numero_registro, estado, fecha_inicio) VALUES (?, 'REG-RBAC-3G', 'cerrado', datetime('now', '-30 days'))`
  ).run(provVerificacion).lastInsertRowid;
  agentVerif = await loginAgent('verificador@test.local', 'Perfil2026!');
  agentAprob = await loginAgent('aprobador@test.local', 'Perfil2026!');
  agentRevisor = await loginAgent('revisor@test.local', 'Perfil2026!');
}, 60000);

afterAll(async () => {
  try { if (db && typeof db.close === 'function') db.close(); } catch (e) {}
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {}
}, 15000);

describe('🛡️ RBAC composable (Sprint 8 R5)', () => {
  test('/api/me expone permisos y es_superadmin del superadmin', async () => {
    const res = await agentSuper.get('/api/me');
    expect(res.status).toBe(200);
    expect(res.body.es_superadmin).toBe(true);
    expect(Array.isArray(res.body.permisos)).toBe(true);
  });

  test('/api/me expone el catálogo del perfil verificador', async () => {
    const res = await agentVerif.get('/api/me');
    expect(res.status).toBe(200);
    expect(res.body.es_superadmin).toBe(false);
    expect(res.body.permisos).toContain('docs.verificar');
    expect(res.body.permisos).not.toContain('docs.aprobar');
  });

  test('verificador NO puede aprobar (403 + requiere_permiso)', async () => {
    const res = await agentVerif.post(`/api/admin/documento/${docVerificado}/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(403);
    expect(res.body.requiere_permiso).toBe('docs.aprobar');
  });

  test('aprobador SÍ puede aprobar documento verificado (200)', async () => {
    const res = await agentAprob.post(`/api/admin/documento/${docVerificado}/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(200);
  });

  // [INC-002] ANTES: "revisor solo ve proveedores en etapa registrado".
  // AHORA: el visualizador con docs.ver ve TODAS las etapas (solo lectura).
  test('[INC-002] revisor con docs.ver ve proveedores de todas las etapas', async () => {
    const res = await agentRevisor.get('/api/admin/proveedores');
    expect(res.status).toBe(200);
    const etapas = res.body.data.map(p => p.etapa);
    expect(etapas).toContain('registrado');
    expect(etapas).toContain('verificacion');
  });

  // [INC-002] ANTES: 403 en detalle de proveedor en verificación. AHORA: 200.
  test('[INC-002] revisor 200 en detalle de proveedor en verificación', async () => {
    const res = await agentRevisor.get(`/api/admin/proveedor/${provVerificacion}`);
    expect(res.status).toBe(200);
    expect(res.body.proveedor.etapa).toBe('verificacion');
  });

  test('revisor 200 en detalle de proveedor registrado', async () => {
    const res = await agentRevisor.get(`/api/admin/proveedor/${provRegistrado}`);
    expect(res.status).toBe(200);
  });

  // [INC-002] ANTES: 403 en ZIP de proveedor en verificación. AHORA: 200.
  test('[INC-002] revisor descarga ZIP de proveedor en verificación (sin 403 de etapa)', async () => {
    const res = await agentRevisor.get(`/api/admin/proveedor/${provVerificacion}/documentos/zip`);
    expect(res.status).toBe(200);
  });

    // [INC-002 FIX-2] La evaluación activa no tiene fila en documentos:
  // se referencia por proveedores.evaluacion_inicial. El visualizador debe poder verla.
  test('[INC-002 FIX-2] revisor ve la evaluación inicial referenciada (uploads 200)', async () => {
    const rel = `${provVerificacion}/evaluacion_rbac.enc`;
    const dir = path.join(dataDir, 'uploads', String(provVerificacion));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'evaluacion_rbac.enc'), '%PDF-1.4 dummy');
    db.prepare(`UPDATE proveedores SET evaluacion_inicial = ? WHERE id = ?`).run(rel, provVerificacion);
    const res = await agentRevisor.get(`/uploads/${rel}`);
    expect(res.status).toBe(200);
  });

  test('[INC-002 FIX-2] revisor 403 en evaluación NO referenciada (huérfana)', async () => {
    const rel = `${provVerificacion}/evaluacion_huerfana.enc`;
    const dir = path.join(dataDir, 'uploads', String(provVerificacion));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'evaluacion_huerfana.enc'), '%PDF-1.4 dummy');
    const res = await agentRevisor.get(`/uploads/${rel}`);
    expect(res.status).toBe(403);
  });

  // [INC-002] NUEVO: el historial (ciclos) de proveedores en verificación
  // es visible para el visualizador (caso exacto del reporte de producción).
  test('[INC-002] revisor ve ciclos (historial) de proveedores en verificación', async () => {
    const res = await agentRevisor.get('/api/admin/ciclos');
    expect(res.status).toBe(200);
    const provs = res.body.data.map(c => c.proveedor_id);
    expect(provs).toContain(provVerificacion);
  });

  // [INC-002] NUEVO: la lectura ampliada NO concede escritura.
  test('[INC-002] revisor con docs.ver NO puede aprobar (escritura sigue bloqueada)', async () => {
    const res = await agentRevisor.post(`/api/admin/documento/${docVerificado}/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(403);
    expect(res.body.requiere_permiso).toBe('docs.aprobar');
  });

  // [INC-002] NUEVO: no relajamos el gate de ruta: sin docs.ver sigue 403.
  test('[INC-002] admin SIN docs.ver sigue sin listar proveedores (403 de ruta)', async () => {
    crearAdminDB('sinpermisos@test.local', []);
    const agentSin = await loginAgent('sinpermisos@test.local', 'Perfil2026!');
    const res = await agentSin.get('/api/admin/proveedores');
    expect(res.status).toBe(403);
  });

  test('revisor 403 en Auditoría (actividad)', async () => {
    const res = await agentRevisor.get('/api/admin/actividad');
    expect(res.status).toBe(403);
  });

  test('revisor 403 en Equipo (usuarios) — clave reservada', async () => {
    const res = await agentRevisor.get('/api/admin/usuarios');
    expect(res.status).toBe(403);
  });

  test('D8: superadmin no puede cambiar sus propios permisos (409)', async () => {
    const res = await agentSuper.put(`/api/admin/usuarios/${superId}/permisos`).send({ permisos: ['docs.ver'] });
    expect(res.status).toBe(409);
  });

  test('D8: superadmin no puede desactivarse a sí mismo (409)', async () => {
    const res = await agentSuper.put(`/api/admin/usuarios/${superId}/activo`).send({ activo: 0 });
    expect(res.status).toBe(409);
  });

  test('cambiar permisos de un miembro cierra su sesión (200 → 403)', async () => {
    const res = await agentSuper.put(`/api/admin/usuarios/${verifId}/permisos`).send({ permisos: ['docs.ver'] });
    expect(res.status).toBe(200);
    expect(res.body.sesiones_cerradas).toBeGreaterThanOrEqual(1);
    const after = await agentVerif.get('/api/admin/proveedores');
    // Las rutas /api/admin/* responden 403 sin sesión (diseño existente, ver auth.test.js).
    // 403 aquí PRUEBA que la sesión fue destruida por el cambio de permisos.
    expect(after.status).toBe(403);
  });

  test('superadmin puede promover y degradar a otro admin (200/200)', async () => {
    const up = await agentSuper.put(`/api/admin/usuarios/${verifId}/superadmin`).send({ es_superadmin: 1 });
    expect(up.status).toBe(200);
    expect(db.prepare(`SELECT es_superadmin FROM usuarios WHERE id = ?`).get(verifId).es_superadmin).toBe(1);
    const down = await agentSuper.put(`/api/admin/usuarios/${verifId}/superadmin`).send({ es_superadmin: 0 });
    expect(down.status).toBe(200);
    expect(db.prepare(`SELECT es_superadmin FROM usuarios WHERE id = ?`).get(verifId).es_superadmin).toBe(0);
  });
});