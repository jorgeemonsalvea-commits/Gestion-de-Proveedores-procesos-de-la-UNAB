// ==========================================
// 📄 TESTS: FLUJO DE DOCUMENTOS (admin)
// Subida → verificación → aprobación / rechazo + validaciones de archivo
// ==========================================
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3996';
process.env.APP_URL = 'http://localhost:3996';

const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-docs-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

// PDF mínimo con magic bytes válidos (%PDF-)
const PDF_VALIDO = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n');
// Archivo .pdf con cabecera incorrecta
const PDF_INVALIDO = Buffer.from('ESTO NO ES UN PDF REAL');

let app, db, agent, proveedorId, docRut, docCamara;

beforeAll(async () => {
  const serverModule = require('../server');
  app = serverModule.app;
  db = serverModule.db;
  agent = request.agent(app);
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

describe('📄 Flujo de documentos (admin)', () => {
  test('crear proveedor de prueba', async () => {
    const res = await agent.post('/api/admin/proveedor').send({
      email: 'prov-test@empresa.com',
      password: 'Proveedor2026!',
      nombre_empresa: 'Proveedor Test SA',
      razon_social: 'Proveedor Test SA',
      rfc: '900123456',
      tipo_proveedor: 'juridica'
    });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    proveedorId = res.body.proveedorId;
    await new Promise(r => setTimeout(r, 300)); // espera a que Brevo termine
  });

  test('rechaza archivo que no es PDF', async () => {
    const res = await agent
      .post(`/api/admin/proveedor/${proveedorId}/documento`)
      .field('tipo', 'rut')
      .attach('archivo', Buffer.from('texto plano'), { filename: 'nota.txt', contentType: 'text/plain' });
    expect(res.status).toBe(400);
  });

  test('rechaza PDF con cabecera inválida (magic bytes)', async () => {
    const res = await agent
      .post(`/api/admin/proveedor/${proveedorId}/documento`)
      .field('tipo', 'rut')
      .attach('archivo', PDF_INVALIDO, { filename: 'falso.pdf', contentType: 'application/pdf' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('PDF válido');
  });

  test('sube PDF válido como admin', async () => {
    const res = await agent
      .post(`/api/admin/proveedor/${proveedorId}/documento`)
      .field('tipo', 'rut')
      .attach('archivo', PDF_VALIDO, { filename: 'rut.pdf', contentType: 'application/pdf' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('el documento queda pendiente y sin verificar', async () => {
    const res = await agent.get(`/api/admin/proveedor/${proveedorId}`);
    expect(res.status).toBe(200);
    docRut = res.body.documentos.find(d => d.tipo === 'rut');
    expect(docRut).toBeTruthy();
    expect(docRut.estado).toBe('pendiente');
    expect(docRut.verificado).toBe(0);
    // El archivo se guarda cifrado (.enc)
    expect(docRut.archivo).toMatch(/\.enc$/);
  });

  test('no se puede aprobar sin verificar antes', async () => {
    const res = await agent.post(`/api/admin/documento/${docRut.id}/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(400);
  });

  test('verificar documento', async () => {
    const res = await agent.post(`/api/admin/documento/${docRut.id}/verificar`).send({ verificado: true });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('aprobar documento asigna fecha de vencimiento', async () => {
    const res = await agent.post(`/api/admin/documento/${docRut.id}/estado`).send({ estado: 'aprobado' });
    expect(res.status).toBe(200);
    const prov = await agent.get(`/api/admin/proveedor/${proveedorId}`);
    const doc = prov.body.documentos.find(d => d.id === docRut.id);
    expect(doc.estado).toBe('aprobado');
    expect(doc.fecha_vencimiento).toBeTruthy();
  });

  test('rechazar otro documento con comentario', async () => {
    const up = await agent
      .post(`/api/admin/proveedor/${proveedorId}/documento`)
      .field('tipo', 'camara_comercio')
      .attach('archivo', PDF_VALIDO, { filename: 'camara.pdf', contentType: 'application/pdf' });
    expect(up.status).toBe(200);
    const prov = await agent.get(`/api/admin/proveedor/${proveedorId}`);
    docCamara = prov.body.documentos.find(d => d.tipo === 'camara_comercio');
    const res = await agent.post(`/api/admin/documento/${docCamara.id}/estado`)
      .send({ estado: 'rechazado', comentario: 'Documento ilegible' });
    expect(res.status).toBe(200);
    const prov2 = await agent.get(`/api/admin/proveedor/${proveedorId}`);
    const doc = prov2.body.documentos.find(d => d.id === docCamara.id);
    expect(doc.estado).toBe('rechazado');
    expect(doc.comentario).toContain('Documento ilegible');
  });
});