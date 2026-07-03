// ==========================================
// 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ==========================================
const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

// Usar volumen persistente en Railway, o local en desarrollo
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const db = new Database(path.join(dataDir, 'proveedores.db'));

// Optimizaciones de SQLite
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -64000');
db.pragma('busy_timeout = 5000');

console.log('🗄️  Base de datos inicializada');


// ==========================================
// 2. CREACIÓN DE TABLAS BASE
// ==========================================
console.log('📋 Verificando estructura de tablas...');

db.exec(`
  -- Tabla de usuarios (admin y proveedores)
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    rol TEXT NOT NULL CHECK(rol IN ('admin','proveedor')),
    nombre_empresa TEXT,
    debe_cambiar_password INTEGER DEFAULT 1,
    intentos_fallidos INTEGER DEFAULT 0,
    bloqueado_hasta DATETIME,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Tabla de proveedores
  CREATE TABLE IF NOT EXISTS proveedores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER UNIQUE NOT NULL,
    razon_social TEXT,
    rfc TEXT,
    representante TEXT,
    telefono TEXT,
    direccion TEXT,
    estado_general TEXT DEFAULT 'pendiente' CHECK(estado_general IN ('pendiente','aprobado','rechazado')),
    fecha_aprobacion DATETIME,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  -- Tabla de documentos
  CREATE TABLE IF NOT EXISTS documentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proveedor_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    archivo TEXT NOT NULL,
    nombre_original TEXT,
    hash_archivo TEXT,
    estado TEXT DEFAULT 'pendiente' CHECK(estado IN ('pendiente','aprobado','rechazado')),
    comentario TEXT,
    no_aplica INTEGER DEFAULT 0,
    subido_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );

  -- Tabla de plantillas
  CREATE TABLE IF NOT EXISTS plantillas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo TEXT UNIQUE NOT NULL,
    archivo TEXT NOT NULL,
    nombre_original TEXT,
    subido_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Tabla de historial de acciones
  CREATE TABLE IF NOT EXISTS historial (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proveedor_id INTEGER NOT NULL,
    usuario_id INTEGER,
    usuario_nombre TEXT,
    accion TEXT NOT NULL,
    detalle TEXT,
    documento_tipo TEXT,
    documento_id INTEGER,
    ip_origen TEXT,
    creado_en DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );

  -- Tabla de recordatorios
  CREATE TABLE IF NOT EXISTS recordatorios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proveedor_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    admin_nombre TEXT,
    mensaje TEXT NOT NULL,
    leido INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );

  -- Tabla de notas para proveedores
  CREATE TABLE IF NOT EXISTS notas_proveedor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proveedor_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    admin_nombre TEXT,
    titulo TEXT NOT NULL,
    nota TEXT NOT NULL,
    leida INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );

  -- Tabla de logs de seguridad
  CREATE TABLE IF NOT EXISTS logs_seguridad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    email TEXT,
    accion TEXT NOT NULL,
    ip_origen TEXT,
    user_agent TEXT,
    detalle TEXT,
    exitoso INTEGER,
    creado_en DATETIME DEFAULT (datetime('now','localtime'))
  );

 -- Tabla de consentimiento de Habeas Data
  CREATE TABLE IF NOT EXISTS habeas_data_consent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    aceptado INTEGER NOT NULL DEFAULT 0,
    fecha_aceptacion DATETIME,
    ip_origen TEXT,
    user_agent TEXT,
    version TEXT DEFAULT '1.0',
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_habeas_data_usuario ON habeas_data_consent(usuario_id, aceptado);
`);

console.log('✅ Estructura de tablas verificada');


// ==========================================
// 3. SISTEMA DE MIGRACIONES AUTOMÁTICAS
// ==========================================
console.log('🔄 Verificando migraciones...');

const migraciones = [
  { tabla: 'usuarios', campo: 'debe_cambiar_password', tipo: 'INTEGER DEFAULT 1' },
  { tabla: 'usuarios', campo: 'intentos_fallidos', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'usuarios', campo: 'bloqueado_hasta', tipo: 'DATETIME' },
  { tabla: 'proveedores', campo: 'fecha_aprobacion', tipo: 'DATETIME' },
  { tabla: 'documentos', campo: 'hash_archivo', tipo: 'TEXT' },
  { tabla: 'documentos', campo: 'no_aplica', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'historial', campo: 'ip_origen', tipo: 'TEXT' },
  { tabla: 'notas_proveedor', campo: 'leida', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'notas_proveedor', campo: 'cerrada', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'recordatorios', campo: 'cerrada', tipo: 'INTEGER DEFAULT 0' }
];

let migracionesAplicadas = 0;
let migracionesFallidas = 0;

migraciones.forEach(m => {
  try {
    const columnas = db.prepare(`PRAGMA table_info(${m.tabla})`).all();
    if (!columnas.some(c => c.name === m.campo)) {
      db.exec(`ALTER TABLE ${m.tabla} ADD COLUMN ${m.campo} ${m.tipo}`);
      console.log(`  ✅ ${m.tabla}.${m.campo}`);
      migracionesAplicadas++;
    }
  } catch (e) {
    console.log(`  ⚠️  ${m.tabla}.${m.campo}: ${e.message}`);
    migracionesFallidas++;
  }
});

if (migracionesAplicadas > 0) {
  console.log(`✅ ${migracionesAplicadas} migración(es) aplicada(s)`);
} else {
  console.log('✅ No se requieren migraciones');
}

if (migracionesFallidas > 0) {
  console.log(`⚠️  ${migracionesFallidas} migración(es) fallida(s)`);
}


// ==========================================
// 4. CREACIÓN DE ÍNDICES PARA OPTIMIZACIÓN
// ==========================================
console.log('📊 Verificando índices...');

const indices = [
  { nombre: 'idx_historial_prov', tabla: 'historial', columnas: 'proveedor_id, creado_en DESC' },
  { nombre: 'idx_historial_accion', tabla: 'historial', columnas: 'accion' },
  { nombre: 'idx_recordatorios_prov', tabla: 'recordatorios', columnas: 'proveedor_id, leido' },
  { nombre: 'idx_recordatorios_creado', tabla: 'recordatorios', columnas: 'creado_en DESC' },
  { nombre: 'idx_logs_seguridad_fecha', tabla: 'logs_seguridad', columnas: 'creado_en DESC' },
  { nombre: 'idx_logs_seguridad_usuario', tabla: 'logs_seguridad', columnas: 'usuario_id' },
  { nombre: 'idx_logs_seguridad_accion', tabla: 'logs_seguridad', columnas: 'accion' },
  { nombre: 'idx_documentos_proveedor', tabla: 'documentos', columnas: 'proveedor_id, tipo' },
  { nombre: 'idx_documentos_estado', tabla: 'documentos', columnas: 'estado' },
  { nombre: 'idx_notas_proveedor', tabla: 'notas_proveedor', columnas: 'proveedor_id, leida' },
  { nombre: 'idx_usuarios_email', tabla: 'usuarios', columnas: 'email' },
  { nombre: 'idx_proveedores_estado', tabla: 'proveedores', columnas: 'estado_general' },
  
];

let indicesCreados = 0;

indices.forEach(idx => {
  try {
    db.exec(`CREATE INDEX IF NOT EXISTS ${idx.nombre} ON ${idx.tabla}(${idx.columnas})`);
    indicesCreados++;
  } catch (e) {
    console.log(`  ⚠️  Índice ${idx.nombre}: ${e.message}`);
  }
});

console.log(`✅ ${indicesCreados} índices verificados`);


// ==========================================
// 5. CREACIÓN DE ADMIN POR DEFECTO
// ==========================================
const adminEmail = process.env.ADMIN_EMAIL || 'admin@empresa.com';
const adminPass = process.env.ADMIN_PASSWORD_INICIAL || 'Admin2024!';

const adminExistente = db.prepare('SELECT id FROM usuarios WHERE email = ?').get(adminEmail);

if (!adminExistente) {
  try {
    const hash = bcrypt.hashSync(adminPass, 12);
    db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password) 
      VALUES (?, ?, ?, ?, 1)
    `).run(adminEmail, hash, 'admin', 'Administración');
    
    console.log(`\n✅ Admin creado exitosamente`);
    console.log(`   📧 Email: ${adminEmail}`);
    console.log(`   🔑 Contraseña: ${adminPass}`);
    console.log(`   ⚠️  Deberás cambiar la contraseña al primer ingreso\n`);
  } catch (e) {
    console.error(`❌ Error creando admin: ${e.message}`);
  }
} else {
  console.log(`✅ Admin existente: ${adminEmail}`);
}


// ==========================================
// 6. CONFIGURACIÓN DE DOCUMENTOS REQUERIDOS
// ==========================================
const DOCUMENTOS_REQUERIDOS = [
  { tipo: 'gaf01', nombre: 'GAF04-01-FO-01 Abastacimiento de Bienes y Servicios V11', descripcion: 'Aba Bie Serv V1.1', esPlantilla: true, requiereFirma: true, requiereHuella: false, cantidadMin: 1 },
  { tipo: 'gaf07', nombre: 'GAF04-01-FO-07 Lavado de activos V2', descripcion: 'Lavado de activos V2', esPlantilla: true, requiereFirma: true, requiereHuella: true, cantidadMin: 1 },
  { tipo: 'gaf08', nombre: 'GAF04-01-FO-08 Declaración de Origen de Fondos V2', descripcion: 'Declaración origen de fondos V2', esPlantilla: true, requiereFirma: true, requiereHuella: true, cantidadMin: 1 },
  { tipo: 'rut', nombre: 'RUT', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'camara_comercio', nombre: 'Certificado Cámara de Comercio', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'cedula_rl', nombre: 'Fotocopia cédula de ciudadanía del Representante Legal', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'estados_financieros', nombre: 'Estados Financieros', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'parafiscales', nombre: 'Certificación de parafiscales', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'calidad', nombre: 'Certificación de calidad (si aplica)', esPlantilla: false, cantidadMin: 1, opcional: true },
  { tipo: 'sgsst', nombre: 'Certificación Seguridad y Salud en el Trabajo', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'experiencia', nombre: 'Certificados de experiencia comercial (mínimo 3)', descripcion: 'Mínimo 3 certificados', esPlantilla: false, cantidadMin: 3 },
  { tipo: 'cuenta_bancaria', nombre: 'Certificación de la Cuenta Bancaria', esPlantilla: false, cantidadMin: 1 }
];


// ==========================================
// 7. FUNCIONES HELPER DE BASE DE DATOS
// ==========================================

function obtenerEstadisticas() {
  try {
    const stats = {
      usuarios: db.prepare('SELECT COUNT(*) as total FROM usuarios').get().total,
      proveedores: db.prepare('SELECT COUNT(*) as total FROM proveedores').get().total,
      documentos: db.prepare('SELECT COUNT(*) as total FROM documentos').get().total,
      documentosAprobados: db.prepare("SELECT COUNT(*) as total FROM documentos WHERE estado = 'aprobado'").get().total,
      documentosPendientes: db.prepare("SELECT COUNT(*) as total FROM documentos WHERE estado = 'pendiente'").get().total,
      documentosRechazados: db.prepare("SELECT COUNT(*) as total FROM documentos WHERE estado = 'rechazado'").get().total,
      proveedoresAprobados: db.prepare("SELECT COUNT(*) as total FROM proveedores WHERE estado_general = 'aprobado'").get().total,
      proveedoresPendientes: db.prepare("SELECT COUNT(*) as total FROM proveedores WHERE estado_general = 'pendiente'").get().total,
      proveedoresRechazados: db.prepare("SELECT COUNT(*) as total FROM proveedores WHERE estado_general = 'rechazado'").get().total
    };
    return stats;
  } catch (e) {
    console.error('Error obteniendo estadísticas:', e.message);
    return null;
  }
}

function limpiarLogsAntiguos() {
  try {
    const result = db.prepare(`
      DELETE FROM logs_seguridad 
      WHERE creado_en < datetime('now', '-90 days', 'localtime')
    `).run();
    
    if (result.changes > 0) {
      console.log(`🧹 ${result.changes} logs de seguridad antiguos eliminados`);
    }
  } catch (e) {
    console.error('Error limpiando logs:', e.message);
  }
}

function verificarIntegridad() {
  try {
    const result = db.prepare('PRAGMA integrity_check').get();
    return result.integrity_check === 'ok';
  } catch (e) {
    console.error('Error verificando integridad:', e.message);
    return false;
  }
}


// ==========================================
// 8. EXPORTACIÓN
// ==========================================
module.exports = { 
  db, 
  DOCUMENTOS_REQUERIDOS,
  obtenerEstadisticas,
  limpiarLogsAntiguos,
  verificarIntegridad
};

console.log('✅ Base de datos completamente inicializada\n');