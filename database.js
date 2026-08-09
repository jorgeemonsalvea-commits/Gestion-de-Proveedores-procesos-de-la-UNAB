// ==========================================
// 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ==========================================
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { generarPasswordAleatoria } = require('./security');
// Usar volumen persistente en Railway, o local en desarrollo
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const dbPath = path.join(dataDir, 'proveedores.db');
// 🩹 SELF-HEALING (Railway): si la BD principal está corrupta y hay backups en el
// volumen, restaura automáticamente el más reciente ANTES de abrir el servicio.
// El archivo dañado se conserva cuarentenado como proveedores.db.corrupt_<ts>.
function asegurarIntegridadInicial() {
  const backupsDir = path.join(dataDir, 'backups');
  try {
    if (fs.existsSync(dbPath)) {
      let temp = null;
      try {
        temp = new Database(dbPath, { readonly: true, fileMustExist: true });
        const check = temp.pragma('integrity_check', { simple: true });
        temp.close();
        if (check === 'ok') return; // BD sana: no hacer nada
        console.error(`⚠️ integrity_check de la BD principal falló: ${check}`);
      } catch (e) {
        try { if (temp) temp.close(); } catch (_) {}
        console.error('⚠️ No se pudo abrir la BD principal para verificación:', e.message);
      }
    }
    if (!fs.existsSync(backupsDir)) return;
    const candidatos = fs.readdirSync(backupsDir)
      .filter(f => /^proveedores_\d{4}-\d{2}-\d{2}(_\d{4})?\.db$/.test(f))
      .sort();
    if (!candidatos.length) { console.warn('⚠️ SELF-HEALING: no hay backups disponibles en el volumen'); return; }
    const ultimo = path.join(backupsDir, candidatos[candidatos.length - 1]);
    if (fs.existsSync(dbPath)) fs.renameSync(dbPath, `${dbPath}.corrupt_${Date.now()}`);
    fs.rmSync(`${dbPath}-wal`, { force: true });
    fs.rmSync(`${dbPath}-shm`, { force: true });
    fs.copyFileSync(ultimo, dbPath);
    console.log(`🩹 SELF-HEALING: BD restaurada automáticamente desde ${path.basename(ultimo)}`);
  } catch (e) {
    console.error('❌ Error en self-healing:', e.message);
  }
}
asegurarIntegridadInicial();
const db = new Database(dbPath);

console.log('📂 Ruta de la base de datos:', dbPath);
console.log('📂 dataDir:', dataDir);

// Optimizaciones de SQLite
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -64000');
db.pragma('busy_timeout = 5000');
db.pragma('mmap_size = 268435456'); // 256 MB mapeados en memoria (lecturas más rápidas)

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
    creado_en DATETIME DEFAULT (datetime('now','-05:00'))
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
    ultimo_recordatorio_envio DATETIME,
    todos_subidos INTEGER DEFAULT 0,
    todos_verificados INTEGER DEFAULT 0,
    numero_registro TEXT,
    tipo_gestion TEXT CHECK(tipo_gestion IN ('inscripcion','actualizacion')),
    notas_gestion TEXT,
    fecha_gestion DATETIME,
    etapa TEXT DEFAULT 'verificacion' CHECK(etapa IN ('verificacion','aprobacion','inscripcion','registrado','rechazado')),
    evaluacion_inicial TEXT,
    evaluacion_estado TEXT DEFAULT 'pendiente' CHECK(evaluacion_estado IN ('pendiente','aprobado','rechazado')),
    evaluacion_fecha DATETIME,
    tipo_proveedor TEXT,
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
    verificado INTEGER DEFAULT 0,
    fecha_vencimiento DATETIME,
    ciclo TEXT,
    es_historico INTEGER DEFAULT 0,
    fecha_archivado DATETIME,
    subido_en DATETIME DEFAULT (datetime('now','-05:00')),
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );

  -- Tabla de plantillas
  CREATE TABLE IF NOT EXISTS plantillas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo TEXT UNIQUE NOT NULL,
    archivo TEXT NOT NULL,
    nombre_original TEXT,
    subido_en DATETIME DEFAULT (datetime('now','-05:00'))
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
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
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
    cerrada INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
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
    cerrada INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
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
    creado_en DATETIME DEFAULT (datetime('now','-05:00'))
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
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_habeas_data_usuario
  ON habeas_data_consent(usuario_id, aceptado);

  -- Tabla de recuperación de contraseña
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expiracion DATETIME NOT NULL,
    usado INTEGER DEFAULT 0,
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_password_resets_token
  ON password_resets(token);

  CREATE INDEX IF NOT EXISTS idx_password_resets_expiracion
  ON password_resets(expiracion);

  -- Tabla de configuración (parámetros del sistema)
  CREATE TABLE IF NOT EXISTS configuracion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clave TEXT UNIQUE NOT NULL,
    valor TEXT NOT NULL,
    descripcion TEXT,
    actualizado_en DATETIME DEFAULT (datetime('now','-05:00'))
  );

  -- Tabla de ciclos de actualización (histórico de registros)
  CREATE TABLE IF NOT EXISTS ciclos_actualizacion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proveedor_id INTEGER NOT NULL,
    numero_registro TEXT NOT NULL,
    fecha_inicio DATETIME DEFAULT (datetime('now','-05:00')),
    fecha_fin DATETIME,
    estado TEXT DEFAULT 'activo' CHECK(estado IN ('activo','cerrado','rechazado')),
    creado_en DATETIME DEFAULT (datetime('now','-05:00')),
    FOREIGN KEY(proveedor_id) REFERENCES proveedores(id) ON DELETE CASCADE
  );
`);

console.log('✅ Estructura de tablas verificada');

// ==========================================
// 3. SISTEMA DE MIGRACIONES AUTOMÁTICAS
// ==========================================
console.log('🔄 Verificando migraciones...');

const migraciones = [
  // Usuarios
  { tabla: 'usuarios', campo: 'debe_cambiar_password', tipo: 'INTEGER DEFAULT 1' },
  { tabla: 'usuarios', campo: 'intentos_fallidos', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'usuarios', campo: 'bloqueado_hasta', tipo: 'DATETIME' },

  // Proveedores
  { tabla: 'proveedores', campo: 'fecha_aprobacion', tipo: 'DATETIME' },
  { tabla: 'proveedores', campo: 'ultimo_recordatorio_envio', tipo: 'DATETIME' },
  { tabla: 'proveedores', campo: 'todos_subidos', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'proveedores', campo: 'todos_verificados', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'proveedores', campo: 'numero_registro', tipo: 'TEXT' },
  { tabla: 'proveedores', campo: 'tipo_gestion', tipo: "TEXT CHECK(tipo_gestion IN ('inscripcion','actualizacion'))" },
  { tabla: 'proveedores', campo: 'notas_gestion', tipo: 'TEXT' },
  { tabla: 'proveedores', campo: 'fecha_gestion', tipo: 'DATETIME' },
  { tabla: 'proveedores', campo: 'etapa', tipo: "TEXT DEFAULT 'verificacion' CHECK(etapa IN ('verificacion','aprobacion','inscripcion','registrado','rechazado'))" },
  { tabla: 'proveedores', campo: 'evaluacion_inicial', tipo: 'TEXT' },
  { tabla: 'proveedores', campo: 'evaluacion_estado', tipo: "TEXT DEFAULT 'pendiente' CHECK(evaluacion_estado IN ('pendiente','aprobado','rechazado'))" },
  { tabla: 'proveedores', campo: 'evaluacion_fecha', tipo: 'DATETIME' },
  { tabla: 'proveedores', campo: 'tipo_proveedor', tipo: 'TEXT' },

  // Documentos
  { tabla: 'documentos', campo: 'hash_archivo', tipo: 'TEXT' },
  { tabla: 'documentos', campo: 'no_aplica', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'documentos', campo: 'verificado', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'documentos', campo: 'fecha_vencimiento', tipo: 'DATETIME' },
  { tabla: 'documentos', campo: 'ciclo', tipo: 'TEXT' },
  { tabla: 'documentos', campo: 'es_historico', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'documentos', campo: 'fecha_archivado', tipo: 'DATETIME' },

  // Historial
  { tabla: 'historial', campo: 'ip_origen', tipo: 'TEXT' },

  // Notas
  { tabla: 'notas_proveedor', campo: 'leida', tipo: 'INTEGER DEFAULT 0' },
  { tabla: 'notas_proveedor', campo: 'cerrada', tipo: 'INTEGER DEFAULT 0' },

  // Recordatorios
  { tabla: 'recordatorios', campo: 'cerrada', tipo: 'INTEGER DEFAULT 0' }
];

let migracionesAplicadas = 0;
let migracionesFallidas = 0;

migraciones.forEach(m => {
  try {
    const columnas = db.prepare(`PRAGMA table_info(${m.tabla})`).all();

    if (!columnas.some(c => c.name === m.campo)) {
      db.exec(`ALTER TABLE ${m.tabla} ADD COLUMN ${m.campo} ${m.tipo}`);
      console.log(`✅ ${m.tabla}.${m.campo}`);
      migracionesAplicadas++;
    }
  } catch (e) {
    console.log(`⚠️ ${m.tabla}.${m.campo}: ${e.message}`);
    migracionesFallidas++;
  }
});

if (migracionesAplicadas > 0) {
  console.log(`✅ ${migracionesAplicadas} migración(es) aplicada(s)`);
} else {
  console.log('✅ No se requieren migraciones');
}

if (migracionesFallidas > 0) {
  console.log(`⚠️ ${migracionesFallidas} migración(es) fallida(s)`);
}

// ==========================================
// 3.5 NORMALIZACIÓN DE DATOS EXISTENTES
// ==========================================
console.log('🧹 Normalizando datos existentes...');

try {
  db.prepare(`UPDATE documentos SET es_historico = 0 WHERE es_historico IS NULL`).run();
  db.prepare(`UPDATE documentos SET no_aplica = 0 WHERE no_aplica IS NULL`).run();
  db.prepare(`UPDATE documentos SET verificado = 0 WHERE verificado IS NULL`).run();

  db.prepare(`UPDATE proveedores SET todos_subidos = 0 WHERE todos_subidos IS NULL`).run();
  db.prepare(`UPDATE proveedores SET todos_verificados = 0 WHERE todos_verificados IS NULL`).run();

  db.prepare(`
    UPDATE proveedores
    SET etapa = 'verificacion'
    WHERE etapa IS NULL OR etapa = ''
  `).run();

  db.prepare(`
    UPDATE proveedores
    SET evaluacion_estado = 'pendiente'
    WHERE evaluacion_estado IS NULL OR evaluacion_estado = ''
  `).run();

  // Los documentos históricos deben quedar rechazados
  db.prepare(`
    UPDATE documentos
    SET estado = 'rechazado',
        comentario = COALESCE(comentario, 'Documento histórico')
    WHERE es_historico = 1
      AND estado != 'rechazado'
  `).run();

  // 🧹 Eliminar marcadores "No aplica" que quedaron desmarcados y sin archivo real
const marcadoresNoAplicaInvalidos = db.prepare(`
  DELETE FROM documentos
  WHERE no_aplica = 0
    AND (archivo IS NULL OR archivo = 'no_aplica')
    AND es_historico = 0
`).run();

if (marcadoresNoAplicaInvalidos.changes > 0) {
  console.log(`🧹 ${marcadoresNoAplicaInvalidos.changes} marcador(es) No aplica inválido(s) eliminado(s)`);
}


  // 🆕 Normalizar tipo_proveedor: los existentes quedan como 'juridica'
//    (equivalente al comportamiento actual). Solo se preserva quien ya
//    tenga la palabra "natural" en el texto libre que haya puesto el admin.
db.prepare(`
  UPDATE proveedores
  SET tipo_proveedor = 'natural'
  WHERE tipo_proveedor IS NOT NULL
    AND tipo_proveedor != ''
    AND lower(tipo_proveedor) LIKE '%natural%'
`).run();
db.prepare(`
  UPDATE proveedores
  SET tipo_proveedor = 'juridica'
  WHERE tipo_proveedor IS NULL
     OR tipo_proveedor = ''
     OR tipo_proveedor != 'natural'
`).run();
console.log('✅ tipo_proveedor normalizado (natural/juridica)');

  console.log('✅ Normalización básica completada');
} catch (err) {
  console.error('⚠️ Error normalizando datos existentes:', err.message);
}

// ==========================================
// 4. CREACIÓN DE ÍNDICES PARA OPTIMIZACIÓN
// ==========================================
console.log('📊 Verificando índices...');

const indices = [
  // Historial
  { nombre: 'idx_historial_prov', tabla: 'historial', columnas: 'proveedor_id, creado_en DESC' },
  { nombre: 'idx_historial_accion', tabla: 'historial', columnas: 'accion' },

  // Recordatorios
  { nombre: 'idx_recordatorios_prov', tabla: 'recordatorios', columnas: 'proveedor_id, leido' },
  { nombre: 'idx_recordatorios_creado', tabla: 'recordatorios', columnas: 'creado_en DESC' },

  // Logs
  { nombre: 'idx_logs_seguridad_fecha', tabla: 'logs_seguridad', columnas: 'creado_en DESC' },
  { nombre: 'idx_logs_seguridad_usuario', tabla: 'logs_seguridad', columnas: 'usuario_id' },
  { nombre: 'idx_logs_seguridad_accion', tabla: 'logs_seguridad', columnas: 'accion' },

  // Documentos
  { nombre: 'idx_documentos_proveedor', tabla: 'documentos', columnas: 'proveedor_id, tipo' },
  { nombre: 'idx_documentos_estado', tabla: 'documentos', columnas: 'estado' },

  // Índices críticos para históricos / activos
  { nombre: 'idx_documentos_historico', tabla: 'documentos', columnas: 'proveedor_id, es_historico' },
  { nombre: 'idx_documentos_ciclo', tabla: 'documentos', columnas: 'ciclo' },
  { nombre: 'idx_documentos_proveedor_ciclo', tabla: 'documentos', columnas: 'proveedor_id, ciclo' },
  { nombre: 'idx_documentos_historico_ciclo', tabla: 'documentos', columnas: 'proveedor_id, es_historico, ciclo' },
  { nombre: 'idx_documentos_activo_tipo', tabla: 'documentos', columnas: 'proveedor_id, es_historico, tipo, estado' },
  { nombre: 'idx_documentos_fecha_vencimiento', tabla: 'documentos', columnas: 'fecha_vencimiento' },

  // Notas
  { nombre: 'idx_notas_proveedor', tabla: 'notas_proveedor', columnas: 'proveedor_id, leida' },

  // Usuarios
  { nombre: 'idx_usuarios_email', tabla: 'usuarios', columnas: 'email' },

  // Proveedores
  { nombre: 'idx_proveedores_estado', tabla: 'proveedores', columnas: 'estado_general' },
  { nombre: 'idx_proveedores_etapa', tabla: 'proveedores', columnas: 'etapa' },

  // Ciclos
  { nombre: 'idx_ciclos_proveedor', tabla: 'ciclos_actualizacion', columnas: 'proveedor_id' },
  { nombre: 'idx_ciclos_numero_registro', tabla: 'ciclos_actualizacion', columnas: 'numero_registro' },
  { nombre: 'idx_ciclos_estado', tabla: 'ciclos_actualizacion', columnas: 'estado' },

  // Configuración
  { nombre: 'idx_configuracion_clave', tabla: 'configuracion', columnas: 'clave' }
];

let indicesCreados = 0;

indices.forEach(idx => {
  try {
    db.exec(`CREATE INDEX IF NOT EXISTS ${idx.nombre} ON ${idx.tabla}(${idx.columnas})`);
    indicesCreados++;
  } catch (e) {
    console.log(`⚠️ Índice ${idx.nombre}: ${e.message}`);
  }
});

console.log(`✅ ${indicesCreados} índices verificados`);

// ==========================================
// 4.5 CONFIGURACIÓN INICIAL
// ==========================================
console.log('⚙️  Verificando configuración inicial...');

const anioActual = new Date().getFullYear();
const fechaVencimientoDefault = `${anioActual}-12-31 23:59:59`;

const configuracionesIniciales = [
  {
    clave: 'dias_validez_documentos',
    valor: '365',
    descripcion: 'Número de días de validez de los documentos aprobados (por defecto 1 año)'
  },
  {
    clave: 'fecha_vencimiento_fija',
    valor: fechaVencimientoDefault,
    descripcion: 'Fecha fija de vencimiento de los documentos aprobados (formato YYYY-MM-DD HH:MM:SS)'
  }
];

configuracionesIniciales.forEach(cfg => {
  const existente = db.prepare('SELECT id FROM configuracion WHERE clave = ?').get(cfg.clave);

  if (!existente) {
    db.prepare(`
      INSERT INTO configuracion (clave, valor, descripcion)
      VALUES (?, ?, ?)
    `).run(cfg.clave, cfg.valor, cfg.descripcion);

    console.log(`✅ Configuración inicial insertada: ${cfg.clave} = ${cfg.valor}`);
  } else {
    console.log(`✅ Configuración existente: ${cfg.clave} = ${existente.valor || ''}`);
  }
});

// ==========================================
// 5. CREACIÓN DE ADMIN POR DEFECTO
// ==========================================
const adminEmail = process.env.ADMIN_EMAIL || 'admin@empresa.com';
const adminExistente = db.prepare('SELECT id FROM usuarios WHERE email = ?').get(adminEmail);
if (!adminExistente) {
try {
// 🛡️ M5: si ADMIN_PASSWORD_INICIAL existe se usa; si no, se genera una fuerte
// y se muestra UNA sola vez en el log (no queda escrita en código ni en BD en claro).
const adminPass = process.env.ADMIN_PASSWORD_INICIAL || generarPasswordAleatoria(16);
const hash = bcrypt.hashSync(adminPass, 12);

    db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password)
      VALUES (?, ?, ?, ?, 1)
    `).run(adminEmail, hash, 'admin', 'Administración');


//Recomendación de despliegue en Railway: define ADMIN_PASSWORD_INICIAL en las variables de entorno (una fuerte, ≥ 16 caracteres). Así nunca dependes de leer el log.
console.log(`
✅ Admin creado exitosamente`);
console.log(`   📧 Email: ${adminEmail}`);
console.log(`   🔑 Contraseña: ${adminPass}`);
console.log(`   ⚠️  Deberás cambiar la contraseña al primer ingreso
`);
if (!process.env.ADMIN_PASSWORD_INICIAL) {
console.error(`
⚠️  CONTRASEÑA DE ADMIN GENERADA AUTOMÁTICAMENTE — cópiala YA, no se volverá a mostrar:`);
console.error(`   🔑 ${adminPass}
`);
}
  } catch (e) {
    console.error(`❌ Error creando admin: ${e.message}`);
  }
} else {
  console.log(`✅ Admin existente: ${adminEmail}`);
}

// ==========================================
// 5.5 MIGRACIÓN DE DATOS:
// ASIGNAR CICLO Y FECHA DE VENCIMIENTO
// A DOCUMENTOS APROBADOS ACTIVOS EXISTENTES
// ==========================================
console.log('🔄 Verificando datos existentes para vencimientos...');

try {
  // 1. Asignar ciclo a documentos aprobados activos sin ciclo
  const docsSinCiclo = db.prepare(`
    SELECT d.id, p.numero_registro
    FROM documentos d
    JOIN proveedores p ON d.proveedor_id = p.id
    WHERE d.estado = 'aprobado'
      AND d.es_historico = 0
      AND (d.ciclo IS NULL OR d.ciclo = '')
      AND p.numero_registro IS NOT NULL
      AND p.numero_registro != ''
  `).all();

  if (docsSinCiclo.length > 0) {
    console.log(`Asignando ciclo a ${docsSinCiclo.length} documentos aprobados activos...`);

    const updateCiclo = db.prepare(`
      UPDATE documentos
      SET ciclo = ?
      WHERE id = ?
    `);

    for (const doc of docsSinCiclo) {
      updateCiclo.run(doc.numero_registro, doc.id);
    }
  }

  // 2. Asignar fecha de vencimiento fija a documentos aprobados activos sin fecha
  const configFecha = db.prepare(`
    SELECT valor
    FROM configuracion
    WHERE clave = 'fecha_vencimiento_fija'
  `).get();

  const fechaVencimiento = configFecha?.valor || fechaVencimientoDefault;

  const docsSinVencimiento = db.prepare(`
    SELECT id
    FROM documentos
    WHERE estado = 'aprobado'
      AND es_historico = 0
      AND fecha_vencimiento IS NULL
  `).all();

  if (docsSinVencimiento.length > 0) {
    console.log(`Asignando fecha de vencimiento a ${docsSinVencimiento.length} documentos aprobados activos (${fechaVencimiento})...`);

    const updateVenc = db.prepare(`
      UPDATE documentos
      SET fecha_vencimiento = ?
      WHERE id = ?
    `);

    for (const doc of docsSinVencimiento) {
      updateVenc.run(fechaVencimiento, doc.id);
    }
  } else {
    console.log('   No se requieren actualizaciones de fecha de vencimiento.');
  }
} catch (err) {
  console.error('❌ Error en migración de datos de vencimientos:', err.message);
}

// ==========================================
// 6. CONFIGURACIÓN DE DOCUMENTOS REQUERIDOS
// ==========================================
const DOCUMENTOS_REQUERIDOS = [
  { tipo: 'gaf01', nombre: 'GAF04-01-FO-01 Abastacimiento de Bienes y Servicios V11', descripcion: 'Aba Bie Serv V1.1', esPlantilla: true, requiereFirma: true, requiereHuella: false, cantidadMin: 1 },
  { tipo: 'gaf07', nombre: 'GAF04-01-FO-07 Lavado de activos V2', descripcion: 'Lavado de activos V2', esPlantilla: true, requiereFirma: true, requiereHuella: true, cantidadMin: 1 },
  { tipo: 'gaf08', nombre: 'GAF04-01-FO-08 Declaración de Origen de Fondos V2', descripcion: 'Declaración origen de fondos V2', esPlantilla: true, requiereFirma: true, requiereHuella: true, cantidadMin: 1 },
  { tipo: 'carta_ica', nombre: 'Carta ICA', descripcion: 'Carta ICA - formato institucional', esPlantilla: true, cantidadMin: 1 },
  { tipo: 'rut', nombre: 'RUT', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'camara_comercio', nombre: 'Certificado Cámara de Comercio', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'cedula_rl', nombre: 'Fotocopia cédula de ciudadanía del Representante Legal', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'estados_financieros', nombre: 'Estados Financieros', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'parafiscales', nombre: 'Certificación de parafiscales', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'calidad', nombre: 'Certificación de calidad (si aplica)', esPlantilla: false, cantidadMin: 1, opcional: true },
  { tipo: 'sgsst', nombre: 'Certificación Seguridad y Salud en el Trabajo', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'experiencia', nombre: 'Certificados de experiencia comercial (mínimo 3)', descripcion: 'Mínimo 3 certificados', esPlantilla: false, cantidadMin: 3, cantidadMax: 3 },
  { tipo: 'cuenta_bancaria', nombre: 'Certificación de la Cuenta Bancaria', esPlantilla: false, cantidadMin: 1 },
  { tipo: 'ambiental', nombre: 'Certificado Ambiental', esPlantilla: false, cantidadMin: 1, opcional: true }
];

// ==========================================
// 🆕 6.1 DOCUMENTOS POR TIPO DE PERSONA
// ==========================================

// Documento exclusivo de Persona Natural
const DOC_COMPETENCIAS = {
  tipo: 'competencias',
  nombre: 'Certificados de competencia (cuando aplique)',
  descripcion: 'Alturas, manipulación de alimentos, matrícula electricista, espacios confinados, etc.',
  esPlantilla: false,
  cantidadMin: 1,
  opcional: true
};

// Orden de presentación solicitado para Persona Natural
const ORDEN_NATURAL = [
  'gaf01', 'gaf07', 'gaf08', 'carta_ica', 'rut', 'camara_comercio', 'cedula_rl',
  'estados_financieros', 'experiencia', 'parafiscales', 'calidad',
  'ambiental', 'sgsst', 'competencias'
];

const OBLIGATORIOS_NATURAL = ['gaf01', 'gaf07', 'gaf08', 'carta_ica', 'rut', 'cedula_rl'];
/**
 * 🆕 Devuelve los documentos requeridos según el tipo de persona.
 * - 'juridica' (o vacío/null) → lista ACTUAL sin cambios.
 * - 'natural' → todos con "No aplica", experiencia 1-2, sin cuenta_bancaria, + competencias.
 */
function requerimientosPara(tipoPersona) {
  if (String(tipoPersona || '').trim().toLowerCase() !== 'natural') {
  return DOCUMENTOS_REQUERIDOS; // 👈 Jurídica = flujo actual intacto
  }
  return DOCUMENTOS_REQUERIDOS
  .filter(r => r.tipo !== 'cuenta_bancaria')
  .map(r => {
  // 🆕 Los obligatorios para natural NO llevan "No aplica"; el resto sí
  const esObligatorio = OBLIGATORIOS_NATURAL.includes(r.tipo);
  const doc = esObligatorio ? { ...r } : { ...r, opcional: true };
  if (r.tipo === 'experiencia') {
  doc.nombre = 'Certificados comerciales como proveedores (1 o 2)';
  doc.cantidadMin = 1;
  doc.cantidadMax = 2;
  }
  if (r.tipo === 'camara_comercio') doc.nombre = 'Cámara de Comercio actualizada';
  if (r.tipo === 'parafiscales') doc.nombre = 'Certificación de revisor fiscal, contador o representante legal al día con pagos de seguridad social';
  if (r.tipo === 'sgsst') doc.nombre = 'Certificación ARL y/o evaluación SGSST';
  return doc;
  })
  .concat([DOC_COMPETENCIAS])
  .sort((a, b) => ORDEN_NATURAL.indexOf(a.tipo) - ORDEN_NATURAL.indexOf(b.tipo));
}

/** 🆕 Configuración de un tipo de documento según el tipo de persona del proveedor */
function configDocumento(tipoDoc, tipoPersona) {
  return requerimientosPara(tipoPersona).find(d => d.tipo === tipoDoc) || null;
  }

// ==========================================
// 7. FUNCIONES HELPER DE BASE DE DATOS
// ==========================================
function limpiarLogsAntiguos() {
  try {
    const result = db.prepare(`
      DELETE FROM logs_seguridad
      WHERE creado_en < datetime('now', '-90 days', '-05:00')
    `).run();

    if (result.changes > 0) {
      console.log(`🧹 ${result.changes} logs de seguridad antiguos eliminados`);
    }
  } catch (e) {
    console.error('Error limpiando logs:', e.message);
  }
}

// ==========================================
// 8. EXPORTACIÓN
// ==========================================
module.exports = {
  db,
    DOCUMENTOS_REQUERIDOS,
    requerimientosPara,
    configDocumento,
    limpiarLogsAntiguos
};

console.log('✅ Base de datos completamente inicializada\n');