// ==========================================
// 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ==========================================
require('dotenv').config();
const http = require('http');
const { Server } = require('socket.io');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const archiver = require('archiver');
const crypto = require('crypto');

if (typeof archiver !== 'function') {
  console.error('❌ archiver no está instalado o no se cargó correctamente.');
  console.error('   Ejecuta: npm install archiver');
  process.exit(1);
}

const { db, DOCUMENTOS_REQUERIDOS } = require('./database');
const {
  cifrarArchivo,
  descifrarArchivo,
  calcularHash,
  verificarHash,
  validarPassword,
  generarClaveMaestra,
  validarClaveMaestra,
  obtenerConfiguracionSeguridad,
  verificarSistemaCifrado
} = require('./security');

const {
  enviarEmail,
  emailProveedorSubioDocumento,
  emailDocumentoRechazado,
  emailNuevaNota,
  emailProveedorAprobado,
  emailProveedorActualizacionAprobada,
  emailBienvenidaProveedor,
  emailRecordatorio,
  emailProveedorCompletoDocumentos,
  emailRecordatorioDocumentosFaltantes,
  emailEvaluacionRechazada,
  emailSolicitudActualizacion
} = require('./email');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? false : '*',
    credentials: true
  }
});

const PORT = process.env.PORT || 3000;
console.log('✅ Socket.IO inicializado sobre el servidor HTTP');

app.set('trust proxy', 1);

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!validarClaveMaestra(ENCRYPTION_KEY)) {
  console.error('❌ ENCRYPTION_KEY no es válida (mínimo 32 caracteres)');
  process.exit(1);
}

if (!validarClaveMaestra(SESSION_SECRET)) {
  console.error('❌ SESSION_SECRET no es válida (mínimo 32 caracteres)');
  process.exit(1);
}

const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const uploadsDir = path.join(dataDir, 'uploads');
const plantillasDir = path.join(dataDir, 'plantillas');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(plantillasDir)) fs.mkdirSync(plantillasDir, { recursive: true });

console.log('\n🔐 Configuración de seguridad:');
console.table(obtenerConfiguracionSeguridad());

const testCifrado = verificarSistemaCifrado(ENCRYPTION_KEY);
console.log(testCifrado.mensaje);
if (!testCifrado.funcional) {
  console.error('❌ El sistema de cifrado NO está funcionando');
  process.exit(1);
}
// 🛡️ M2 (Fase 3): hash bcrypt dummy (cost 12) para igualar el tiempo de respuesta
// en login cuando el email no existe. Evita la enumeración de usuarios por timing.
// Este hash nunca va a matchear con una contraseña real; solo consume tiempo de CPU.
const DUMMY_BCRYPT_HASH = '$2a$12$WApznUPhDubN0oeveSXoqOe6eHZMVj7S5rJtgvQXlhQl1JqF.F8O2';

// ==========================================
// 2. SEGURIDAD Y MIDDLEWARES
// ==========================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],
      scriptSrcElem: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      frameSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
}));

const limiterLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: {
    error: 'Demasiados intentos. Espera 15 minutos o contacta al administrador.',
    minutos_restantes: 15
  },
  skipSuccessfulRequests: true,
skip: (req) => {
// 🛡️ A3: ya NO eximimos al admin del rate-limit por rol.
// Solo se salta el límite si ya hay una sesión activa (usuario logueado).
// Así los intentos contra el admin SÍ cuentan y se limitan por IP (20/15 min),
// cerrando el bypass que permitía fuerza bruta a velocidad de red contra el admin.
if (req.session && req.session.usuario) return true;
return false;
},
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Demasiados intentos. Espera 15 minutos.',
      minutos_restantes: 15
    });
  }
});

const limiterGeneral = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 500,
  message: { error: 'Demasiadas peticiones. Espera un momento.' },
  skipSuccessfulRequests: false
});

const limiterUpload = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  message: { error: 'Demasiadas subidas. Espera 5 minutos.' }
});

app.use('/api/login', limiterLogin);
app.use('/api/registro', limiterLogin);
app.use('/api/recuperar-password', limiterLogin);
app.use('/api/', limiterGeneral);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const FileStore = require('session-file-store');
const FileStoreInstance = FileStore(session);

const sessionsDir = path.join(dataDir, 'sessions');
if (!fs.existsSync(sessionsDir)) fs.mkdirSync(sessionsDir, { recursive: true });

function limpiarArchivosTemporalesSesiones() {
  try {
    const archivos = fs.readdirSync(sessionsDir);
    let eliminados = 0;

    archivos.forEach(archivo => {
      if (archivo.match(/\.json\.\d+$/)) {
        try {
          fs.unlinkSync(path.join(sessionsDir, archivo));
          eliminados++;
        } catch (e) {}
      }
    });

    if (eliminados > 0) {
      console.log(`🧹 ${eliminados} archivos temporales de sesión eliminados`);
    }
  } catch (err) {
    console.error('Error limpiando archivos temporales de sesión:', err.message);
  }
}

function limpiarSesionesCorruptas() {
  try {
    const archivos = fs.readdirSync(sessionsDir);
    let limpiados = 0;

    archivos.forEach(archivo => {
      if (!archivo.endsWith('.json')) return;

      const rutaArchivo = path.join(sessionsDir, archivo);

      try {
        const contenido = fs.readFileSync(rutaArchivo, 'utf8');
        const sesion = JSON.parse(contenido);

        if (!sesion || !sesion.cookie || !sesion.cookie.expires) {
          fs.unlinkSync(rutaArchivo);
          limpiados++;
        }
      } catch (err) {
        try {
          fs.unlinkSync(rutaArchivo);
          limpiados++;
        } catch (e) {
          console.error(`No se pudo eliminar ${archivo}:`, e.message);
        }
      }
    });

    if (limpiados > 0) {
      console.log(`🧹 ${limpiados} sesión(es) corrupta(s) eliminada(s)`);
    }
  } catch (err) {
    console.error('Error limpiando sesiones:', err.message);
  }
}

limpiarArchivosTemporalesSesiones();
limpiarSesionesCorruptas();

const fileStoreOptions = {
  path: sessionsDir,
  ttl: 60 * 60 * 8,
  retries: 5,
  retryDelay: 500,
  logFn: () => {},
  fallbackSessionFn: () => ({
    cookie: {
      originalMaxAge: null,
      expires: null,
      secure: false,
      httpOnly: true,
      path: '/',
      sameSite: 'lax'
    }
  }),
  reapInterval: 60 * 60,
  reapAsync: true,
  useReapInterval: true
};

const sessionMiddleware = session({
  store: new FileStoreInstance(fileStoreOptions),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
cookie: {
maxAge: 1000 * 60 * 60 * 8,
httpOnly: true,
// 🛡️ A4: 'lax' también en producción para mitigar CSRF.
// 'none' permitía enviar la cookie en peticiones cross-site (vector CSRF clásico:
// un <form> oculto en otro sitio disparaba POST con la sesión del admin).
// 'lax' sigue permitiendo: navegación por enlace desde correos (top-level GET)
// y TODAS las llamadas same-origin (fetch con credentials, Socket.IO, iframes del portal).
sameSite: 'lax',
secure: process.env.NODE_ENV === 'production'
}
});

app.use(sessionMiddleware);

const sharedsession = require('express-socket.io-session');

io.use(sharedsession(sessionMiddleware, {
  autoSave: true,
  saveUninitialized: false
}));

io.use((socket, next) => {
  const sess = socket.handshake.session;

  if (sess && sess.usuario) {
    socket.usuario = sess.usuario;
    next();
  } else {
    console.log('⚠️ Socket rechazado: sesión inválida');
    next(new Error('No autorizado'));
  }
});

io.on('connection', (socket) => {
  const usuario = socket.usuario;
  console.log(`🔌 Cliente conectado: ${usuario.email} (${usuario.rol})`);

  if (usuario.rol === 'admin') {
    socket.join('admin');
  } else if (usuario.rol === 'proveedor') {
    const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(usuario.id);
    if (proveedor) {
      socket.join(`proveedor_${proveedor.id}`);
    }
  }

  socket.on('disconnect', () => {
    console.log(`🔌 Cliente desconectado: ${usuario.email}`);
  });
});

function emitirAdmin(evento, datos) {
  io.to('admin').emit(evento, datos);
}

function emitirProveedor(proveedorId, evento, datos) {
  io.to(`proveedor_${proveedorId}`).emit(evento, datos);
}

function emitirTodos(proveedorId, evento, datos) {
  emitirAdmin(evento, datos);
  emitirProveedor(proveedorId, evento, datos);
}

app.use((err, req, res, next) => {
  if (err && err.message && (err.message.includes('expires') || err.message.includes('corrupt'))) {
    console.log('⚠️ Sesión corrupta/expired detectada, destruyendo...');
    if (req.session) {
      req.session.destroy(() => {});
    }
    res.clearCookie('connect.sid');
    return res.redirect('/');
  }

  if (err && err.code === 'EPERM' && err.syscall === 'rename') {
    console.warn(`⚠️ Error EPERM al guardar sesión, reintentando...`);
    if (req.session) {
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('❌ Error al guardar sesión después de reintento:', saveErr.message);
        } else {
          console.log('✅ Sesión guardada después de reintento');
        }
      });
    }
    return next();
  }

  next();
});

app.use('/plantillas', express.static(plantillasDir));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 3. FUNCIONES HELPER
// ==========================================
function validarLimiteDocumentos(proveedorId, tipo, cantidadMax = null) {
  if (!cantidadMax) return { valido: true };

  const count = db.prepare(`
    SELECT COUNT(*) as total
    FROM documentos
    WHERE proveedor_id = ?
      AND tipo = ?
      AND estado != 'rechazado'
      AND no_aplica = 0
      AND es_historico = 0
  `).get(proveedorId, tipo).total;

  if (count >= cantidadMax) {
    return {
      valido: false,
      mensaje: `Ya has subido el máximo de ${cantidadMax} documentos de este tipo.`
    };
  }

  return { valido: true };
}

function obtenerIP(req) {
  return req.ip || req.connection.remoteAddress || 'unknown';
}

function registrarLogSeguridad(usuarioId, email, accion, exitoso, detalle = '', req = null) {
  try {
    db.prepare(`
      INSERT INTO logs_seguridad (usuario_id, email, accion, ip_origen, user_agent, detalle, exitoso)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      usuarioId,
      email,
      accion,
      req ? obtenerIP(req) : null,
      req ? (req.headers['user-agent'] || '').substring(0, 200) : null,
      detalle,
      exitoso ? 1 : 0
    );
  } catch (e) {
    console.error('Error log:', e.message);
  }
}

function obtenerCarpetaProveedor(proveedorId) {
  const ruta = path.join(uploadsDir, String(proveedorId));
  if (!fs.existsSync(ruta)) fs.mkdirSync(ruta, { recursive: true });
  return ruta;
}

function obtenerRutaRelativa(proveedorId, nombreArchivo) {
  return `${proveedorId}/${nombreArchivo}`;
}

function registrarHistorial(proveedorId, usuario, accion, detalle, docTipo = null, docId = null, req = null) {
  const detalleEscapado = detalle ? escapeHtml(detalle) : null;

  db.prepare(`
    INSERT INTO historial (proveedor_id, usuario_id, usuario_nombre, accion, detalle, documento_tipo, documento_id, ip_origen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    proveedorId,
    usuario?.id || null,
    usuario?.email || 'Sistema',
    accion,
    detalleEscapado,
    docTipo,
    docId,
    req ? obtenerIP(req) : null
  );
}

function eliminarCarpetaRecursiva(ruta) {
  if (fs.existsSync(ruta)) fs.rmSync(ruta, { recursive: true, force: true });
}

function escapeHtml(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;')
.replace(/"/g, '&quot;')
.replace(/'/g, '&#39;');
}
// 🏷️ Nombre legible del formato a partir del tipo (para descargas)
function nombreFormatoServer(tipo) {
const c = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
return c ? c.nombre : null;
}

// 🏷️ Estado legible para exportaciones (diferencia las etapas reales)
function estadoLegibleServer(p) {
const etapa = p.etapa || '';
if (etapa === 'registrado') return 'Registrado';
if (etapa === 'rechazado') return 'Rechazado';
if (etapa === 'verificacion') return 'Por verificar';
if (etapa === 'aprobacion') return 'Por aprobación';
if (etapa === 'inscripcion') return 'En inscripción';
if (p.estado_general === 'aprobado') return 'Registrado';
if (p.estado_general === 'rechazado') return 'Rechazado';
return 'Pendiente';
}

function formatearFechaExcel(fecha) {
  if (!fecha) return '';

  const d = new Date(fecha.replace(' ', 'T'));
  return d.toLocaleString('es-CO', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'America/Bogota'
  });
}

function fechaArchivo() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}`;
}

function obtenerFechaVencimiento() {
  try {
    const config = db.prepare('SELECT valor FROM configuracion WHERE clave = ?').get('fecha_vencimiento_fija');

    if (config) {
      const fecha = new Date(config.valor.replace(' ', 'T'));
      if (!isNaN(fecha)) {
        return fecha;
      }
    }

    const fecha = new Date();
    fecha.setFullYear(fecha.getFullYear() + 1);
    fecha.setHours(23, 59, 59, 0);
    return fecha;
  } catch (err) {
    console.error('Error obteniendo fecha de vencimiento:', err.message);

    const fecha = new Date();
    fecha.setFullYear(fecha.getFullYear() + 1);
    fecha.setHours(23, 59, 59, 0);
    return fecha;
  }
}

// ==========================================
// HELPERS DE CICLOS / HISTÓRICOS
// ==========================================
function obtenerCicloActivo(proveedorId) {
  try {
    return db.prepare(`
      SELECT id, numero_registro
      FROM ciclos_actualizacion
      WHERE proveedor_id = ?
        AND estado = 'activo'
      ORDER BY id DESC
      LIMIT 1
    `).get(proveedorId) || null;
  } catch (err) {
    console.error('Error obteniendo ciclo activo:', err.message);
    return null;
  }
}

function obtenerCicloParaDocumento(doc, proveedorId) {
  try {
    if (doc?.ciclo && String(doc.ciclo).trim()) {
      return String(doc.ciclo).trim();
    }

    const prov = db.prepare(`
      SELECT numero_registro
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (prov?.numero_registro && String(prov.numero_registro).trim()) {
      return String(prov.numero_registro).trim();
    }

    const cicloActivo = obtenerCicloActivo(proveedorId);
    if (cicloActivo?.numero_registro && String(cicloActivo.numero_registro).trim()) {
      return String(cicloActivo.numero_registro).trim();
    }

    return 'sin_ciclo';
  } catch (err) {
    console.error('Error obteniendo ciclo para documento:', err.message);
    return 'sin_ciclo';
  }
}

function asignarCicloADocumentosActivos(proveedorId, numeroRegistro) {
  try {
    if (!numeroRegistro || !String(numeroRegistro).trim()) {
      return 0;
    }

    const result = db.prepare(`
      UPDATE documentos
      SET ciclo = ?
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).run(String(numeroRegistro).trim(), proveedorId);

    console.log(`📌 ${result.changes} documentos activos asociados al ciclo ${numeroRegistro} para proveedor ${proveedorId}`);
    return result.changes;
  } catch (err) {
    console.error('Error asignando ciclo a documentos activos:', err.message);
    return 0;
  }
}

function cerrarCicloAnterior(proveedorId) {
  try {
    const cicloActivo = db.prepare(`
      SELECT id
      FROM ciclos_actualizacion
      WHERE proveedor_id = ?
        AND estado = 'activo'
    `).get(proveedorId);

    if (cicloActivo) {
      db.prepare(`
        UPDATE ciclos_actualizacion
        SET estado = 'cerrado',
            fecha_fin = datetime('now', 'localtime')
        WHERE id = ?
      `).run(cicloActivo.id);

      console.log(`🔒 Ciclo anterior cerrado para proveedor ${proveedorId}`);
      return true;
    }

    return false;
  } catch (err) {
    console.error('Error cerrando ciclo anterior:', err.message);
    return false;
  }
}

function crearNuevoCiclo(proveedorId, numeroRegistro, tipoGestion = 'inscripcion') {
  try {
    const result = db.prepare(`
      INSERT INTO ciclos_actualizacion (proveedor_id, numero_registro, estado)
      VALUES (?, ?, 'activo')
    `).run(proveedorId, numeroRegistro);

    console.log(`🔄 Nuevo ciclo creado para proveedor ${proveedorId}: ${numeroRegistro}`);
    return result.lastInsertRowid;
  } catch (err) {
console.error('Error creando nuevo ciclo:', err.message);
return null;
}
}
// 🏷️ Helper: resuelve la Evaluación Inicial de un ciclo (activo o histórico).
//   - Ciclo ACTIVO con evaluación subida -> la toma de proveedores.evaluacion_inicial
//   - Ciclo CERRADO (o sin eval activa)  -> la busca en disco: uploads/<id>/<ciclo>/evaluacion_*.enc
//   Devuelve { archivo, estado, es_historico, fecha } o null. Reusado por el endpoint de
//   documentos del ciclo y por el ZIP del ciclo (DRY).
function resolverEvaluacionDelCiclo(ciclo) {
try {
if (!ciclo) return null;
if (ciclo.estado === 'activo' && ciclo.evaluacion_inicial) {
return {
archivo: ciclo.evaluacion_inicial,
estado: ciclo.evaluacion_estado || 'pendiente',
es_historico: 0,
fecha: ciclo.evaluacion_fecha || null
};
}
const dirCiclo = path.join(uploadsDir, String(ciclo.proveedor_id), String(ciclo.numero_registro));
if (fs.existsSync(dirCiclo)) {
const evalsEnDisco = fs.readdirSync(dirCiclo)
.filter(f => f.startsWith('evaluacion_') && f.endsWith('.enc'));
if (evalsEnDisco.length > 0) {
return {
archivo: `${ciclo.proveedor_id}/${ciclo.numero_registro}/${evalsEnDisco[0]}`,
estado: 'archivada',
es_historico: 1,
fecha: null
};
}
}
return null;
} catch (e) {
console.error('⚠️ Error resolviendo evaluación del ciclo:', e.message);
return null;
}
}
function moverDocumentoAHistorico(doc) {
  try {
    const proveedor = db.prepare(`
      SELECT id, razon_social, numero_registro
      FROM proveedores
      WHERE id = ?
    `).get(doc.proveedor_id);

    if (!proveedor) {
      console.warn(`⚠️ Proveedor ${doc.proveedor_id} no encontrado para mover documento ${doc.id}`);
      return false;
    }

    const ciclo = obtenerCicloParaDocumento(doc, proveedor.id);

    if (doc.id) {
      db.prepare(`
        UPDATE documentos
        SET ciclo = ?
        WHERE id = ?
      `).run(ciclo, doc.id);
    }

    if (doc.archivo === 'no_aplica') {
      if (doc.id) {
        db.prepare(`
          UPDATE documentos
          SET es_historico = 1,
              fecha_archivado = datetime('now', 'localtime'),
              estado = 'rechazado',
              comentario = 'Documento movido a histórico por vencimiento',
              ciclo = ?
          WHERE id = ?
        `).run(ciclo, doc.id);
      }

      console.log(`📄 Documento ${doc.id} (no_aplica) marcado como histórico en ciclo ${ciclo}.`);
      return true;
    }

    const rutaActual = path.join(uploadsDir, doc.archivo);

    if (!fs.existsSync(rutaActual)) {
      console.warn(`⚠️ Archivo no encontrado: ${rutaActual}`);
      return false;
    }

    const rutaHistorico = path.join(uploadsDir, String(proveedor.id), ciclo);

    if (!fs.existsSync(rutaHistorico)) {
      fs.mkdirSync(rutaHistorico, { recursive: true });
    }

    let nombreArchivo = path.basename(doc.archivo);
    let rutaNueva = path.join(rutaHistorico, nombreArchivo);

    if (fs.existsSync(rutaNueva)) {
      const ext = path.extname(nombreArchivo);
      const base = path.basename(nombreArchivo, ext);
      nombreArchivo = `${base}_${Date.now()}${ext}`;
      rutaNueva = path.join(rutaHistorico, nombreArchivo);
    }

    fs.renameSync(rutaActual, rutaNueva);

    console.log(`📦 Documento ${doc.id} movido a histórico: ${rutaNueva}`);

    const rutaRelativa = `${proveedor.id}/${ciclo}/${nombreArchivo}`;

    if (doc.id) {
      db.prepare(`
        UPDATE documentos
        SET archivo = ?,
            es_historico = 1,
            fecha_archivado = datetime('now', 'localtime'),
            estado = 'rechazado',
            comentario = 'Documento movido a histórico por vencimiento',
            ciclo = ?
        WHERE id = ?
      `).run(rutaRelativa, ciclo, doc.id);
    }

    return true;
  } catch (err) {
    console.error(`❌ Error moviendo documento ${doc.id} a histórico:`, err.message);
    return false;
  }
}

function todosDocumentosVencidos(proveedorId) {
  try {
    const countActivos = db.prepare(`
      SELECT COUNT(*) as total
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).get(proveedorId).total;

    if (countActivos === 0) return false;

    const countVencidos = db.prepare(`
      SELECT COUNT(*) as total
      FROM documentos
      WHERE proveedor_id = ?
      AND es_historico = 0
      AND fecha_vencimiento <= datetime('now', '-5 hours')
    `).get(proveedorId).total;

    return countVencidos === countActivos;
  } catch (err) {
    console.error(`Error verificando vencimientos para proveedor ${proveedorId}:`, err.message);
    return false;
  }
}

function notificarVencimientoProveedor(proveedorId) {
  try {
    const proveedor = db.prepare(`
      SELECT p.id, p.razon_social, u.email, u.nombre_empresa
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      WHERE p.id = ?
    `).get(proveedorId);

    if (!proveedor) {
      console.warn(`⚠️ Proveedor ${proveedorId} no encontrado para notificación`);
      return;
    }

    const nombreProveedor = proveedor.razon_social || proveedor.nombre_empresa || 'Proveedor';

    const yaNotificado = db.prepare(`
      SELECT id
      FROM recordatorios
      WHERE proveedor_id = ?
        AND mensaje LIKE '%documentos vencidos%'
        AND creado_en > datetime('now', '-7 days')
    `).get(proveedorId);

    if (yaNotificado) {
      console.log(`⏳ Proveedor ${nombreProveedor} ya fue notificado en los últimos 7 días.`);
      return;
    }

    const mensaje = `⚠️ Tus documentos han vencido. Por favor, contacta al administrador para iniciar un nuevo proceso de actualización y poder continuar como proveedor activo.`;

    db.prepare(`
      INSERT INTO recordatorios (proveedor_id, admin_id, admin_nombre, mensaje)
      VALUES (?, ?, ?, ?)
    `).run(proveedorId, 1, 'Sistema', mensaje);

    registrarHistorial(
      proveedorId,
      { id: 1, email: 'Sistema' },
      'recordatorio_vencimiento',
      `Notificación automática: documentos vencidos para ${nombreProveedor}`,
      null,
      null,
      null
    );

    // 🛡️ M4 (Fase 3): escapar nombre del proveedor en HTML inline del correo
    const nombreProveedorEscapado = escapeHtml(nombreProveedor);
    const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
        <h2 style="margin: 0;">⚠️ Documentos Vencidos</h2>
      </div>
      <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
        <p>Hola <strong>${nombreProveedorEscapado}</strong>,</p>
          <p>Te informamos que <strong>todos tus documentos han vencido</strong> y tu perfil como proveedor ya no está vigente.</p>
          <div style="background: #fee2e2; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
            <p style="margin: 0;">Para continuar como proveedor activo, debes contactar al administrador y solicitar un nuevo proceso de actualización.</p>
          </div>
          <p>Ingresa al portal para más información.</p>
          <div style="text-align: center; margin-top: 20px;">
            <a href="${process.env.APP_URL || 'http://localhost:3000/'}/proveedor.html"
               style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Ir al Portal
            </a>
          </div>
        </div>
      </div>
    `;

    enviarEmail(proveedor.email, '⚠️ Documentos vencidos - Actualización requerida', html)
      .then(result => {
        if (result.ok) {
          console.log(`✅ Correo de vencimiento enviado a ${proveedor.email}`);
        } else {
          console.error(`❌ Error enviando correo de vencimiento: ${result.error}`);
        }
      })
      .catch(err => console.error('Error enviando correo de vencimiento:', err));

    console.log(`📨 Notificación de vencimiento enviada al proveedor ${proveedorId}`);
  } catch (err) {
    console.error(`❌ Error notificando vencimiento a proveedor ${proveedorId}:`, err.message);
  }
}

async function procesarVencimientos() {
  console.log(`\n🔄 [CRON VENCIMIENTOS] Iniciando procesamiento - ${new Date().toLocaleString()}`);

  let movidos = 0;
  let notificados = 0;
  let errores = 0;
  const proveedoresAfectados = new Set();

  try {
    const docsVencidos = db.prepare(`
      SELECT id, proveedor_id, archivo, ciclo
      FROM documentos
      WHERE es_historico = 0
      AND fecha_vencimiento <= datetime('now', '-5 hours')
    `).all();

    if (docsVencidos.length === 0) {
      console.log('✅ No hay documentos vencidos para procesar.');
      const resultado = { movidos: 0, notificados: 0, errores: 0 };
      emitirAdmin('vencimientos_procesados', resultado);
      return resultado;
    }

    console.log(`📋 Encontrados ${docsVencidos.length} documentos vencidos.`);

    for (const doc of docsVencidos) {
      try {
        const exito = moverDocumentoAHistorico(doc);
        if (exito) {
          movidos++;
          proveedoresAfectados.add(doc.proveedor_id);
        } else {
          errores++;
        }
      } catch (err) {
        console.error(`❌ Error procesando documento ${doc.id}:`, err.message);
        errores++;
      }
    }

    for (const proveedorId of proveedoresAfectados) {
      try {
        const proveedor = db.prepare(`
          SELECT id, evaluacion_inicial, numero_registro, etapa, estado_general
          FROM proveedores
          WHERE id = ?
        `).get(proveedorId);

        if (!proveedor) continue;

        const activos = db.prepare(`
          SELECT COUNT(*) as total
          FROM documentos
          WHERE proveedor_id = ?
            AND es_historico = 0
        `).get(proveedorId).total;

        if (proveedor.etapa === 'registrado' && activos === 0) {
          console.log(`⚠️ Proveedor ${proveedorId} (${proveedor.numero_registro}) ya no tiene documentos activos.`);

          if (proveedor.evaluacion_inicial) {
            const docEvaluacion = {
              id: null,
              proveedor_id: proveedorId,
              archivo: proveedor.evaluacion_inicial,
              ciclo: proveedor.numero_registro || null
            };

            const exito = moverDocumentoAHistorico(docEvaluacion);

            if (exito) {
              db.prepare(`UPDATE proveedores SET evaluacion_inicial = NULL WHERE id = ?`).run(proveedorId);
              console.log(`📄 Evaluación inicial del proveedor ${proveedorId} movida a histórico.`);
            } else {
              console.warn(`⚠️ No se pudo mover la evaluación del proveedor ${proveedorId}.`);
            }
          }

          db.prepare(`
            UPDATE proveedores
            SET etapa = 'rechazado',
                estado_general = 'rechazado',
                notas_gestion = 'Rechazado por vencimiento de documentos'
            WHERE id = ?
          `).run(proveedorId);

          registrarHistorial(
            proveedorId,
            { id: 1, email: 'Sistema' },
            'vencimiento_automatico',
            `Proveedor rechazado automáticamente por vencimiento de todos los documentos.`,
            null,
            null,
            null
          );

          console.log(`❌ Proveedor ${proveedorId} cambiado a RECHAZADO por vencimiento.`);

          await notificarVencimientoProveedor(proveedorId);
          notificados++;
        }
      } catch (err) {
        console.error(`❌ Error procesando proveedor ${proveedorId}:`, err.message);
        errores++;
      }
    }

    console.log(`✅ CRON VENCIMIENTOS completado: ${movidos} documentos movidos, ${notificados} proveedores notificados, ${errores} errores.`);

    const resultado = { movidos, notificados, errores };
    emitirAdmin('vencimientos_procesados', resultado);
    return resultado;
  } catch (err) {
    console.error('❌ Error en procesarVencimientos:', err.message);
    const resultado = { movidos, notificados, errores };
    emitirAdmin('vencimientos_procesados', resultado);
    return resultado;
  }
}

async function forzarVencimientos() {
  console.log(`\n🔄 [FORZAR VENCIMIENTOS] Iniciando procesamiento - ${new Date().toLocaleString()}`);

  let movidos = 0;
  let notificados = 0;
  let errores = 0;
  const proveedoresAfectados = new Set();

  try {
    const docsActivos = db.prepare(`
      SELECT id, proveedor_id, archivo, ciclo
      FROM documentos
      WHERE es_historico = 0
    `).all();

    if (docsActivos.length === 0) {
      console.log('✅ No hay documentos activos para procesar.');
      return { movidos: 0, notificados: 0, errores: 0 };
    }

    console.log(`📋 Encontrados ${docsActivos.length} documentos activos.`);

    for (const doc of docsActivos) {
      try {
        const exito = moverDocumentoAHistorico(doc);
        if (exito) {
          movidos++;
          proveedoresAfectados.add(doc.proveedor_id);
        } else {
          errores++;
        }
      } catch (err) {
        console.error(`❌ Error procesando documento ${doc.id}:`, err.message);
        errores++;
      }
    }

    for (const proveedorId of proveedoresAfectados) {
      try {
        const proveedor = db.prepare(`
          SELECT id, evaluacion_inicial, numero_registro, etapa, estado_general
          FROM proveedores
          WHERE id = ?
        `).get(proveedorId);

        if (!proveedor || proveedor.etapa === 'rechazado') continue;

        if (proveedor.evaluacion_inicial) {
          const docEvaluacion = {
            id: null,
            proveedor_id: proveedorId,
            archivo: proveedor.evaluacion_inicial,
            ciclo: proveedor.numero_registro || 'sin_ciclo'
          };

          const exito = moverDocumentoAHistorico(docEvaluacion);

          if (exito) {
            db.prepare(`UPDATE proveedores SET evaluacion_inicial = NULL WHERE id = ?`).run(proveedorId);
          }
        }

        db.prepare(`
          UPDATE proveedores
          SET etapa = 'rechazado',
              estado_general = 'rechazado',
              notas_gestion = 'Rechazado por vencimiento de documentos'
          WHERE id = ?
        `).run(proveedorId);

        registrarHistorial(
          proveedorId,
          { id: 1, email: 'Sistema' },
          'vencimiento_forzado',
          `Proveedor rechazado por vencimiento forzado de todos los documentos.`,
          null,
          null,
          null
        );

        await notificarVencimientoProveedor(proveedorId);
        notificados++;
      } catch (err) {
        console.error(`❌ Error procesando proveedor ${proveedorId}:`, err.message);
        errores++;
      }
    }

    console.log(`✅ FORZAR VENCIMIENTOS completado: ${movidos} documentos movidos, ${notificados} proveedores notificados, ${errores} errores.`);

    const resultado = { movidos, notificados, errores };
    emitirAdmin('vencimientos_procesados', resultado);
    return resultado;
  } catch (err) {
    console.error('❌ Error en forzarVencimientos:', err.message);
    return { movidos, notificados, errores };
  }
}

async function enviarRecordatoriosFaltantes() {
  console.log(`\n📨 [CRON RECORDATORIOS] Iniciando envío de recordatorios - ${new Date().toLocaleString()}`);

  try {
    const proveedores = db.prepare(`
      SELECT p.id, p.razon_social, u.email, u.nombre_empresa
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      WHERE p.etapa NOT IN ('registrado', 'rechazado')
        AND (p.ultimo_recordatorio_envio IS NULL OR p.ultimo_recordatorio_envio < datetime('now', '-7 days'))
    `).all();

    if (!proveedores.length) {
      console.log('✅ No hay proveedores que necesiten recordatorios.');
      return;
    }

    let enviados = 0;

    for (const prov of proveedores) {
      const docs = db.prepare(`
        SELECT tipo, estado, no_aplica
        FROM documentos
        WHERE proveedor_id = ?
          AND es_historico = 0
      `).all(prov.id);

      const faltantes = [];

      for (const req of DOCUMENTOS_REQUERIDOS) {
        const docsTipo = docs.filter(d => d.tipo === req.tipo);
        const noAplica = docsTipo.some(d => d.no_aplica === 1);

        if (req.opcional && noAplica) continue;

        const subidosValidos = docsTipo.filter(d => d.estado === 'pendiente' || d.estado === 'aprobado').length;
        const rechazados = docsTipo.filter(d => d.estado === 'rechazado').length;

        if (subidosValidos < req.cantidadMin || rechazados > 0) {
          faltantes.push({
            nombre: req.nombre,
            estado: rechazados > 0 ? 'rechazado' : 'pendiente'
          });
        }
      }

      if (faltantes.length === 0) continue;

      const nombreProveedor = prov.razon_social || prov.nombre_empresa || 'Proveedor';
      const html = emailRecordatorioDocumentosFaltantes(nombreProveedor, faltantes);

      await enviarEmail(prov.email, '⚠️ Recordatorio - Documentos pendientes', html)
        .then(result => {
          if (result.ok) {
            console.log(`✅ Recordatorio enviado a ${prov.email}`);
            db.prepare(`UPDATE proveedores SET ultimo_recordatorio_envio = datetime('now', 'localtime') WHERE id = ?`).run(prov.id);
            enviados++;
          } else {
            console.error(`❌ Error enviando recordatorio a ${prov.email}: ${result.error}`);
          }
        })
        .catch(err => console.error(`Error enviando recordatorio a ${prov.email}:`, err));
    }

    console.log(`📨 Recordatorios enviados: ${enviados}`);
  } catch (err) {
    console.error('❌ Error en enviarRecordatoriosFaltantes:', err.message);
  }
}

// ==========================================
// 4. MULTER
// ==========================================
const storageDocs = multer.memoryStorage();

const uploadDoc = multer({
  storage: storageDocs,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() === '.pdf') cb(null, true);
    else cb(new Error('Solo se permiten archivos PDF'));
  }
});

const storagePlantillas = multer.memoryStorage();

const uploadPlantilla = multer({
  storage: storagePlantillas,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.pdf', '.doc', '.docx', '.xls', '.xlsx'].includes(ext)) cb(null, true);
    else cb(new Error('Formato no permitido'));
  }
});

// ==========================================
// 🔐 VALIDACIÓN DE ETAPA PARA SUBIDA DE DOCUMENTOS
// ==========================================
function validarEtapaParaSubida(proveedor) {
  const etapa = (proveedor.etapa || '').trim();
  const etapasPermitidas = ['verificacion', 'rechazado', ''];
  if (!etapasPermitidas.includes(etapa)) {
    const mensajes = {
      'registrado': 'Estás registrado como proveedor activo. Para actualizar tus documentos, espera la solicitud de actualización del administrador.',
      'aprobacion': 'Tus documentos están en etapa de aprobación. No puedes modificarlos en este momento.',
      'inscripcion': 'Tus documentos están en etapa de inscripción. No puedes modificarlos en este momento.'
    };
    return { valido: false, mensaje: mensajes[etapa] || 'No puedes subir documentos en la etapa actual.' };
  }
  return { valido: true };
}

// ==========================================
// 5. MIDDLEWARES DE AUTENTICACIÓN
// ==========================================
function requiereLogin(req, res, next) {
  if (!req.session.usuario) return res.status(401).json({ error: 'No autorizado' });
  next();
}

function requiereAdmin(req, res, next) {
  if (!req.session.usuario || req.session.usuario.rol !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

function requiereHabeasData(req, res, next) {
  if (!req.session.usuario) return res.status(401).json({ error: 'No autorizado' });
  if (req.session.usuario.rol === 'admin') return next();

  const consent = db.prepare(`
    SELECT aceptado
    FROM habeas_data_consent
    WHERE usuario_id = ?
      AND aceptado = 1
  `).get(req.session.usuario.id);

  if (!consent) {
    return res.status(403).json({
      error: 'Debes aceptar la Política de Tratamiento de Datos Personales para continuar.',
      requiere_habeas: true
    });
  }

  next();
}

// ==========================================
// 6. ENDPOINTS DE AUTENTICACIÓN
// ==========================================
app.post('/api/proveedor/habeas-data/aceptar', requiereLogin, (req, res) => {
  const usuarioId = req.session.usuario.id;

  const existente = db.prepare('SELECT id FROM habeas_data_consent WHERE usuario_id = ?').get(usuarioId);

  if (existente) {
    return res.status(400).json({ error: 'Ya has aceptado la política de datos' });
  }

  const ip = obtenerIP(req);
  const userAgent = req.headers['user-agent'] || '';

  db.prepare(`
    INSERT INTO habeas_data_consent (usuario_id, aceptado, fecha_aceptacion, ip_origen, user_agent, version)
    VALUES (?, 1, datetime('now', 'localtime'), ?, ?, '1.0')
  `).run(usuarioId, ip, userAgent);

  console.log(`📋 Habeas Data aceptado por usuario ${usuarioId} (${req.session.usuario.email})`);
  registrarLogSeguridad(usuarioId, req.session.usuario.email, 'habeas_data_aceptado', true, `IP: ${ip}`, req);

  res.json({ ok: true, mensaje: 'Política de datos aceptada correctamente' });
});

app.post('/api/registro', limiterUpload, (req, res) => {
const { email, password, nombre_empresa, habeas_data, website, _ts } = req.body;
if (!email || !password || !nombre_empresa) {
return res.status(400).json({ error: 'Todos los campos son obligatorios' });
}
if (!habeas_data || habeas_data !== 'true') {
return res.status(400).json({
error: 'Debe aceptar la Política de Tratamiento de Datos Personales para registrarse'
});
}
// 🛡️ M6 anti-bot (1/2) — HONEYPOT: el campo oculto lo rellenan los bots, nunca un humano.
// Respondemos 200 FALSO (idéntico al éxito real) para no revelar la trampa, y NO creamos la cuenta.
if (website && String(website).trim() !== '') {
registrarLogSeguridad(null, email || 'bot', 'registro_bot_honeypot', false, 'Honeypot rellenado', req);
return res.json({ ok: true, mensaje: 'Cuenta creada exitosamente' });
}
// 🛡️ M6 anti-bot (2/2) — TIMING: un humano tarda segundos (marca Habeas Data a mano);
// un bot envía en milisegundos. Umbral 3000 ms (ajustable). 429 reintentable, no silencioso.
const _tsNum = parseInt(_ts, 10) || 0;
const _elapsed = Date.now() - _tsNum;
if (!_tsNum || _elapsed < 3000) {
registrarLogSeguridad(null, email || 'bot', 'registro_bot_too_fast', false, `elapsed=${_elapsed}ms`, req);
return res.status(429).json({ error: 'Formulario enviado demasiado rápido. Espera unos segundos e inténtalo de nuevo.' });
}
const validacion = validarPassword(password);
  if (!validacion.valido) return res.status(400).json({ error: validacion.mensaje });

  try {
    const existente = db.prepare('SELECT id FROM usuarios WHERE email = ?').get(email);
    if (existente) return res.status(400).json({ error: 'Email ya registrado' });

    const hash = bcrypt.hashSync(password, 12);

    const result = db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password)
      VALUES (?, ?, 'proveedor', ?, 0)
    `).run(email, hash, nombre_empresa);

    const usuarioId = result.lastInsertRowid;

    const provResult = db.prepare(`
      INSERT INTO proveedores (usuario_id, razon_social)
      VALUES (?, ?)
    `).run(usuarioId, nombre_empresa);

    const proveedorId = provResult.lastInsertRowid;

    const ip = obtenerIP(req);
    const userAgent = req.headers['user-agent'] || '';

    db.prepare(`
      INSERT INTO habeas_data_consent (usuario_id, aceptado, fecha_aceptacion, ip_origen, user_agent, version)
      VALUES (?, 1, datetime('now', 'localtime'), ?, ?, '1.0')
    `).run(usuarioId, ip, userAgent);

    console.log(`✅ Habeas data registrado para usuario ${usuarioId} (${email})`);

    registrarHistorial(
      proveedorId,
      { id: usuarioId, email },
      'registro',
      `Proveedor registrado: ${nombre_empresa} - Habeas data aceptado`,
      null,
      null,
      req
    );

    registrarLogSeguridad(usuarioId, email, 'registro_proveedor', true, nombre_empresa, req);

    res.json({ ok: true, mensaje: 'Cuenta creada exitosamente' });
  } catch (err) {
    console.error('Error registrando:', err.message);
    registrarLogSeguridad(null, email, 'registro_proveedor', false, err.message, req);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/habeas-data/check', requiereLogin, (req, res) => {
  try {
    const usuarioId = req.session.usuario.id;

    const registro = db.prepare(`
      SELECT aceptado, fecha_aceptacion, version
      FROM habeas_data_consent
      WHERE usuario_id = ?
    `).get(usuarioId);

    res.json({
      aceptado: registro ? registro.aceptado === 1 : false,
      fecha_aceptacion: registro ? registro.fecha_aceptacion : null,
      version: registro ? registro.version : null
    });
  } catch (err) {
    console.error('Error verificando habeas data:', err.message);
    res.status(500).json({ error: 'Error al verificar aceptación' });
  }
});

app.get('/api/admin/habeas-data', requiereAdmin, (req, res) => {
  try {
    const aceptaciones = db.prepare(`
      SELECT hdc.id, hdc.usuario_id, u.email, u.nombre_empresa, hdc.aceptado, hdc.fecha_aceptacion, hdc.ip_origen, hdc.version, p.razon_social
      FROM habeas_data_consent hdc
      JOIN usuarios u ON hdc.usuario_id = u.id
      LEFT JOIN proveedores p ON u.id = p.usuario_id
      ORDER BY hdc.creado_en DESC
    `).all();

    res.json(aceptaciones);
  } catch (err) {
    console.error('Error obteniendo aceptaciones:', err.message);
    res.status(500).json({ error: 'Error al obtener registros' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
  if (!usuario) {
    // 🛡️ M2 (Fase 3): anti-enumeración por timing.
    // Ejecutamos un bcrypt.compareSync dummy para que el tiempo de respuesta
    // sea indistinguible del caso "email existe + contraseña incorrecta" (~200-400 ms).
    // Sin esto, un atacante puede medir el tiempo y descubrir qué emails están registrados.
    bcrypt.compareSync(password, DUMMY_BCRYPT_HASH);
    registrarLogSeguridad(null, email, 'login', false, 'Email no encontrado', req);
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

if (usuario.bloqueado_hasta) {
// 🛡️ El admin NUNCA queda bloqueado. Si por algún residuo de código anterior
// tuviera un bloqueo grabado, lo limpiamos aquí y continuamos (no devolvemos 423).
if (usuario.rol === 'admin') {
db.prepare('UPDATE usuarios SET bloqueado_hasta = NULL, intentos_fallidos = 0 WHERE id = ?').run(usuario.id);
} else {
const bloqueoHasta = new Date(usuario.bloqueado_hasta);
if (bloqueoHasta > new Date()) {
const minutos = Math.ceil((bloqueoHasta - new Date()) / 60000);
return res.status(423).json({ error: `Cuenta bloqueada. Intenta en ${minutos} minutos.` });
} else {
db.prepare('UPDATE usuarios SET bloqueado_hasta = NULL, intentos_fallidos = 0 WHERE id = ?').run(usuario.id);
}
}
}

if (!bcrypt.compareSync(password, usuario.password)) {
// 🛡️ El admin NO se bloquea por intentos fallidos (anti-DoS de bloqueo distribuido).
// Queda protegido por el rate-limit por IP (20/15 min) + bcrypt cost 12.
if (usuario.rol === 'admin') {
registrarLogSeguridad(usuario.id, email, 'login_fallido_admin', false, 'Contraseña incorrecta (admin, sin bloqueo de cuenta)', req);
return res.status(401).json({ error: 'Credenciales inválidas' });
}
const intentos = (usuario.intentos_fallidos || 0) + 1;
if (intentos >= 5) {
const bloqueo = new Date(Date.now() + 15 * 60 * 1000).toISOString();
db.prepare('UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?').run(intentos, bloqueo, usuario.id);
return res.status(423).json({ error: 'Cuenta bloqueada por 15 minutos.' });
}
db.prepare('UPDATE usuarios SET intentos_fallidos = ? WHERE id = ?').run(intentos, usuario.id);
return res.status(401).json({ error: `Credenciales inválidas. Intento ${intentos}/5` });
}

  db.prepare('UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?').run(usuario.id);

  req.session.usuario = {
    id: usuario.id,
    email: usuario.email,
    rol: usuario.rol
  };

  registrarLogSeguridad(usuario.id, email, 'login_exitoso', true, null, req);

  res.json({
    ok: true,
    rol: usuario.rol,
    debe_cambiar_password: usuario.debe_cambiar_password === 1
  });
});

app.post('/api/cambiar-password', requiereLogin, (req, res) => {
  const { password_actual, password_nueva } = req.body;

  const usuario = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.session.usuario.id);

  if (!bcrypt.compareSync(password_actual, usuario.password)) {
    return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
  }

  const validacion = validarPassword(password_nueva);
  if (!validacion.valido) return res.status(400).json({ error: validacion.mensaje });

  const hash = bcrypt.hashSync(password_nueva, 12);

  db.prepare('UPDATE usuarios SET password = ?, debe_cambiar_password = 0 WHERE id = ?').run(hash, usuario.id);

  registrarLogSeguridad(usuario.id, usuario.email, 'cambio_password', true, null, req);

  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  if (req.session.usuario) {
    registrarLogSeguridad(req.session.usuario.id, req.session.usuario.email, 'logout', true, null, req);
  }

  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.usuario) return res.json({ usuario: null });

  const u = db.prepare('SELECT debe_cambiar_password FROM usuarios WHERE id = ?').get(req.session.usuario.id);

  res.json({
    usuario: req.session.usuario,
    debe_cambiar_password: u?.debe_cambiar_password === 1
  });
});

app.post('/api/recuperar-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email es requerido' });
  }

  try {
    const usuario = db.prepare('SELECT id, email, rol FROM usuarios WHERE email = ?').get(email);

    if (!usuario) {
      console.log(`⚠️ Intento de recuperación para email no registrado: ${email}`);
      return res.json({
        ok: true,
        mensaje: 'Si el email está registrado, recibirás instrucciones para recuperar tu contraseña'
      });
    }

        const token = crypto.randomBytes(32).toString('hex');
        // 🛡️ M1 (Fase 3): guardamos el HASH del token, no el plaintext.
        // Si alguien accede a la BD, no puede usar los tokens de recuperación.
        // El token plaintext solo se usa para construir el enlace del correo.
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiracion = new Date(Date.now() + 3600000).toISOString();
        db.prepare(`
          INSERT INTO password_resets (usuario_id, token, expiracion)
          VALUES (?, ?, ?)
        `).run(usuario.id, tokenHash, expiracion);

    const sistemaUrl = (process.env.APP_URL || `http://localhost:${PORT}`)
  .trim()
  .replace(/[;,\s]+$/g, '')
  .replace(/\/+$/g, '');
const enlaceRecuperacion = `${sistemaUrl}/restablecer-password.html?token=${token}`;

    const htmlEmail = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #8600dd 0%, #6b00b0 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
          <h1 style="margin: 0; color: white;">🔐 Recuperación de Contraseña</h1>
          </div>
        <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
          <p>Hola,</p>
          <p>Has solicitado restablecer tu contraseña en el Portal de Proveedores.</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="${enlaceRecuperacion}" style="background: #8600dd; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
              Restablecer Contraseña
            </a>
          </div>
          <p style="word-break: break-all; background: #f3f4f6; padding: 10px; border-radius: 4px;">${enlaceRecuperacion}</p>
          <p>Este enlace expira en 1 hora.</p>
        </div>
      </div>
    `;

    try {
      await enviarEmail(usuario.email, '🔐 Recuperación de Contraseña - Portal de Proveedores', htmlEmail);
      console.log(`✅ Email de recuperación enviado a: ${usuario.email}`);
    } catch (emailError) {
      console.error('❌ Error enviando email de recuperación:', emailError.message);
    }

    res.json({
      ok: true,
      mensaje: 'Si el email está registrado, recibirás instrucciones para recuperar tu contraseña'
    });
  } catch (err) {
    console.error('❌ Error en recuperación de contraseña:', err.message);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

app.post('/api/restablecer-password', async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ error: 'Token y contraseña son requeridos' });
  }

  const validacion = validarPassword(password);
  if (!validacion.valido) {
    return res.status(400).json({ error: validacion.mensaje });
  }

  try {
    // 🛡️ M1 (Fase 3): comparamos contra el hash guardado, no contra plaintext.
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const resetToken = db.prepare(`
      SELECT *
      FROM password_resets
      WHERE token = ?
        AND expiracion > datetime('now')
        AND usado = 0
    `).get(tokenHash);

    if (!resetToken) {
      return res.status(400).json({
        error: 'Token inválido o expirado. Solicita un nuevo restablecimiento.'
      });
    }

    const hash = bcrypt.hashSync(password, 12);

    db.prepare(`
      UPDATE usuarios
      SET password = ?,
          debe_cambiar_password = 0,
          intentos_fallidos = 0,
          bloqueado_hasta = NULL
      WHERE id = ?
    `).run(hash, resetToken.usuario_id);

    db.prepare(`UPDATE password_resets SET usado = 1 WHERE id = ?`).run(resetToken.id);
    db.prepare(`DELETE FROM password_resets WHERE usuario_id = ? AND usado = 1`).run(resetToken.usuario_id);

    console.log(`✅ Contraseña restablecida para usuario ID: ${resetToken.usuario_id}`);

    res.json({
      ok: true,
      mensaje: 'Contraseña restablecida exitosamente. Ya puedes iniciar sesión.'
    });
  } catch (err) {
    console.error('❌ Error restableciendo contraseña:', err.message);
    res.status(500).json({ error: 'Error al restablecer la contraseña' });
  }
});

app.get('/api/verificar-token/:token', (req, res) => {
  const { token } = req.params;
  try {
    // 🛡️ M1 (Fase 3): el token viaja en plaintext en la URL, pero en BD
    // solo existe su hash. Hasheamos antes de buscar.
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const resetToken = db.prepare(`
      SELECT *
      FROM password_resets
      WHERE token = ?
        AND expiracion > datetime('now')
        AND usado = 0
    `).get(tokenHash);

    if (!resetToken) {
      return res.json({ valido: false, mensaje: 'Token inválido o expirado' });
    }

    res.json({ valido: true, mensaje: 'Token válido' });
  } catch (err) {
    console.error('Error verificando token:', err.message);
    res.status(500).json({ error: 'Error al verificar token' });
  }
});

// ==========================================
// 7. ENDPOINTS DE PROVEEDOR
// ==========================================
app.use('/api/proveedor/documentos', requiereHabeasData);
app.use('/api/proveedor/documento', requiereHabeasData);
app.use('/api/proveedor/datos', requiereHabeasData);
app.use('/api/proveedor/historial', requiereHabeasData);
app.use('/api/proveedor/recordatorios', requiereHabeasData);
app.use('/api/proveedor/notas', requiereHabeasData);
app.use('/api/proveedor/recordatorio', requiereHabeasData);
app.use('/api/proveedor/nota', requiereHabeasData);

app.get('/api/proveedor/info', requiereLogin, (req, res) => {
  const proveedor = db.prepare('SELECT * FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  if (!proveedor) {
    return res.status(404).json({ error: 'Proveedor no encontrado' });
  }

  const docs = db.prepare(`
    SELECT tipo, estado, verificado, no_aplica
    FROM documentos
    WHERE proveedor_id = ?
      AND es_historico = 0
  `).all(proveedor.id);

  let tiposSubidos = 0;

  DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
    const docsTipo = docs.filter(d => d.tipo === reqDoc.tipo);

    const subidos = docsTipo.filter(d =>
      d.estado === 'pendiente' ||
      d.estado === 'aprobado' ||
      d.estado === 'rechazado'
    ).length;

    const noAplica = docsTipo.some(d => d.no_aplica === 1);

    if (reqDoc.opcional && noAplica) {
      tiposSubidos++;
    } else if (subidos >= reqDoc.cantidadMin) {
      tiposSubidos++;
    }
  });

  const todos_subidos = (tiposSubidos === DOCUMENTOS_REQUERIDOS.length);

  let tiposVerificados = 0;

  DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
    const docsTipo = docs.filter(d => d.tipo === reqDoc.tipo);
    const verificadosTipo = docsTipo.filter(d => d.verificado === 1).length;
    const noAplica = docsTipo.some(d => d.no_aplica === 1);

    if (reqDoc.opcional && noAplica) {
      tiposVerificados++;
    } else if (verificadosTipo >= reqDoc.cantidadMin) {
      tiposVerificados++;
    }
  });

  const todos_verificados = (tiposVerificados === DOCUMENTOS_REQUERIDOS.length);

  res.json({
    ...proveedor,
    todos_subidos,
    todos_verificados
  });
});

app.post('/api/proveedor/datos', requiereLogin, (req, res) => {
  const { razon_social, rfc, representante, telefono, direccion } = req.body;

  if (!razon_social || !rfc || !representante || !telefono || !direccion ||
      !razon_social.trim() || !rfc.trim() || !representante.trim() || !telefono.trim() || !direccion.trim()) {
    return res.status(400).json({ error: 'Todos los datos de la empresa son obligatorios para desbloquear el portal.' });
  }

  const prov = db.prepare('SELECT * FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  db.prepare(`
    UPDATE proveedores
    SET razon_social = ?,
        rfc = ?,
        representante = ?,
        telefono = ?,
        direccion = ?
    WHERE usuario_id = ?
  `).run(
    razon_social.trim(),
    rfc.trim(),
    representante.trim(),
    telefono.trim(),
    direccion.trim(),
    req.session.usuario.id
  );

  registrarHistorial(
    prov.id,
    req.session.usuario,
    'datos_actualizados',
    `Datos de empresa completados. Razón social: ${razon_social}`,
    null,
    null,
    req
  );

  res.json({ ok: true, perfil_completo: true });
});

app.post('/api/proveedor/documento', requiereLogin, (req, res, next) => {
  if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
    const proveedor = db.prepare('SELECT id, etapa FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
    if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });
    const validacionEtapa = validarEtapaParaSubida(proveedor);
    if (!validacionEtapa.valido) return res.status(403).json({ error: validacionEtapa.mensaje });
    const { tipo, no_aplica } = req.body;
    const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
    if (!config) return res.status(400).json({ error: 'Tipo inválido' });

    let docId = null;

    if (no_aplica === true || no_aplica === 'true') {
      if (!config.opcional) {
        return res.status(400).json({ error: 'Este documento no tiene opción "No aplica"' });
      }

      const existente = db.prepare(`
        SELECT id
        FROM documentos
        WHERE proveedor_id = ?
          AND tipo = ?
          AND es_historico = 0
      `).get(proveedor.id, tipo);

      if (existente) {
        db.prepare(`
          UPDATE documentos
          SET no_aplica = 1,
              estado = 'pendiente',
              comentario = 'No aplica - Marcado por el proveedor',
              verificado = 1
          WHERE id = ?
        `).run(existente.id);

        docId = existente.id;

        registrarHistorial(
          proveedor.id,
          req.session.usuario,
          'documento_no_aplica',
          `Documento "${config.nombre}" marcado como NO APLICA por el proveedor`,
          tipo,
          existente.id,
          req
        );
      } else {
        const r = db.prepare(`
          INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, no_aplica, comentario, verificado)
          VALUES (?, ?, 'no_aplica', 'No aplica', 'pendiente', 1, 'No aplica - Marcado por el proveedor', 1)
        `).run(proveedor.id, tipo);

        docId = r.lastInsertRowid;

        registrarHistorial(
          proveedor.id,
          req.session.usuario,
          'documento_no_aplica',
          `Documento "${config.nombre}" marcado como NO APLICA por el proveedor (creado)`,
          tipo,
          r.lastInsertRowid,
          req
        );
      }

      actualizarEstadoProveedor(proveedor.id);

      const provActual = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(proveedor.id);
      if (provActual?.numero_registro && docId) {
        db.prepare(`
          UPDATE documentos
          SET ciclo = ?
          WHERE id = ?
            AND (ciclo IS NULL OR ciclo = '')
        `).run(provActual.numero_registro, docId);
      }

      notificarAdminDocumento(proveedor.id, req.session.usuario, config, null, 'documento_no_aplica');

      const prov = db.prepare('SELECT todos_subidos, todos_verificados, etapa FROM proveedores WHERE id = ?').get(proveedor.id);

      if (prov.todos_subidos && prov.todos_verificados && prov.etapa === 'verificacion') {
        db.prepare(`UPDATE proveedores SET etapa = 'aprobacion' WHERE id = ?`).run(proveedor.id);

        console.log(`✅ Proveedor ${proveedor.id} pasa a etapa APROBACION (todos subidos y verificados)`);

        registrarHistorial(
          proveedor.id,
          req.session.usuario,
          'cambio_etapa',
          'Todos los documentos subidos y verificados. El proveedor pasa a APROBACIÓN.',
          null,
          null,
          req
        );
      }

      return res.json({ ok: true, mensaje: 'Documento marcado como No Aplica' });
    }

    if (no_aplica === false || no_aplica === 'false') {
      if (!config.opcional) {
        return res.status(400).json({ error: 'Este documento no tiene opción "No aplica"' });
      }

      const existente = db.prepare(`
        SELECT id
        FROM documentos
        WHERE proveedor_id = ?
          AND tipo = ?
          AND es_historico = 0
      `).get(proveedor.id, tipo);

      if (existente) {
        db.prepare(`
          UPDATE documentos
          SET no_aplica = 0,
              estado = 'pendiente',
              comentario = NULL,
              verificado = 0
          WHERE id = ?
        `).run(existente.id);

        docId = existente.id;

        registrarHistorial(
          proveedor.id,
          req.session.usuario,
          'documento_requiere_carga',
          `Documento "${config.nombre}" ahora requiere carga (desmarcó No aplica)`,
          tipo,
          existente.id,
          req
        );

        actualizarEstadoProveedor(proveedor.id);

        const provActual = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(proveedor.id);
        if (provActual?.numero_registro && docId) {
          db.prepare(`
            UPDATE documentos
            SET ciclo = ?
            WHERE id = ?
              AND (ciclo IS NULL OR ciclo = '')
          `).run(provActual.numero_registro, docId);
        }

        return res.json({ ok: true, mensaje: 'Documento ahora requiere carga' });
      }

      return res.status(400).json({ error: 'No existe documento activo para desmarcar' });
    }

    return res.status(400).json({ error: 'Se requiere archivo o marcar no_aplica' });
  }

  next();
}, uploadDoc.single('archivo'), (req, res) => {
const proveedor = db.prepare('SELECT id, etapa FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });
const validacionEtapa = validarEtapaParaSubida(proveedor);
if (!validacionEtapa.valido) return res.status(403).json({ error: validacionEtapa.mensaje });
if (!req.file) return res.status(400).json({ error: 'Archivo PDF requerido' });

  const { tipo } = req.body;
  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
  if (!config) return res.status(400).json({ error: 'Tipo inválido' });

  try {
    const hashOriginal = calcularHash(req.file.buffer);
    const bufferCifrado = cifrarArchivo(req.file.buffer, ENCRYPTION_KEY);

    let docId, accion;

    const nombreArchivoCifrado = `${tipo}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.enc`;
    const carpeta = obtenerCarpetaProveedor(proveedor.id);
    const rutaArchivo = path.join(carpeta, nombreArchivoCifrado);
    const rutaRelativa = obtenerRutaRelativa(proveedor.id, nombreArchivoCifrado);

    if (tipo === 'experiencia') {
      const rechazado = db.prepare(`
        SELECT id
        FROM documentos
        WHERE proveedor_id = ?
          AND tipo = 'experiencia'
          AND estado = 'rechazado'
          AND no_aplica = 0
          AND es_historico = 0
        ORDER BY id ASC
        LIMIT 1
      `).get(proveedor.id);

      if (!rechazado) {
        const count = db.prepare(`
          SELECT COUNT(*) as total
          FROM documentos
          WHERE proveedor_id = ?
            AND tipo = 'experiencia'
            AND estado != 'rechazado'
            AND no_aplica = 0
            AND es_historico = 0
        `).get(proveedor.id).total;

        if (count >= 3) {
          return res.status(400).json({
            error: 'Ya has subido el máximo de 3 certificados de experiencia comercial.'
          });
        }
      }

      fs.writeFileSync(rutaArchivo, bufferCifrado);

      if (rechazado) {
        const docAnterior = db.prepare('SELECT archivo FROM documentos WHERE id = ?').get(rechazado.id);

        if (docAnterior && docAnterior.archivo !== 'no_aplica') {
          const rutaVieja = path.join(uploadsDir, docAnterior.archivo);
          if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
        }

        db.prepare(`
          UPDATE documentos
          SET archivo = ?,
              nombre_original = ?,
              hash_archivo = ?,
              estado = 'pendiente',
              comentario = NULL,
              no_aplica = 0,
              verificado = 0,
              subido_en = datetime('now', 'localtime')
          WHERE id = ?
        `).run(rutaRelativa, req.file.originalname, hashOriginal, rechazado.id);

        docId = rechazado.id;
        accion = 'documento_reemplazado';
      } else {
        const r = db.prepare(`
          INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
          VALUES (?, ?, ?, ?, ?, 0)
        `).run(proveedor.id, tipo, rutaRelativa, req.file.originalname, hashOriginal);

        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    } else {
      if (config.cantidadMin === 1) {
        const existente = db.prepare(`
          SELECT id, archivo, estado
          FROM documentos
          WHERE proveedor_id = ?
            AND tipo = ?
            AND es_historico = 0
        `).get(proveedor.id, tipo);

        if (existente && existente.estado === 'aprobado') {
          return res.status(400).json({
            error: 'No puedes reemplazar un documento aprobado. Contacta al administrador.'
          });
        }

        fs.writeFileSync(rutaArchivo, bufferCifrado);

        if (existente) {
          if (existente.archivo && existente.archivo !== 'no_aplica') {
            const rutaVieja = path.join(uploadsDir, existente.archivo);
            if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
          }

          db.prepare(`
            UPDATE documentos
            SET archivo = ?,
                nombre_original = ?,
                hash_archivo = ?,
                estado = 'pendiente',
                comentario = NULL,
                no_aplica = 0,
                verificado = 0,
                subido_en = datetime('now', 'localtime')
            WHERE id = ?
          `).run(rutaRelativa, req.file.originalname, hashOriginal, existente.id);

          docId = existente.id;
          accion = 'documento_reemplazado';
        } else {
          const r = db.prepare(`
            INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
            VALUES (?, ?, ?, ?, ?, 0)
          `).run(proveedor.id, tipo, rutaRelativa, req.file.originalname, hashOriginal);

          docId = r.lastInsertRowid;
          accion = 'documento_subido';
        }
      } else {
        fs.writeFileSync(rutaArchivo, bufferCifrado);

        const r = db.prepare(`
          INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
          VALUES (?, ?, ?, ?, ?, 0)
        `).run(proveedor.id, tipo, rutaRelativa, req.file.originalname, hashOriginal);

        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    }

    registrarHistorial(
      proveedor.id,
      req.session.usuario,
      accion,
      `Documento "${config.nombre}" subido: ${req.file.originalname}`,
      tipo,
      docId,
      req
    );

    actualizarEstadoProveedor(proveedor.id);

    const provActual = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(proveedor.id);
    if (provActual?.numero_registro && docId) {
      db.prepare(`
        UPDATE documentos
        SET ciclo = ?
        WHERE id = ?
          AND (ciclo IS NULL OR ciclo = '')
      `).run(provActual.numero_registro, docId);
    }

    notificarAdminDocumento(proveedor.id, req.session.usuario, config, req.file.originalname, accion);

    emitirTodos(proveedor.id, 'documento_subido', {
      tipo: tipo,
      proveedorId: proveedor.id,
      accion: accion,
      documentoId: docId
    });

    emitirAdmin('estadisticas_actualizadas');

    return res.json({ ok: true });
  } catch (err) {
    console.error('Error cifrando archivo:', err);
    return res.status(500).json({ error: 'Error al procesar el documento' });
  }
});

app.post('/api/proveedor/documento/:id/no-aplica', requiereLogin, (req, res) => {
  const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  const doc = db.prepare(`
    SELECT *
    FROM documentos
    WHERE id = ?
      AND proveedor_id = ?
  `).get(req.params.id, proveedor.id);

  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });

  if (doc.es_historico === 1) {
    return res.status(400).json({
      error: 'Este documento es histórico y no puede modificarse.'
    });
  }

  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);

  if (!config || !config.opcional) {
    return res.status(400).json({ error: 'Este documento no tiene opción "No aplica"' });
  }

  const { no_aplica } = req.body;

  if (no_aplica) {
    db.prepare(`
      UPDATE documentos
      SET no_aplica = 1,
          estado = 'pendiente',
          comentario = 'No aplica - Marcado por el proveedor',
          verificado = 1
      WHERE id = ?
    `).run(doc.id);

    registrarHistorial(
      proveedor.id,
      req.session.usuario,
      'documento_no_aplica',
      `Documento "${config.nombre}" marcado como NO APLICA`,
      doc.tipo,
      doc.id,
      req
    );
  } else {
    db.prepare(`
      UPDATE documentos
      SET no_aplica = 0,
          estado = 'pendiente',
          comentario = NULL,
          verificado = 0
      WHERE id = ?
    `).run(doc.id);

    registrarHistorial(
      proveedor.id,
      req.session.usuario,
      'documento_requiere_carga',
      `Documento "${config.nombre}" ahora requiere carga`,
      doc.tipo,
      doc.id,
      req
    );
  }

  actualizarEstadoProveedor(proveedor.id);

  res.json({ ok: true });
});

app.delete('/api/proveedor/documento/:id', requiereLogin, (req, res) => {
  const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  const doc = db.prepare(`
    SELECT *
    FROM documentos
    WHERE id = ?
      AND proveedor_id = ?
  `).get(req.params.id, proveedor.id);

  if (!doc) return res.status(404).json({ error: 'No encontrado' });

  if (doc.es_historico === 1) {
    return res.status(400).json({
      error: 'Este documento es histórico y no puede eliminarse.'
    });
  }

  if (doc.verificado === 1 || doc.estado === 'aprobado') {
    return res.status(400).json({
      error: 'No puedes eliminar un documento que ya ha sido verificado o aprobado.'
    });
  }

  if (doc.archivo && doc.archivo !== 'no_aplica') {
    const ruta = path.join(uploadsDir, doc.archivo);
    if (fs.existsSync(ruta)) fs.unlinkSync(ruta);
  }

  db.prepare('DELETE FROM documentos WHERE id = ?').run(doc.id);

  registrarHistorial(
    proveedor.id,
    req.session.usuario,
    'documento_eliminado',
    `Documento eliminado: ${doc.nombre_original}`,
    doc.tipo,
    doc.id,
    req
  );

  actualizarEstadoProveedor(proveedor.id);

  res.json({ ok: true });
});

app.get('/api/proveedor/documentos', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  res.json(db.prepare(`
    SELECT *
    FROM documentos
    WHERE proveedor_id = ?
      AND es_historico = 0
    ORDER BY id
  `).all(p.id));
});

app.get('/api/proveedor/requerimientos', requiereLogin, (req, res) => {
  const requeridos = DOCUMENTOS_REQUERIDOS.map(r => {
    let plantilla = null;

    if (r.esPlantilla) {
      plantilla = db.prepare('SELECT archivo, nombre_original FROM plantillas WHERE tipo = ?').get(r.tipo);
    }

    return { ...r, plantilla };
  });

  res.json(requeridos);
});

app.get('/api/proveedor/plantilla/:tipo', requiereLogin, (req, res) => {
  const { tipo } = req.params;

  const plantilla = db.prepare('SELECT * FROM plantillas WHERE tipo = ?').get(tipo);

  if (!plantilla) {
    return res.status(404).json({ error: 'Plantilla no encontrada' });
  }

  const rutaPlantilla = path.join(plantillasDir, plantilla.archivo);

  if (!fs.existsSync(rutaPlantilla)) {
    return res.status(404).json({ error: 'Archivo de plantilla no encontrado' });
  }

  const extension = path.extname(plantilla.archivo).toLowerCase();

  const mimeTypes = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  };

  const mimeType = mimeTypes[extension] || 'application/octet-stream';

  res.setHeader('Content-Type', mimeType);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(plantilla.nombre_original)}"`);
  res.setHeader('Content-Length', fs.statSync(rutaPlantilla).size);

  const fileStream = fs.createReadStream(rutaPlantilla);
  fileStream.pipe(res);

  fileStream.on('error', (err) => {
    console.error('Error enviando plantilla:', err);
    res.status(500).json({ error: 'Error al descargar la plantilla' });
  });
});

app.get('/api/proveedor/historial', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  res.json(db.prepare(`
    SELECT *
    FROM historial
    WHERE proveedor_id = ?
    ORDER BY creado_en DESC
    LIMIT 200
  `).all(p.id));
});

app.get('/api/proveedor/recordatorios', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  res.json(db.prepare(`
    SELECT *
    FROM recordatorios
    WHERE proveedor_id = ?
      AND (cerrada = 0 OR cerrada IS NULL)
    ORDER BY creado_en DESC
  `).all(p.id));
});

app.post('/api/proveedor/recordatorio/:id/leido', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  db.prepare(`
    UPDATE recordatorios
    SET leido = 1
    WHERE id = ?
      AND proveedor_id = ?
  `).run(req.params.id, p.id);

  res.json({ ok: true });
});

app.get('/api/proveedor/notas', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  res.json(db.prepare(`
    SELECT *
    FROM notas_proveedor
    WHERE proveedor_id = ?
      AND (cerrada = 0 OR cerrada IS NULL)
    ORDER BY creado_en DESC
  `).all(p.id));
});

app.post('/api/proveedor/nota/:id/leida', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);

  db.prepare(`
    UPDATE notas_proveedor
    SET leida = 1
    WHERE id = ?
      AND proveedor_id = ?
  `).run(req.params.id, p.id);

  res.json({ ok: true });
});

app.post('/api/proveedor/nota/:id/cerrar', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  if (!p) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const nota = db.prepare(`
    SELECT id
    FROM notas_proveedor
    WHERE id = ?
      AND proveedor_id = ?
  `).get(req.params.id, p.id);

  if (!nota) return res.status(404).json({ error: 'Nota no encontrada' });

  db.prepare(`
    UPDATE notas_proveedor
    SET cerrada = 1,
        leida = 1
    WHERE id = ?
  `).run(req.params.id);

  res.json({ ok: true, mensaje: 'Nota cerrada' });
});

app.post('/api/proveedor/recordatorio/:id/cerrar', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  if (!p) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const rec = db.prepare(`
    SELECT id
    FROM recordatorios
    WHERE id = ?
      AND proveedor_id = ?
  `).get(req.params.id, p.id);

  if (!rec) return res.status(404).json({ error: 'Recordatorio no encontrado' });

  db.prepare(`
    UPDATE recordatorios
    SET cerrada = 1,
        leido = 1
    WHERE id = ?
  `).run(req.params.id);

  res.json({ ok: true, mensaje: 'Recordatorio cerrado' });
});

// ==========================================
// 8. ENDPOINTS DE ADMINISTRADOR
// ==========================================
app.post('/api/admin/forzar-vencimientos', requiereAdmin, async (req, res) => {
  try {
    const resultado = await forzarVencimientos();

    res.json({
      ok: true,
      mensaje: 'Procesamiento forzado de vencimientos completado',
      ...resultado
    });
  } catch (err) {
    console.error('Error forzando vencimientos:', err);
    res.status(500).json({ error: 'Error al forzar el procesamiento: ' + err.message });
  }
});

app.delete('/api/admin/documento/:id', requiereAdmin, (req, res) => {
  try {
    const doc = db.prepare('SELECT * FROM documentos WHERE id = ?').get(req.params.id);

    if (!doc) {
      return res.status(404).json({ error: 'Documento no encontrado' });
    }

    if (doc.es_historico === 1) {
      return res.status(400).json({
        error: 'Este documento es histórico y no puede eliminarse.'
      });
    }

    if (doc.archivo && doc.archivo !== 'no_aplica') {
      const ruta = path.join(uploadsDir, doc.archivo);
      if (fs.existsSync(ruta)) {
        fs.unlinkSync(ruta);
      }
    }

    db.prepare('DELETE FROM documentos WHERE id = ?').run(doc.id);

    registrarHistorial(
      doc.proveedor_id,
      req.session.usuario,
      'documento_eliminado',
      `Documento eliminado por admin: ${doc.nombre_original} (${doc.tipo})`,
      doc.tipo,
      doc.id,
      req
    );

    actualizarEstadoProveedor(doc.proveedor_id);

    res.json({ ok: true, mensaje: 'Documento eliminado correctamente' });
  } catch (err) {
    console.error('Error eliminando documento por admin:', err);
    res.status(500).json({ error: 'Error al eliminar el documento' });
  }
});

app.get('/api/admin/proveedores', requiereAdmin, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const busqueda = req.query.busqueda ? `%${req.query.busqueda}%` : null;
    const estado = req.query.estado || null;
    const filtroVerificacion = req.query.filtroVerificacion || null;
    const modulo = req.query.modulo || null;

    let whereConditions = [];
    let params = [];

    if (modulo && modulo !== 'registrados') {
      let etapa = null;

      switch (modulo) {
        case 'verificacion':
          etapa = 'verificacion';
          break;
        case 'aprobacion':
          etapa = 'aprobacion';
          break;
        case 'inscripcion':
          etapa = 'inscripcion';
          break;
        default:
          break;
      }

      if (etapa) {
        whereConditions.push('p.etapa = ?');
        params.push(etapa);
      }
    }

    if (modulo === 'registrados') {
      if (!estado || estado === 'todos') {
        whereConditions.push('p.etapa IN (?, ?)');
        params.push('registrado', 'rechazado');
      } else if (estado === 'aprobado') {
        whereConditions.push('p.estado_general = ? AND p.etapa = ?');
        params.push('aprobado', 'registrado');
      } else if (estado === 'rechazado') {
        whereConditions.push('p.etapa = ?');
        params.push('rechazado');
      }
    }

    if (modulo === 'registrados' && filtroVerificacion) {
      if (filtroVerificacion === 'pendiente_verificar') {
        whereConditions.push('p.estado_general = ? AND p.todos_subidos = ? AND p.todos_verificados = ?');
        params.push('pendiente', 1, 0);
      } else if (filtroVerificacion === 'verificado_pendiente_aprobacion') {
        whereConditions.push('p.estado_general = ? AND p.todos_subidos = ? AND p.todos_verificados = ?');
        params.push('pendiente', 1, 1);
      }
    }

    if (busqueda) {
      whereConditions.push(`(
        p.razon_social LIKE ? OR
        u.nombre_empresa LIKE ? OR
        p.rfc LIKE ? OR
        u.email LIKE ? OR
        p.representante LIKE ? OR
        p.telefono LIKE ?
      )`);

      for (let i = 0; i < 6; i++) params.push(busqueda);
    }

    const whereClause = whereConditions.length ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const countQuery = `
      SELECT COUNT(*) as total
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      ${whereClause}
    `;

    const total = db.prepare(countQuery).get(...params).total;

    const query = `
      SELECT
        p.*,
        u.email,
        u.nombre_empresa,
        p.etapa,
        p.evaluacion_inicial,
        p.evaluacion_estado,
        p.evaluacion_fecha,
        p.numero_registro,
        p.tipo_gestion,
        p.notas_gestion,
        p.fecha_gestion
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      ${whereClause}
      ORDER BY p.id DESC
      LIMIT ? OFFSET ?
    `;

    const proveedores = db.prepare(query).all(...params, limit, offset);

    proveedores.forEach(p => {
      const docs = db.prepare(`
        SELECT tipo, estado, verificado, no_aplica
        FROM documentos
        WHERE proveedor_id = ?
          AND es_historico = 0
      `).all(p.id);

      const agrupado = {};

      docs.forEach(d => {
        if (!agrupado[d.tipo]) agrupado[d.tipo] = [];
        agrupado[d.tipo].push(d.estado);
      });

      let aprobados = 0;

      DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
        const estados = agrupado[reqDoc.tipo] || [];
        if (estados.filter(e => e === 'aprobado').length >= reqDoc.cantidadMin) {
          aprobados++;
        }
      });

p.aprobados = aprobados;
p.total = DOCUMENTOS_REQUERIDOS.length;
// 🏷️ Conteo de tipos VERIFICADOS (o no-aplica) para el medidor de la pestaña Verificación.
// Espeja la lógica de "todos_verificados" de /api/proveedor/info y de actualizarEstadoProveedor:
// un tipo cuenta si es opcional con no_aplica=1, o si tiene >= cantidadMin docs con verificado=1.
let verificados = 0;
DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
const docsTipo = docs.filter(d => d.tipo === reqDoc.tipo);
const verificadosTipo = docsTipo.filter(d => d.verificado === 1).length;
const noAplica = docsTipo.some(d => d.no_aplica === 1);
if (reqDoc.opcional && noAplica) {
verificados++;
} else if (verificadosTipo >= reqDoc.cantidadMin) {
verificados++;
}
});
p.verificados = verificados;

      const recs = db.prepare('SELECT COUNT(*) as n FROM recordatorios WHERE proveedor_id = ? AND leido = 0').get(p.id);
      p.recordatorios_pendientes = recs.n;

      const notasCount = db.prepare('SELECT COUNT(*) as n FROM notas_proveedor WHERE proveedor_id = ?').get(p.id);
      p.notas_count = notasCount.n;

      if (p.estado_general === 'aprobado') {
        p.fecha_aprobacion = p.fecha_aprobacion || null;
      } else {
        p.fecha_aprobacion = null;
      }

      p.todos_subidos = p.todos_subidos === 1;
      p.todos_verificados = p.todos_verificados === 1;
    });

    const totalPages = Math.ceil(total / limit);

    res.json({
      data: proveedores,
      total,
      page,
      limit,
      totalPages
    });
  } catch (err) {
    console.error('❌ Error en /api/admin/proveedores:', err);
    res.status(500).json({ error: 'Error al cargar proveedores: ' + err.message });
  }
});

app.get('/api/admin/ciclos', requiereAdmin, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const busqueda = req.query.busqueda ? `%${req.query.busqueda}%` : null;
    const año = req.query.año ? parseInt(req.query.año) : null;
    const rfc = req.query.rfc ? `%${req.query.rfc}%` : null;
    const estado = req.query.estado || null;

    let whereConditions = [];
    let params = [];

    if (busqueda) {
      whereConditions.push(`(
        p.razon_social LIKE ? OR
        u.nombre_empresa LIKE ? OR
        u.email LIKE ?
      )`);

      for (let i = 0; i < 3; i++) params.push(busqueda);
    }

    if (año) {
      whereConditions.push(`strftime('%Y', c.fecha_inicio) = ?`);
      params.push(String(año));
    }

    if (rfc) {
      whereConditions.push(`p.rfc LIKE ?`);
      params.push(rfc);
    }

    if (estado && ['activo', 'cerrado', 'rechazado'].includes(estado)) {
      whereConditions.push(`c.estado = ?`);
      params.push(estado);
    }

    const whereClause = whereConditions.length ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const countQuery = `
      SELECT COUNT(*) as total
      FROM ciclos_actualizacion c
      JOIN proveedores p ON c.proveedor_id = p.id
      JOIN usuarios u ON p.usuario_id = u.id
      ${whereClause}
    `;

    const total = db.prepare(countQuery).get(...params).total;

    const query = `
      SELECT
        c.id,
        c.proveedor_id,
        c.numero_registro,
        c.fecha_inicio,
        c.fecha_fin,
        c.estado,
        c.creado_en,
        p.razon_social,
        u.email,
        u.nombre_empresa,
        (SELECT COUNT(*) FROM documentos WHERE proveedor_id = p.id AND ciclo = c.numero_registro) as total_documentos,
        (SELECT COUNT(*) FROM documentos WHERE proveedor_id = p.id AND ciclo = c.numero_registro AND estado = 'aprobado') as documentos_aprobados
      FROM ciclos_actualizacion c
      JOIN proveedores p ON c.proveedor_id = p.id
      JOIN usuarios u ON p.usuario_id = u.id
      ${whereClause}
      ORDER BY c.fecha_inicio DESC, c.id DESC
      LIMIT ? OFFSET ?
    `;

    const ciclos = db.prepare(query).all(...params, limit, offset);
    const totalPages = Math.ceil(total / limit);

    res.json({
      data: ciclos,
      total,
      page,
      limit,
      totalPages
    });
  } catch (err) {
    console.error('❌ Error en /api/admin/ciclos:', err);
    res.status(500).json({ error: 'Error al cargar el historial de ciclos: ' + err.message });
  }
});

app.get('/api/admin/ciclos/:id/documentos', requiereAdmin, (req, res) => {
  try {
    const cicloId = parseInt(req.params.id);

const ciclo = db.prepare(`
SELECT c.*, p.razon_social, u.email, p.evaluacion_inicial, p.evaluacion_estado, p.evaluacion_fecha
FROM ciclos_actualizacion c
JOIN proveedores p ON c.proveedor_id = p.id
JOIN usuarios u ON p.usuario_id = u.id
WHERE c.id = ?
`).get(cicloId);

    if (!ciclo) {
      return res.status(404).json({ error: 'Ciclo no encontrado' });
    }

    const documentos = db.prepare(`
      SELECT d.*,
        CASE
          WHEN d.fecha_vencimiento IS NOT NULL AND d.fecha_vencimiento <= datetime('now', '-5 hours') THEN 'vencido'
          WHEN d.fecha_vencimiento IS NOT NULL AND d.fecha_vencimiento <= datetime('now', '-5 hours', '+30 days') THEN 'proximo_a_vencer'
          ELSE 'vigente'
        END as estado_vencimiento
      FROM documentos d
      WHERE d.proveedor_id = ?
        AND d.ciclo = ?
ORDER BY d.tipo, d.id
`).all(ciclo.proveedor_id, ciclo.numero_registro);
const evaluacion = resolverEvaluacionDelCiclo(ciclo);
res.json({
ciclo,
documentos,
evaluacion
});
  } catch (err) {
    console.error('❌ Error en /api/admin/ciclos/:id/documentos:', err);
    res.status(500).json({ error: 'Error al obtener documentos del ciclo' });
  }
});

app.get('/api/admin/ciclos/:id/zip', requiereAdmin, async (req, res) => {
  const cicloId = parseInt(req.params.id);

  try {
    const ciclo = db.prepare(`
SELECT c.*, p.razon_social, p.id as proveedor_id, p.evaluacion_inicial, p.evaluacion_estado, p.evaluacion_fecha
FROM ciclos_actualizacion c
JOIN proveedores p ON c.proveedor_id = p.id
WHERE c.id = ?
`).get(cicloId);

    if (!ciclo) {
      return res.status(404).json({ error: 'Ciclo no encontrado' });
    }

const documentos = db.prepare(`
SELECT archivo, nombre_original, tipo, estado
FROM documentos
WHERE proveedor_id = ?
AND ciclo = ?
`).all(ciclo.proveedor_id, ciclo.numero_registro);
const evaluacion = resolverEvaluacionDelCiclo(ciclo);
if ((!documentos || documentos.length === 0) && !evaluacion) {
return res.status(404).json({ error: 'Este ciclo no tiene documentos asociados' });
}

    const nombreProveedor = ciclo.razon_social || `Proveedor_${ciclo.proveedor_id}`;
    const nombreZip = `${nombreProveedor.replace(/[^a-zA-Z0-9]/g, '_')}_Ciclo_${ciclo.numero_registro}.zip`;

    const nombreProveedorLimpio = nombreProveedor
      .replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-_]/g, '')
      .trim()
      .replace(/\s+/g, '_');

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(nombreZip)}"`);

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    let agregados = 0;
const contadorTipos = {};
// 🏷️ FIX: incluir la Evaluación Inicial del ciclo en el ZIP (activa o histórica),
//   coherente con el ZIP de proveedor. Se descifra igual que el resto de documentos.
if (evaluacion && evaluacion.archivo && evaluacion.archivo !== 'no_aplica') {
try {
const rutaEval = path.join(uploadsDir, evaluacion.archivo);
if (fs.existsSync(rutaEval)) {
const bufferCifrado = fs.readFileSync(rutaEval);
let bufferDescifrado;
try {
bufferDescifrado = descifrarArchivo(bufferCifrado, ENCRYPTION_KEY);
} catch (decryptErr) {
console.warn(`⚠️ Error descifrando evaluación del ciclo: ${decryptErr.message}. Se incluirá tal cual.`);
bufferDescifrado = bufferCifrado;
}
archive.append(bufferDescifrado, { name: `${nombreProveedorLimpio} - Evaluación Inicial.pdf` });
agregados++;
console.log(`📄 Evaluación inicial agregada al ZIP del ciclo ${ciclo.numero_registro}`);
} else {
console.warn(`⚠️ Archivo de evaluación del ciclo no encontrado: ${rutaEval}`);
}
} catch (err) {
console.error(`❌ Error procesando evaluación del ciclo: ${err.message}`);
}
}
for (const doc of documentos) {
      try {
        if (doc.archivo === 'no_aplica') continue;

        const rutaArchivo = path.join(uploadsDir, doc.archivo);

        if (!fs.existsSync(rutaArchivo)) {
          console.warn(`⚠️ Archivo no encontrado: ${rutaArchivo}`);
          continue;
        }

        const bufferCifrado = fs.readFileSync(rutaArchivo);

        let bufferDescifrado;

        try {
          bufferDescifrado = descifrarArchivo(bufferCifrado, ENCRYPTION_KEY);
        } catch (decryptErr) {
          console.warn(`⚠️ Error descifrando ${doc.archivo}: ${decryptErr.message}. Se incluirá cifrado.`);
          bufferDescifrado = bufferCifrado;
        }

        const configDoc = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);
        let nombreBase = configDoc ? configDoc.nombre : doc.tipo;

        nombreBase = nombreBase.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-_]/g, '').trim();
        if (!nombreBase) nombreBase = doc.tipo;

        if (!contadorTipos[doc.tipo]) contadorTipos[doc.tipo] = 0;
        contadorTipos[doc.tipo]++;

        let nombreArchivo = `${nombreProveedorLimpio} - ${nombreBase}.pdf`;

        if (contadorTipos[doc.tipo] > 1) {
          nombreArchivo = `${nombreProveedorLimpio} - ${nombreBase}_${contadorTipos[doc.tipo]}.pdf`;
        }

        archive.append(bufferDescifrado, { name: nombreArchivo });
        agregados++;
      } catch (err) {
        console.error(`❌ Error procesando documento ${doc.id}:`, err.message);
      }
    }

    await archive.finalize();

    console.log(`📦 ZIP generado para ciclo ${ciclo.numero_registro}: ${agregados} archivos`);
  } catch (err) {
    console.error('❌ Error generando ZIP del ciclo:', err);

    if (!res.headersSent) {
      res.status(500).json({ error: 'Error al generar el ZIP: ' + err.message });
    }
  }
});

app.get('/api/admin/ciclos/anos', requiereAdmin, (req, res) => {
  try {
    const anos = db.prepare(`
      SELECT DISTINCT strftime('%Y', fecha_inicio) as año
      FROM ciclos_actualizacion
      ORDER BY año DESC
    `).all();

    res.json(anos.map(a => a.año).filter(a => a !== null));
  } catch (err) {
    console.error('❌ Error obteniendo años:', err);
    res.status(500).json({ error: 'Error al obtener años' });
  }
});

app.get('/api/admin/configuracion', requiereAdmin, (req, res) => {
  try {
    const config = db.prepare(`
      SELECT clave, valor, descripcion, actualizado_en
      FROM configuracion
      WHERE clave = 'fecha_vencimiento_fija'
    `).get();

    if (!config) {
      const fechaDefault = '2026-12-31 23:59:59';

      db.prepare(`
        INSERT INTO configuracion (clave, valor, descripcion)
        VALUES (?, ?, ?)
      `).run(
        'fecha_vencimiento_fija',
        fechaDefault,
        'Fecha fija de vencimiento de los documentos aprobados (formato YYYY-MM-DD HH:MM:SS)'
      );

      return res.json({
        clave: 'fecha_vencimiento_fija',
        valor: fechaDefault,
        descripcion: 'Fecha fija de vencimiento de los documentos aprobados',
        actualizado_en: new Date().toISOString()
      });
    }

    res.json(config);
  } catch (err) {
    console.error('❌ Error obteniendo configuración:', err);
    res.status(500).json({ error: 'Error al obtener configuración: ' + err.message });
  }
});

app.put('/api/admin/configuracion', requiereAdmin, (req, res) => {
  const { valor } = req.body;
  if (!valor) {
    return res.status(400).json({ error: 'Debes proporcionar una fecha y hora' });
  }
  // 🕐 FIX TZ: datetime-local del admin = hora civil Bogotá (UTC-5 fijo).
  // NO pasar por new Date()/toISOString() (en Railway/UTC desplaza 5h).
  const m = String(valor).match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?/);
  if (!m) {
    return res.status(400).json({ error: 'Fecha inválida. Usa formato YYYY-MM-DDTHH:mm' });
  }
  const fechaStr = `${m[1]} ${m[2]}:${m[3] || '00'}`;
  try {
    db.prepare(`
      UPDATE configuracion
      SET valor = ?,
      actualizado_en = datetime('now', 'localtime')
      WHERE clave = 'fecha_vencimiento_fija'
    `).run(fechaStr);

    registrarLogSeguridad(
      req.session.usuario.id,
      req.session.usuario.email,
      'configuracion_actualizada',
      true,
      `Fecha de vencimiento actualizada a ${fechaStr}`,
      req
    );

    res.json({
      ok: true,
      mensaje: `✅ Fecha de vencimiento actualizada a ${fechaStr}`,
      valor: fechaStr
    });
  } catch (err) {
    console.error('❌ Error actualizando configuración:', err);
    res.status(500).json({ error: 'Error al actualizar configuración: ' + err.message });
  }
});

app.post('/api/admin/recalcular-vencimientos', requiereAdmin, async (req, res) => {
  try {
    const fechaVencimientoObj = obtenerFechaVencimiento();
    const fechaStr = fechaVencimientoObj.toISOString().replace('T', ' ').slice(0, 19);

    const docs = db.prepare(`
      SELECT id
      FROM documentos
      WHERE estado = 'aprobado'
        AND es_historico = 0
    `).all();

    if (docs.length === 0) {
      return res.json({
        ok: true,
        mensaje: 'No hay documentos aprobados activos para recalcular.',
        actualizados: 0,
        fecha: fechaStr
      });
    }

    let actualizados = 0;
    const updateStmt = db.prepare(`UPDATE documentos SET fecha_vencimiento = ? WHERE id = ?`);

    for (const doc of docs) {
      updateStmt.run(fechaStr, doc.id);
      actualizados++;
    }

    registrarLogSeguridad(
      req.session.usuario.id,
      req.session.usuario.email,
      'recalcular_vencimientos',
      true,
      `Recalculadas fechas de vencimiento para ${actualizados} documentos a ${fechaStr}`,
      req
    );

    res.json({
      ok: true,
      mensaje: `✅ Fechas de vencimiento actualizadas a ${fechaStr} para ${actualizados} documentos`,
      actualizados,
      fecha: fechaStr
    });
  } catch (err) {
    console.error('❌ Error recalculando vencimientos:', err);
    res.status(500).json({ error: 'Error al recalcular fechas de vencimiento: ' + err.message });
  }
});

app.post('/api/admin/ejecutar-vencimientos', requiereAdmin, async (req, res) => {
  try {
    const resultado = await procesarVencimientos();

    res.json({
      ok: true,
      mensaje: 'Procesamiento de vencimientos completado',
      ...resultado
    });
  } catch (err) {
    console.error('Error ejecutando vencimientos:', err);
    res.status(500).json({ error: 'Error al ejecutar el procesamiento: ' + err.message });
  }
});

app.get('/api/admin/proveedores/export', requiereAdmin, (req, res) => {
  try {
    const busqueda = req.query.busqueda ? `%${req.query.busqueda}%` : null;
    const estado = req.query.estado || null;

    let whereConditions = [];
    let params = [];

    if (estado && estado !== 'todos') {
      whereConditions.push('p.estado_general = ?');
      params.push(estado);
    }

    if (busqueda) {
      whereConditions.push(`(
        p.razon_social LIKE ? OR
        u.nombre_empresa LIKE ? OR
        p.rfc LIKE ? OR
        u.email LIKE ? OR
        p.representante LIKE ? OR
        p.telefono LIKE ?
      )`);

      for (let i = 0; i < 6; i++) params.push(busqueda);
    }

    const whereClause = whereConditions.length ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const query = `
      SELECT p.*, u.email, u.nombre_empresa
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      ${whereClause}
      ORDER BY p.id DESC
    `;

    const proveedores = db.prepare(query).all(...params);

    proveedores.forEach(p => {
      const docs = db.prepare(`
        SELECT tipo, estado, verificado, no_aplica
        FROM documentos
        WHERE proveedor_id = ?
          AND es_historico = 0
      `).all(p.id);

      const agrupado = {};

      docs.forEach(d => {
        if (!agrupado[d.tipo]) agrupado[d.tipo] = [];
        agrupado[d.tipo].push(d.estado);
      });

      let aprobados = 0;

      DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
        const estados = agrupado[reqDoc.tipo] || [];
        if (estados.filter(e => e === 'aprobado').length >= reqDoc.cantidadMin) {
          aprobados++;
        }
      });

p.aprobados = aprobados;
p.total = DOCUMENTOS_REQUERIDOS.length;
// 🏷️ Conteo de tipos VERIFICADOS (o no-aplica) para el medidor de la pestaña Verificación.
// Espeja la lógica de "todos_verificados" de /api/proveedor/info y de actualizarEstadoProveedor:
// un tipo cuenta si es opcional con no_aplica=1, o si tiene >= cantidadMin docs con verificado=1.
let verificados = 0;
DOCUMENTOS_REQUERIDOS.forEach(reqDoc => {
const docsTipo = docs.filter(d => d.tipo === reqDoc.tipo);
const verificadosTipo = docsTipo.filter(d => d.verificado === 1).length;
const noAplica = docsTipo.some(d => d.no_aplica === 1);
if (reqDoc.opcional && noAplica) {
verificados++;
} else if (verificadosTipo >= reqDoc.cantidadMin) {
verificados++;
}
});
p.verificados = verificados;

      const recs = db.prepare('SELECT COUNT(*) as n FROM recordatorios WHERE proveedor_id = ? AND leido = 0').get(p.id);
      p.recordatorios_pendientes = recs.n;

      const notasCount = db.prepare('SELECT COUNT(*) as n FROM notas_proveedor WHERE proveedor_id = ?').get(p.id);
      p.notas_count = notasCount.n;

      if (p.estado_general === 'aprobado') {
        p.fecha_aprobacion = p.fecha_aprobacion || null;
      } else {
        p.fecha_aprobacion = null;
      }

      p.todos_subidos = p.todos_subidos === 1;
      p.todos_verificados = p.todos_verificados === 1;
    });

    res.json({ data: proveedores });
  } catch (err) {
    console.error('❌ Error en exportación de proveedores:', err);
    res.status(500).json({ error: 'Error al exportar proveedores: ' + err.message });
  }
});

app.get('/api/admin/stats', requiereAdmin, (req, res) => {
  try {
    const registrados = db.prepare(`SELECT COUNT(*) as count FROM proveedores WHERE etapa = 'registrado'`).get().count;

    const verificacion = db.prepare(`
      SELECT COUNT(*) as count
      FROM proveedores
      WHERE etapa = 'verificacion'
        AND todos_verificados = 0
    `).get().count;

    const aprobacion = db.prepare(`
      SELECT COUNT(*) as count
      FROM proveedores
      WHERE etapa = 'aprobacion'
        AND (evaluacion_estado IS NULL OR evaluacion_estado != 'aprobado')
    `).get().count;

    const inscripcion = db.prepare(`
      SELECT COUNT(*) as count
      FROM proveedores
      WHERE etapa = 'inscripcion'
    `).get().count;

    const rechazados = db.prepare(`
      SELECT COUNT(*) as count
      FROM proveedores
      WHERE etapa = 'rechazado'
    `).get().count;

    res.json({
      registrados,
      verificacion,
      aprobacion,
      inscripcion,
      rechazados
    });
  } catch (err) {
    console.error('❌ Error obteniendo estadísticas:', err);
    res.status(500).json({ error: 'Error al obtener estadísticas' });
  }
});

app.get('/api/admin/proveedor/:id/gestion', requiereAdmin, (req, res) => {
  try {
    const proveedor = db.prepare(`
      SELECT numero_registro, tipo_gestion, notas_gestion, fecha_gestion
      FROM proveedores
      WHERE id = ?
    `).get(req.params.id);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    res.json({
      numero_registro: proveedor.numero_registro || '',
      tipo_gestion: proveedor.tipo_gestion || 'inscripcion',
      notas_gestion: proveedor.notas_gestion || '',
      fecha_gestion: proveedor.fecha_gestion || null
    });
  } catch (err) {
    console.error('Error obteniendo datos de gestión:', err);
    res.status(500).json({ error: 'Error al obtener datos de gestión' });
  }
});

app.post('/api/admin/proveedor/:id/gestion', requiereAdmin, (req, res) => {
  const { numero_registro, tipo_gestion, notas_gestion, tipo_proveedor } = req.body;
  const proveedorId = req.params.id;

  if (!['inscripcion', 'actualizacion'].includes(tipo_gestion)) {
    return res.status(400).json({ error: 'Tipo de gestión inválido. Debe ser "inscripcion" o "actualizacion".' });
  }

  try {
    const proveedor = db.prepare(`
      SELECT id, etapa, evaluacion_estado, razon_social
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    db.prepare(`
      UPDATE proveedores
      SET numero_registro = ?,
          tipo_gestion = ?,
          notas_gestion = ?,
          fecha_gestion = datetime('now', 'localtime'),
          tipo_proveedor = ?
      WHERE id = ?
    `).run(
      numero_registro || null,
      tipo_gestion,
      notas_gestion || null,
      tipo_proveedor || null,
      proveedorId
    );

    const detalle = `Gestión: ${tipo_gestion} - N° ${numero_registro || 'sin número'} - Notas: ${notas_gestion || ''}`;

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'gestion_actualizada',
      detalle,
      null,
      null,
      req
    );

    if (proveedor.etapa === 'inscripcion' && proveedor.evaluacion_estado === 'aprobado') {
      if (numero_registro) {
        const cicloActivo = obtenerCicloActivo(proveedorId);

        if (!cicloActivo || cicloActivo.numero_registro !== numero_registro) {
          cerrarCicloAnterior(proveedorId);
          crearNuevoCiclo(proveedorId, numero_registro, tipo_gestion);
        }

        asignarCicloADocumentosActivos(proveedorId, numero_registro);
      } else {
        console.warn(`⚠️ No se proporcionó número de registro para crear ciclo del proveedor ${proveedorId}`);
      }

      db.prepare(`UPDATE proveedores SET etapa = 'registrado' WHERE id = ?`).run(proveedorId);

      console.log(`✅ Proveedor ${proveedorId} pasa a etapa REGISTRADO (gestión completada)`);

registrarHistorial(
proveedorId,
req.session.usuario,
'cambio_etapa',
'Gestión completada. El proveedor pasa a REGISTRADO.',
null,
null,
req
);

emitirTodos(proveedorId, 'proveedor_registrado', {
        proveedorId: proveedorId,
        numero_registro: numero_registro
      });

      emitirAdmin('estadisticas_actualizadas');
    }

    res.json({ ok: true, mensaje: 'Datos de gestión guardados correctamente' });
  } catch (err) {
    console.error('Error guardando gestión:', err);
    res.status(500).json({ error: 'Error al guardar los datos de gestión' });
  }
});

app.get('/api/admin/proveedor/:id/evaluacion/download', requiereAdmin, (req, res) => {
  const proveedorId = parseInt(req.params.id);

  try {
    const proveedor = db.prepare('SELECT evaluacion_inicial FROM proveedores WHERE id = ?').get(proveedorId);

    if (!proveedor || !proveedor.evaluacion_inicial) {
      return res.status(404).json({ error: 'Evaluación no encontrada' });
    }

    const rutaArchivo = path.join(uploadsDir, proveedor.evaluacion_inicial);

    if (!fs.existsSync(rutaArchivo)) {
      return res.status(404).json({ error: 'Archivo no encontrado' });
    }

    const bufferArchivo = fs.readFileSync(rutaArchivo);

    let bufferFinal;

    try {
      bufferFinal = descifrarArchivo(bufferArchivo, ENCRYPTION_KEY);
    } catch (err) {
      console.warn('El archivo no parece estar cifrado, enviando tal cual.');
      bufferFinal = bufferArchivo;
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="evaluacion_inicial.pdf"`);
    res.send(bufferFinal);
  } catch (err) {
    console.error('Error descargando evaluación:', err);
    res.status(500).json({ error: 'Error al descargar la evaluación' });
  }
});

app.post('/api/admin/proveedor/:id/evaluacion', requiereAdmin, uploadDoc.single('archivo'), (req, res) => {
  const proveedorId = parseInt(req.params.id);

  if (!req.file) {
    return res.status(400).json({ error: 'Archivo PDF requerido' });
  }

  try {
    const proveedor = db.prepare(`
      SELECT id, etapa, evaluacion_inicial
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    if (proveedor.etapa !== 'aprobacion') {
      return res.status(400).json({ error: 'El proveedor no está en la etapa de aprobación' });
    }

    if (proveedor.evaluacion_inicial) {
      const rutaAnterior = path.join(uploadsDir, proveedor.evaluacion_inicial);

      if (fs.existsSync(rutaAnterior)) {
        fs.unlinkSync(rutaAnterior);
        console.log(`🗑️ Evaluación anterior eliminada: ${rutaAnterior}`);
      }
    }

    const hashOriginal = calcularHash(req.file.buffer);
    const bufferCifrado = cifrarArchivo(req.file.buffer, ENCRYPTION_KEY);

    const nombreArchivoCifrado = `evaluacion_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.enc`;
    const carpeta = obtenerCarpetaProveedor(proveedorId);
    const rutaArchivo = path.join(carpeta, nombreArchivoCifrado);

    fs.writeFileSync(rutaArchivo, bufferCifrado);

    const rutaRelativa = obtenerRutaRelativa(proveedorId, nombreArchivoCifrado);

    db.prepare(`
      UPDATE proveedores
      SET evaluacion_inicial = ?,
          evaluacion_fecha = datetime('now', 'localtime'),
          evaluacion_estado = 'pendiente'
      WHERE id = ?
    `).run(rutaRelativa, proveedorId);

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'evaluacion_subida',
      `Evaluación inicial subida por admin: ${req.file.originalname}`,
      null,
      null,
      req
    );

    res.json({ ok: true, mensaje: 'Evaluación inicial subida correctamente' });
  } catch (err) {
    console.error('Error subiendo evaluación:', err);
    res.status(500).json({ error: 'Error al subir la evaluación' });
  }
});

app.get('/api/admin/proveedor/:id/evaluacion', requiereAdmin, (req, res) => {
  try {
    const proveedor = db.prepare(`
      SELECT evaluacion_inicial, evaluacion_estado, evaluacion_fecha
      FROM proveedores
      WHERE id = ?
    `).get(req.params.id);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    res.json({
      evaluacion_inicial: proveedor.evaluacion_inicial || null,
      evaluacion_estado: proveedor.evaluacion_estado || 'pendiente',
      evaluacion_fecha: proveedor.evaluacion_fecha || null
    });
  } catch (err) {
    console.error('Error obteniendo evaluación:', err);
    res.status(500).json({ error: 'Error al obtener evaluación' });
  }
});

app.delete('/api/admin/proveedor/:id/evaluacion', requiereAdmin, (req, res) => {
  const proveedorId = parseInt(req.params.id);

  try {
    const proveedor = db.prepare(`
      SELECT evaluacion_inicial, evaluacion_estado
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    if (!proveedor.evaluacion_inicial) {
      return res.status(404).json({ error: 'No hay evaluación inicial para eliminar' });
    }

    if (proveedor.evaluacion_estado !== 'pendiente') {
      return res.status(400).json({ error: 'No puedes eliminar una evaluación que ya ha sido aprobada o rechazada.' });
    }

    const rutaArchivo = path.join(uploadsDir, proveedor.evaluacion_inicial);

    if (fs.existsSync(rutaArchivo)) {
      fs.unlinkSync(rutaArchivo);
    }

    db.prepare(`
      UPDATE proveedores
      SET evaluacion_inicial = NULL,
          evaluacion_estado = 'pendiente',
          evaluacion_fecha = NULL
      WHERE id = ?
    `).run(proveedorId);

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'evaluacion_eliminada',
      'Evaluación inicial eliminada por admin',
      null,
      null,
      req
    );

    res.json({ ok: true, mensaje: 'Evaluación inicial eliminada correctamente' });
  } catch (err) {
    console.error('Error eliminando evaluación:', err);
    res.status(500).json({ error: 'Error al eliminar la evaluación' });
  }
});

app.post('/api/admin/proveedor/:id/evaluacion/estado', requiereAdmin, (req, res) => {
  const { estado, comentario } = req.body;
  const proveedorId = parseInt(req.params.id);

  if (!['aprobado', 'rechazado'].includes(estado)) {
    return res.status(400).json({ error: 'Estado inválido. Debe ser "aprobado" o "rechazado".' });
  }

  try {
    const proveedor = db.prepare(`
      SELECT id, etapa, evaluacion_inicial, razon_social, tipo_gestion, estado_general
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    if (!proveedor.evaluacion_inicial) {
      return res.status(400).json({ error: 'El proveedor no tiene evaluación inicial subida' });
    }

    if (proveedor.etapa !== 'aprobacion') {
      return res.status(400).json({ error: 'El proveedor no está en la etapa de aprobación' });
    }

    if (estado === 'aprobado') {
      const docs = db.prepare(`
        SELECT estado, no_aplica
        FROM documentos
        WHERE proveedor_id = ?
          AND es_historico = 0
      `).all(proveedorId);

      const todosAprobados = docs.every(d => d.estado === 'aprobado' || d.no_aplica === 1);

      if (!todosAprobados) {
        return res.status(400).json({
          error: 'No se puede aprobar la evaluación porque no todos los documentos están aprobados. Primero aprueba todos los documentos.'
        });
      }
    }

    db.prepare(`UPDATE proveedores SET evaluacion_estado = ? WHERE id = ?`).run(estado, proveedorId);

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'evaluacion_estado_cambiado',
      `Evaluación ${estado} por admin${comentario ? ': ' + comentario : ''}`,
      null,
      null,
      req
    );

    if (estado === 'rechazado') {
      const esActualizacion = proveedor.tipo_gestion === 'actualizacion';

      console.log(`❌ Evaluación rechazada para proveedor ${proveedorId}. tipo_gestion: ${proveedor.tipo_gestion || 'inscripcion'}`);

      if (esActualizacion) {
        console.log(`🔄 Proveedor ${proveedorId} en ACTUALIZACIÓN: volviendo a verificación sin bloquear.`);

        db.prepare(`
          UPDATE documentos
          SET estado = 'rechazado',
              verificado = 0,
              comentario = 'Rechazado automáticamente por evaluación inicial rechazada en proceso de actualización'
          WHERE proveedor_id = ?
            AND es_historico = 0
        `).run(proveedorId);

        db.prepare(`
          UPDATE proveedores
          SET etapa = 'verificacion',
              evaluacion_estado = 'rechazado'
          WHERE id = ?
        `).run(proveedorId);

        db.prepare(`
          UPDATE proveedores
          SET numero_registro = NULL,
              notas_gestion = NULL,
              fecha_gestion = NULL,
              tipo_proveedor = NULL
          WHERE id = ?
        `).run(proveedorId);

        registrarHistorial(
          proveedorId,
          req.session.usuario,
          'evaluacion_rechazada_actualizacion',
          `Evaluación rechazada en proceso de ACTUALIZACIÓN. El proveedor vuelve a VERIFICACIÓN para corregir documentos. Motivo: ${comentario || ''}`,
          null,
          null,
          req
        );

        const usuario = db.prepare(`
          SELECT u.email, u.nombre_empresa
          FROM usuarios u
          JOIN proveedores p ON u.id = p.usuario_id
          WHERE p.id = ?
        `).get(proveedorId);

        if (usuario) {
          const nombreProveedor = proveedor.razon_social || usuario.nombre_empresa || 'Proveedor';

          // 🛡️ M4 (Fase 3): escapar datos del usuario en HTML inline del correo
          const nombreProveedorEscapado = escapeHtml(nombreProveedor);
          const comentarioEscapado = escapeHtml(comentario || 'La evaluación inicial no cumplió con los requisitos establecidos.');
          const html = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
            <h2 style="margin: 0;">🔄 Actualización - Documentos Rechazados</h2>
            </div>
            <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
              <p>Hola <strong>${nombreProveedorEscapado}</strong>,</p>
              <p>Tu proceso de <strong>actualización de documentos</strong> ha sido rechazado.</p>
              <div style="background: #fee2e2; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
                <p style="margin: 0;"><strong>Motivo del rechazo:</strong></p>
                <p style="margin: 5px 0 0 0;">${comentarioEscapado}</p>
              </div>
                <p>Debes corregir los documentos rechazados y volver a subirlos para continuar con el proceso.</p>
                <div style="text-align: center; margin-top: 20px;">
                  <a href="${process.env.APP_URL || 'http://localhost:3000/'}/proveedor.html"
                    style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                    Ir al Portal
                    </a>
                </div>
              </div>
            </div>
          `;

          enviarEmail(usuario.email, '🔄 Actualización - Documentos rechazados (corregir)', html)
            .then(result => {
              if (result.ok) {
                console.log(`✅ Correo de actualización rechazada enviado a ${usuario.email}`);
              } else {
                console.error(`❌ Error enviando correo: ${result.error}`);
              }
            })
            .catch(err => console.error('Error al enviar correo:', err));
        }

        res.json({
          ok: true,
          mensaje: 'Evaluación rechazada. El proveedor vuelve a VERIFICACIÓN para corregir documentos (proceso de actualización).'
        });
      } else {
        console.log(`❌ Proveedor ${proveedorId} en INSCRIPCIÓN: pasando a RECHAZADO.`);

        db.prepare(`
          UPDATE documentos
          SET estado = 'rechazado',
              verificado = 0,
              comentario = 'Rechazado automáticamente por evaluación inicial rechazada'
          WHERE proveedor_id = ?
            AND es_historico = 0
        `).run(proveedorId);

        db.prepare(`
          UPDATE proveedores
          SET etapa = 'rechazado',
              estado_general = 'rechazado'
          WHERE id = ?
        `).run(proveedorId);

        db.prepare(`UPDATE proveedores SET evaluacion_estado = 'rechazado' WHERE id = ?`).run(proveedorId);

        db.prepare(`
          UPDATE proveedores
          SET numero_registro = NULL,
              notas_gestion = NULL,
              fecha_gestion = NULL,
              tipo_proveedor = NULL
          WHERE id = ?
        `).run(proveedorId);

        const usuario = db.prepare(`
          SELECT u.email, u.nombre_empresa
          FROM usuarios u
          JOIN proveedores p ON u.id = p.usuario_id
          WHERE p.id = ?
        `).get(proveedorId);

        if (usuario) {
          const nombreProveedor = proveedor.razon_social || usuario.nombre_empresa || 'Proveedor';
          const html = emailEvaluacionRechazada(nombreProveedor, comentario || 'La evaluación inicial no cumplió con los requisitos establecidos.');

          enviarEmail(usuario.email, '❌ Evaluación inicial rechazada - Documentos rechazados', html)
            .then(result => {
              if (result.ok) {
                console.log(`✅ Correo de rechazo enviado a ${usuario.email}`);
              } else {
                console.error(`❌ Error enviando correo de rechazo: ${result.error}`);
              }
            })
            .catch(err => console.error('Error al enviar correo de rechazo:', err));
        }

        registrarHistorial(
          proveedorId,
          req.session.usuario,
          'evaluacion_rechazada_con_retroceso',
          `Evaluación rechazada. Proveedor pasa a RECHAZADO. Motivo: ${comentario || ''}`,
          null,
          null,
          req
        );

        res.json({
          ok: true,
          mensaje: 'Evaluación rechazada. El proveedor pasa a estado RECHAZADO con todos sus documentos activos rechazados.'
        });
      }

      emitirTodos(proveedorId, 'evaluacion_actualizada', {
        proveedorId: proveedorId,
        estado: estado
      });

      emitirAdmin('estadisticas_actualizadas');
    } else {
      const usuario = db.prepare(`
        SELECT u.email, u.nombre_empresa
        FROM usuarios u
        JOIN proveedores p ON u.id = p.usuario_id
        WHERE p.id = ?
      `).get(proveedorId);

      if (usuario) {
        const nombreProveedor = proveedor.razon_social || usuario.nombre_empresa || 'Proveedor';
// Diferenciar RENOVACIÓN de ALTA NUEVA: si el proveedor viene de una
// actualización anual (tipo_gestion='actualizacion'), enviamos el correo de
// "actualización aprobada"; si es inscripción/alta, el clásico "¡Felicidades!".
const esRenovacion = proveedor.tipo_gestion === 'actualizacion';
const html = esRenovacion
? emailProveedorActualizacionAprobada(nombreProveedor)
: emailProveedorAprobado(nombreProveedor);
const asuntoCorreo = esRenovacion
? '✅ Actualización de documentos aprobada - Portal de Proveedores'
: '🎉 ¡Felicidades! Has sido aprobado como proveedor';
enviarEmail(usuario.email, asuntoCorreo, html)
.then(result => {
if (result.ok) {
console.log(`✅ Correo de ${esRenovacion ? 'actualización aprobada' : 'felicitación'} enviado a ${usuario.email} (evaluación aprobada)`);
            } else {
              console.error(`❌ Error enviando correo de felicitación: ${result.error}`);
            }
          })
          .catch(err => console.error('Error al enviar correo de felicitación:', err));
      }

      db.prepare(`UPDATE proveedores SET etapa = 'inscripcion' WHERE id = ?`).run(proveedorId);

      res.json({ ok: true, mensaje: 'Evaluación aprobada. El proveedor pasa a inscripción y actualización.' });
    }
  } catch (err) {
    console.error('Error cambiando estado evaluación:', err);
    res.status(500).json({ error: 'Error al cambiar estado de la evaluación' });
  }
});

app.get('/api/admin/proveedor/:id', requiereAdmin, (req, res) => {
  const p = db.prepare(`
    SELECT p.*, u.email, u.nombre_empresa, p.numero_registro, p.tipo_gestion, p.notas_gestion, p.fecha_gestion
    FROM proveedores p
    JOIN usuarios u ON p.usuario_id = u.id
    WHERE p.id = ?
  `).get(req.params.id);

  if (!p) {
    return res.status(404).json({ error: 'Proveedor no encontrado' });
  }

  const docs = db.prepare(`
    SELECT *
    FROM documentos
    WHERE proveedor_id = ?
      AND es_historico = 0
    ORDER BY tipo, id
  `).all(p.id);

  const documentos_historicos = db.prepare(`
    SELECT *
    FROM documentos
    WHERE proveedor_id = ?
      AND es_historico = 1
    ORDER BY ciclo DESC, tipo, id
  `).all(p.id);

  res.json({
    proveedor: p,
    documentos: docs,
    documentos_historicos,
    requeridos: DOCUMENTOS_REQUERIDOS
  });
});

app.post('/api/admin/documento/:id/estado', requiereAdmin, (req, res) => {
  const { estado, comentario } = req.body;

  if (!['pendiente', 'aprobado', 'rechazado'].includes(estado)) {
    return res.status(400).json({ error: 'Estado inválido' });
  }

  const doc = db.prepare('SELECT * FROM documentos WHERE id = ?').get(req.params.id);

  if (!doc) return res.status(404).json({ error: 'No encontrado' });

  if (doc.es_historico === 1) {
    return res.status(400).json({
      error: 'Este documento es histórico y no puede modificarse.'
    });
  }

  console.log(`📌 [ESTADO DOCUMENTO] ID ${doc.id} → ${estado} (comentario: ${comentario || 'N/A'}) por ${req.session.usuario.email}`);

  if (estado === 'aprobado' && doc.verificado !== 1) {
    return res.status(400).json({
      error: 'El documento debe estar marcado como "verificado" antes de aprobarse.'
    });
  }

  const verificadoFinal = estado === 'rechazado' ? 0 : doc.verificado;
  const noAplicaFinal = estado === 'rechazado' ? 0 : doc.no_aplica;

  let fechaVencimiento = null;
  let ciclo = doc.ciclo || null;

  if (estado === 'aprobado') {
    const proveedor = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(doc.proveedor_id);

    ciclo = proveedor?.numero_registro || doc.ciclo || obtenerCicloActivo(doc.proveedor_id)?.numero_registro || null;

    const fechaVencimientoObj = obtenerFechaVencimiento();
    fechaVencimiento = fechaVencimientoObj.toISOString().replace('T', ' ').slice(0, 19);
  }

  db.prepare(`
    UPDATE documentos
    SET estado = ?,
        comentario = ?,
        verificado = ?,
        no_aplica = ?,
        fecha_vencimiento = ?,
        ciclo = ?
    WHERE id = ?
  `).run(
    estado,
    comentario || null,
    verificadoFinal,
    noAplicaFinal,
    fechaVencimiento,
    ciclo,
    req.params.id
  );

  actualizarEstadoProveedor(doc.proveedor_id);

  const prov = db.prepare('SELECT etapa, evaluacion_estado FROM proveedores WHERE id = ?').get(doc.proveedor_id);

  if (estado === 'rechazado') {
    if (prov) {
      if (prov.etapa !== 'verificacion') {
        db.prepare(`UPDATE proveedores SET etapa = 'verificacion' WHERE id = ?`).run(doc.proveedor_id);

        console.log(`🔄 Proveedor ${doc.proveedor_id} vuelve a etapa VERIFICACION (documento rechazado)`);

        registrarHistorial(
          doc.proveedor_id,
          req.session.usuario,
          'cambio_etapa',
          'Documento rechazado. El proveedor vuelve a VERIFICACIÓN.',
          null,
          null,
          req
        );
      }

      if (prov.etapa === 'registrado' || prov.etapa === 'inscripcion') {
        db.prepare(`
          UPDATE proveedores
          SET numero_registro = NULL,
              tipo_gestion = NULL,
              notas_gestion = NULL,
              fecha_gestion = NULL,
              tipo_proveedor = NULL
          WHERE id = ?
        `).run(doc.proveedor_id);

        console.log(`🧹 Campos de gestión limpiados para proveedor ${doc.proveedor_id}`);
      }

      if (prov.etapa === 'aprobacion') {
        db.prepare(`UPDATE proveedores SET evaluacion_estado = 'pendiente' WHERE id = ?`).run(doc.proveedor_id);

        console.log(`📋 Evaluación puesta en 'pendiente' para proveedor ${doc.proveedor_id}`);
      }
    }
  } else if (estado === 'aprobado') {
    const docs = db.prepare(`
      SELECT estado, no_aplica
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).all(doc.proveedor_id);

    const todosAprobados = docs.every(d => d.estado === 'aprobado' || d.no_aplica === 1);

    if (todosAprobados && prov && prov.evaluacion_estado === 'aprobado') {
      db.prepare(`UPDATE proveedores SET etapa = 'inscripcion' WHERE id = ?`).run(doc.proveedor_id);

      console.log(`✅ Proveedor ${doc.proveedor_id} pasa a etapa INSCRIPCION (todos documentos aprobados y evaluación aprobada)`);

      registrarHistorial(
        doc.proveedor_id,
        req.session.usuario,
        'cambio_etapa',
        'Todos los documentos aprobados y evaluación aprobada. El proveedor pasa a INSCRIPCIÓN.',
        null,
        null,
        req
      );
    }
  }

  if (estado === 'rechazado') {
    const proveedorUsuario = db.prepare(`
      SELECT u.email, u.nombre_empresa, p.razon_social
      FROM usuarios u
      JOIN proveedores p ON u.id = p.usuario_id
      WHERE p.id = ?
    `).get(doc.proveedor_id);

    if (proveedorUsuario) {
      const nombreProveedor = proveedorUsuario.razon_social || proveedorUsuario.nombre_empresa || 'Proveedor';
      const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);
      const nombreDoc = config ? config.nombre : doc.tipo;

      enviarEmail(
        proveedorUsuario.email,
        `❌ Documento rechazado: ${nombreDoc}`,
        emailDocumentoRechazado(nombreProveedor, nombreDoc, comentario)
      ).catch(err => console.error('Error enviando notificación de rechazo:', err));
    }
  }

  if (estado === 'aprobado') {
    console.log(`✅ Documento aprobado individualmente (no se envía email): ${doc.nombre_original}`);
  }

  emitirTodos(doc.proveedor_id, 'documento_actualizado', {
    documentoId: doc.id,
    estado: estado,
    proveedorId: doc.proveedor_id
  });

  emitirAdmin('estadisticas_actualizadas');

  return res.json({ ok: true });
});

app.get('/api/admin/proveedor/:id/historial', requiereAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT *
    FROM historial
    WHERE proveedor_id = ?
    ORDER BY creado_en DESC
    LIMIT 500
  `).all(req.params.id));
});

app.post('/api/admin/proveedor/:id/recordatorio', requiereAdmin, (req, res) => {
  const { mensaje } = req.body;

  if (!mensaje || !mensaje.trim()) return res.status(400).json({ error: 'Mensaje requerido' });

  const prov = db.prepare('SELECT id FROM proveedores WHERE id = ?').get(req.params.id);
  if (!prov) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const mensajeEscapado = escapeHtml(mensaje.trim());

  db.prepare(`
    INSERT INTO recordatorios (proveedor_id, admin_id, admin_nombre, mensaje)
    VALUES (?, ?, ?, ?)
  `).run(prov.id, req.session.usuario.id, req.session.usuario.email, mensajeEscapado);

  registrarHistorial(
    prov.id,
    req.session.usuario,
    'recordatorio_enviado',
    `Recordatorio enviado: ${mensajeEscapado}`,
    null,
    null,
    req
  );

  emitirProveedor(prov.id, 'nuevo_recordatorio', { mensaje: mensajeEscapado });

  res.json({ ok: true });
});

app.post('/api/admin/limpiar-sesiones', requiereAdmin, (req, res) => {
  try {
    limpiarSesionesCorruptas();

    const archivos = fs.readdirSync(sessionsDir);
    let eliminados = 0;

    archivos.forEach(archivo => {
      if (archivo.endsWith('.json')) {
        try {
          fs.unlinkSync(path.join(sessionsDir, archivo));
          eliminados++;
        } catch (e) {
          console.error(`Error eliminando ${archivo}:`, e.message);
        }
      }
    });

    res.json({
      ok: true,
      mensaje: `✅ ${eliminados} sesiones eliminadas`,
      sesionesActivas: archivos.length - eliminados
    });
  } catch (err) {
    res.status(500).json({ error: 'Error limpiando sesiones: ' + err.message });
  }
});

app.post('/api/admin/limpiar-rate-limits', requiereAdmin, (req, res) => {
  limiterLogin.resetAll();
  limiterGeneral.resetAll();
  limiterUpload.resetAll();

  console.log('🧹 Rate limits limpiados por admin');

  res.json({ ok: true, mensaje: 'Rate limits reseteados' });
});

app.post('/api/admin/proveedor/:id/documento', requiereAdmin, limiterUpload, uploadDoc.single('archivo'), (req, res) => {
  const proveedorId = parseInt(req.params.id);

  if (!req.file) return res.status(400).json({ error: 'Archivo PDF requerido' });

  const { tipo } = req.body;
  if (!tipo) return res.status(400).json({ error: 'Tipo de documento requerido' });

  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
  if (!config) return res.status(400).json({ error: 'Tipo de documento inválido' });

  const proveedor = db.prepare('SELECT * FROM proveedores WHERE id = ?').get(proveedorId);
  if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });

  try {
    const hashOriginal = calcularHash(req.file.buffer);
    const bufferCifrado = cifrarArchivo(req.file.buffer, ENCRYPTION_KEY);

    let docId, accion;

    const nombreArchivoCifrado = `${tipo}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.enc`;
    const carpeta = obtenerCarpetaProveedor(proveedorId);
    const rutaArchivo = path.join(carpeta, nombreArchivoCifrado);
    const rutaRelativa = obtenerRutaRelativa(proveedorId, nombreArchivoCifrado);

    if (tipo === 'experiencia') {
      const rechazado = db.prepare(`
        SELECT id
        FROM documentos
        WHERE proveedor_id = ?
          AND tipo = 'experiencia'
          AND estado = 'rechazado'
          AND no_aplica = 0
          AND es_historico = 0
        ORDER BY id ASC
        LIMIT 1
      `).get(proveedorId);

      if (!rechazado) {
        const count = db.prepare(`
          SELECT COUNT(*) as total
          FROM documentos
          WHERE proveedor_id = ?
            AND tipo = 'experiencia'
            AND estado != 'rechazado'
            AND no_aplica = 0
            AND es_historico = 0
        `).get(proveedorId).total;

        if (count >= 3) {
          return res.status(400).json({
            error: 'Este proveedor ya tiene el máximo de 3 certificados de experiencia comercial.'
          });
        }
      }

      fs.writeFileSync(rutaArchivo, bufferCifrado);

      if (rechazado) {
        const docAnterior = db.prepare('SELECT archivo FROM documentos WHERE id = ?').get(rechazado.id);

        if (docAnterior && docAnterior.archivo !== 'no_aplica') {
          const rutaVieja = path.join(uploadsDir, docAnterior.archivo);
          if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
        }

        db.prepare(`
          UPDATE documentos
          SET archivo = ?,
              nombre_original = ?,
              hash_archivo = ?,
              estado = 'pendiente',
              comentario = NULL,
              no_aplica = 0,
              verificado = 0,
              subido_en = datetime('now', 'localtime')
          WHERE id = ?
        `).run(rutaRelativa, req.file.originalname, hashOriginal, rechazado.id);

        docId = rechazado.id;
        accion = 'documento_reemplazado';
      } else {
        const r = db.prepare(`
          INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
          VALUES (?, ?, ?, ?, ?, 0)
        `).run(proveedorId, tipo, rutaRelativa, req.file.originalname, hashOriginal);

        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    } else {
      if (config.cantidadMin === 1) {
        const existente = db.prepare(`
          SELECT id, archivo
          FROM documentos
          WHERE proveedor_id = ?
            AND tipo = ?
            AND es_historico = 0
        `).get(proveedorId, tipo);

        fs.writeFileSync(rutaArchivo, bufferCifrado);

        if (existente) {
          if (existente.archivo && existente.archivo !== 'no_aplica') {
            const rutaVieja = path.join(uploadsDir, existente.archivo);
            if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
          }

          db.prepare(`
            UPDATE documentos
            SET archivo = ?,
                nombre_original = ?,
                hash_archivo = ?,
                estado = 'pendiente',
                comentario = NULL,
                no_aplica = 0,
                verificado = 0,
                subido_en = datetime('now', 'localtime')
            WHERE id = ?
          `).run(rutaRelativa, req.file.originalname, hashOriginal, existente.id);

          docId = existente.id;
          accion = 'documento_reemplazado';
        } else {
          const r = db.prepare(`
            INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
            VALUES (?, ?, ?, ?, ?, 0)
          `).run(proveedorId, tipo, rutaRelativa, req.file.originalname, hashOriginal);

          docId = r.lastInsertRowid;
          accion = 'documento_subido';
        }
      } else {
        fs.writeFileSync(rutaArchivo, bufferCifrado);

        const r = db.prepare(`
          INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica)
          VALUES (?, ?, ?, ?, ?, 0)
        `).run(proveedorId, tipo, rutaRelativa, req.file.originalname, hashOriginal);

        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    }

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      accion,
      `Documento "${config.nombre}" subido por admin: ${req.file.originalname}`,
      tipo,
      docId,
      req
    );

    actualizarEstadoProveedor(proveedorId);

    const provActual = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(proveedorId);
    if (provActual?.numero_registro && docId) {
      db.prepare(`
        UPDATE documentos
        SET ciclo = ?
        WHERE id = ?
          AND (ciclo IS NULL OR ciclo = '')
      `).run(provActual.numero_registro, docId);
    }

    emitirTodos(proveedorId, 'documento_subido', {
      tipo: tipo,
      proveedorId: proveedorId,
      accion: accion,
      documentoId: docId
    });

    emitirAdmin('estadisticas_actualizadas');

    return res.json({
      ok: true,
      mensaje: `Documento "${config.nombre}" subido exitosamente para el proveedor`,
      docId: docId
    });
  } catch (err) {
    console.error('Error subiendo documento como admin:', err);
    return res.status(500).json({ error: 'Error al procesar el documento: ' + err.message });
  }
});

app.get('/api/admin/proveedor/:id/notas', requiereAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT *
    FROM notas_proveedor
    WHERE proveedor_id = ?
    ORDER BY creado_en DESC
  `).all(req.params.id));
});

app.get('/api/admin/proveedor/:id/documentos/zip', requiereAdmin, async (req, res) => {
  const proveedorId = parseInt(req.params.id);

  if (typeof archiver !== 'function') {
    console.error('❌ archiver no está disponible en este endpoint');
    return res.status(500).json({
      error: 'El servidor no tiene instalada la librería para generar ZIP. Contacta al administrador.'
    });
  }

  try {
    const proveedor = db.prepare(`
      SELECT id, razon_social, evaluacion_inicial
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    const documentos = db.prepare(`
      SELECT id, archivo, nombre_original, tipo
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
      ORDER BY tipo
    `).all(proveedorId);

    if ((!documentos || documentos.length === 0) && !proveedor.evaluacion_inicial) {
      return res.status(404).json({
        error: 'Este proveedor no tiene documentos activos ni evaluación para descargar.'
      });
    }

    const nombreProveedor = proveedor.razon_social || `Proveedor_${proveedorId}`;
    const nombreZip = `${nombreProveedor.replace(/[^a-zA-Z0-9]/g, '_')}_documentos.zip`;

    const nombreProveedorLimpio = nombreProveedor
      .replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-_]/g, '')
      .trim()
      .replace(/\s+/g, '_');

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(nombreZip)}"`);

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    let documentosAgregados = 0;
    let errores = 0;
    const contadorTipos = {};

    if (proveedor.evaluacion_inicial) {
      try {
        const rutaEvaluacion = path.join(uploadsDir, proveedor.evaluacion_inicial);

        if (fs.existsSync(rutaEvaluacion)) {
          const bufferCifrado = fs.readFileSync(rutaEvaluacion);

          let bufferDescifrado;

          try {
            bufferDescifrado = descifrarArchivo(bufferCifrado, ENCRYPTION_KEY);
          } catch (decryptErr) {
            console.warn(`⚠️ Error descifrando evaluación: ${decryptErr.message}. Se incluirá tal cual.`);
            bufferDescifrado = bufferCifrado;
          }

          archive.append(bufferDescifrado, { name: `${nombreProveedorLimpio} - Evaluación Inicial.pdf` });
          documentosAgregados++;

          console.log(`📄 Evaluación inicial agregada al ZIP para proveedor ${proveedorId}`);
        } else {
          console.warn(`⚠️ Archivo de evaluación no encontrado: ${rutaEvaluacion}`);
          errores++;
        }
      } catch (err) {
        console.error(`❌ Error procesando evaluación: ${err.message}`);
        errores++;
      }
    }

    for (const doc of documentos) {
      try {
        if (doc.archivo === 'no_aplica') continue;

        const rutaArchivo = path.join(uploadsDir, doc.archivo);

        if (!fs.existsSync(rutaArchivo)) {
          console.warn(`⚠️ Archivo no encontrado: ${rutaArchivo}`);
          errores++;
          continue;
        }

        const bufferCifrado = fs.readFileSync(rutaArchivo);

        let bufferDescifrado;

        try {
          bufferDescifrado = descifrarArchivo(bufferCifrado, ENCRYPTION_KEY);
        } catch (decryptErr) {
          console.error(`❌ Error descifrando documento ${doc.id}:`, decryptErr.message);
          errores++;
          continue;
        }

        const configDoc = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);
        let nombreBase = configDoc ? configDoc.nombre : doc.tipo;

        nombreBase = nombreBase.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-_]/g, '').trim();
        if (!nombreBase) nombreBase = doc.tipo;

        if (!contadorTipos[doc.tipo]) {
          contadorTipos[doc.tipo] = 0;
        }

        contadorTipos[doc.tipo]++;

        let nombreArchivo = `${nombreProveedorLimpio} - ${nombreBase}.pdf`;

        if (contadorTipos[doc.tipo] > 1) {
          nombreArchivo = `${nombreProveedorLimpio} - ${nombreBase}_${contadorTipos[doc.tipo]}.pdf`;
        }

        archive.append(bufferDescifrado, { name: nombreArchivo });
        documentosAgregados++;
      } catch (err) {
        console.error(`❌ Error procesando documento ${doc.id}:`, err.message);
        errores++;
      }
    }

    await archive.finalize();

    console.log(`📦 ZIP generado para proveedor ${proveedorId}: ${documentosAgregados} archivos agregados, ${errores} errores`);

    if (documentosAgregados === 0) {
      console.warn(`⚠️ No se pudo agregar ningún archivo al ZIP para proveedor ${proveedorId}`);
    }
  } catch (err) {
    console.error('❌ Error generando ZIP:', err);

    if (!res.headersSent) {
      return res.status(500).json({ error: 'Error al generar el ZIP: ' + err.message });
    }

    res.end();
  }
});

app.post('/api/admin/proveedor/:id/nota', requiereAdmin, (req, res) => {
  const { titulo, nota } = req.body;

  if (!nota || !nota.trim()) return res.status(400).json({ error: 'Nota requerida' });

  const prov = db.prepare('SELECT id FROM proveedores WHERE id = ?').get(req.params.id);
  if (!prov) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const tituloEscapado = escapeHtml((titulo || 'Nota').trim());
  const notaEscapada = escapeHtml(nota.trim());

  db.prepare(`
    INSERT INTO notas_proveedor (proveedor_id, admin_id, admin_nombre, titulo, nota)
    VALUES (?, ?, ?, ?, ?)
  `).run(prov.id, req.session.usuario.id, req.session.usuario.email, tituloEscapado, notaEscapada);

  registrarHistorial(
    prov.id,
    req.session.usuario,
    'nota_agregada',
    `Nota agregada: ${tituloEscapado} - ${notaEscapada.substring(0, 100)}`,
    null,
    null,
    req
  );

  const proveedorUsuario = db.prepare(`
    SELECT u.email, u.nombre_empresa, p.razon_social
    FROM usuarios u
    JOIN proveedores p ON u.id = p.usuario_id
    WHERE p.id = ?
  `).get(prov.id);

  if (proveedorUsuario) {
    const nombreProveedor = proveedorUsuario.razon_social || proveedorUsuario.nombre_empresa || 'Proveedor';

    enviarEmail(
      proveedorUsuario.email,
      `📝 Nueva nota: ${titulo || 'Sin título'}`,
      emailNuevaNota(nombreProveedor, titulo || 'Nota del administrador', nota.trim())
    ).catch(err => console.error('Error enviando notificación:', err));
  }

  emitirProveedor(prov.id, 'nueva_nota', { titulo: tituloEscapado, nota: notaEscapada });

  res.json({ ok: true });
});

app.post('/api/admin/proveedor/:id/documento/:docId/no-aplica', requiereAdmin, (req, res) => {
  const proveedorId = parseInt(req.params.id);
  const docId = parseInt(req.params.docId);
  const { no_aplica, tipo } = req.body;

  const proveedor = db.prepare('SELECT * FROM proveedores WHERE id = ?').get(proveedorId);
  if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
  if (!config) return res.status(400).json({ error: 'Tipo de documento inválido' });

  let documentoId = docId;

  if (docId === 0 || !docId) {
    const existente = db.prepare(`
      SELECT id
      FROM documentos
      WHERE proveedor_id = ?
        AND tipo = ?
        AND es_historico = 0
    `).get(proveedorId, tipo);

    if (existente) {
      documentoId = existente.id;

      if (no_aplica) {
        db.prepare(`
          UPDATE documentos
          SET no_aplica = 1,
              estado = 'pendiente',
              comentario = 'No aplica - Marcado por admin',
              verificado = 1
          WHERE id = ?
        `).run(existente.id);
      } else {
        db.prepare(`
          UPDATE documentos
          SET no_aplica = 0,
              estado = 'pendiente',
              comentario = NULL,
              verificado = 0
          WHERE id = ?
        `).run(existente.id);
      }

      registrarHistorial(
        proveedorId,
        req.session.usuario,
        'documento_no_aplica',
        `Documento "${config.nombre}" ${no_aplica ? 'marcado' : 'desmarcado'} como "No aplica" por admin`,
        tipo,
        existente.id,
        req
      );
    } else {
      if (!no_aplica) {
        return res.status(400).json({ error: 'No existe documento activo para desmarcar' });
      }

      const result = db.prepare(`
        INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, no_aplica, comentario, verificado)
        VALUES (?, ?, 'no_aplica', 'No aplica', 'pendiente', 1, 'No aplica - Marcado por admin', 1)
      `).run(proveedorId, tipo);

      documentoId = result.lastInsertRowid;

      registrarHistorial(
        proveedorId,
        req.session.usuario,
        'documento_no_aplica',
        `Documento "${config.nombre}" marcado como NO APLICA (creado) por admin`,
        tipo,
        documentoId,
        req
      );
    }
  } else {
    const doc = db.prepare(`
      SELECT *
      FROM documentos
      WHERE id = ?
        AND proveedor_id = ?
    `).get(docId, proveedorId);

    if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });

    if (doc.es_historico === 1) {
      return res.status(400).json({
        error: 'Este documento es histórico y no puede modificarse.'
      });
    }

    if (no_aplica) {
      db.prepare(`
        UPDATE documentos
        SET no_aplica = 1,
            estado = 'pendiente',
            comentario = 'No aplica - Marcado por admin',
            verificado = 1
        WHERE id = ?
      `).run(doc.id);
    } else {
      db.prepare(`
        UPDATE documentos
        SET no_aplica = 0,
            estado = 'pendiente',
            comentario = NULL,
            verificado = 0
        WHERE id = ?
      `).run(doc.id);
    }

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'documento_no_aplica',
      `Documento "${config.nombre}" ${no_aplica ? 'marcado' : 'desmarcado'} como "No aplica" por admin`,
      tipo,
      doc.id,
      req
    );
  }

  actualizarEstadoProveedor(proveedorId);

  const provActual = db.prepare('SELECT numero_registro FROM proveedores WHERE id = ?').get(proveedorId);
  if (provActual?.numero_registro && documentoId) {
    db.prepare(`
      UPDATE documentos
      SET ciclo = ?
      WHERE id = ?
        AND (ciclo IS NULL OR ciclo = '')
    `).run(provActual.numero_registro, documentoId);
  }

  const prov = db.prepare('SELECT todos_subidos, todos_verificados, etapa FROM proveedores WHERE id = ?').get(proveedor.id);

  if (prov.todos_subidos && prov.todos_verificados && (prov.etapa === 'verificacion' || prov.etapa === '')) {
    db.prepare(`UPDATE proveedores SET etapa = 'aprobacion' WHERE id = ?`).run(proveedor.id);

    console.log(`✅ Proveedor ${proveedor.id} pasa a etapa APROBACION (todos verificados - desde No aplica)`);

    registrarHistorial(
      proveedor.id,
      req.session.usuario,
      'cambio_etapa',
      'Todos los documentos verificados (incluye No aplica). El proveedor pasa a APROBACIÓN.',
      null,
      null,
      req
    );
  }

  res.json({ ok: true });
});

app.post('/api/admin/proveedor', requiereAdmin, async (req, res) => {
  const { email, password, nombre_empresa, razon_social, rfc, representante, telefono, direccion } = req.body;

  if (!email || !password || !nombre_empresa) {
    return res.status(400).json({ error: 'Email, contraseña y nombre de empresa son obligatorios' });
  }

  const validacion = validarPassword(password);
  if (!validacion.valido) return res.status(400).json({ error: validacion.mensaje });

  try {
    const existente = db.prepare('SELECT id FROM usuarios WHERE email = ?').get(email);
    if (existente) return res.status(400).json({ error: 'El email ya está registrado' });

    const hash = bcrypt.hashSync(password, 12);

    const result = db.prepare(`
      INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password)
      VALUES (?, ?, 'proveedor', ?, 1)
    `).run(email, hash, nombre_empresa);

    const provResult = db.prepare(`
      INSERT INTO proveedores (usuario_id, razon_social, rfc, representante, telefono, direccion)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      result.lastInsertRowid,
      razon_social || nombre_empresa,
      rfc || '',
      representante || '',
      telefono || '',
      direccion || ''
    );

    registrarHistorial(
      provResult.lastInsertRowid,
      req.session.usuario,
      'registro',
      `Proveedor creado por admin: ${nombre_empresa}`,
      null,
      null,
      req
    );

    registrarLogSeguridad(result.lastInsertRowid, email, 'proveedor_creado_admin', true, nombre_empresa, req);

    try {
      const htmlCredenciales = emailBienvenidaProveedor(email, password, nombre_empresa);

      await enviarEmail(
        email,
        `🏢 Bienvenido - Credenciales de acceso al Portal de Proveedores`,
        htmlCredenciales
      );
    } catch (emailErr) {
      console.error('Error enviando email de bienvenida:', emailErr.message);
    }

    emitirAdmin('proveedores_actualizados');
    emitirAdmin('estadisticas_actualizadas');

    res.json({
      ok: true,
      mensaje: `Proveedor "${nombre_empresa}" creado exitosamente. Se enviaron las credenciales a ${email}`,
      proveedorId: provResult.lastInsertRowid
    });
  } catch (err) {
    console.error('Error creando proveedor:', err);
    res.status(500).json({ error: 'Error al crear el proveedor: ' + err.message });
  }
});

app.delete('/api/admin/proveedor/:id', requiereAdmin, (req, res) => {
  const { password } = req.body;

  if (!password) return res.status(400).json({ error: 'Contraseña requerida' });

  const admin = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.session.usuario.id);

  if (!bcrypt.compareSync(password, admin.password)) {
    registrarLogSeguridad(admin.id, admin.email, 'eliminar_proveedor_fallido', false, 'Contraseña incorrecta', req);
    return res.status(403).json({ error: 'Contraseña incorrecta' });
  }

  const prov = db.prepare('SELECT * FROM proveedores WHERE id = ?').get(req.params.id);
  if (!prov) return res.status(404).json({ error: 'Proveedor no encontrado' });

  const usuario = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(prov.usuario_id);
  const nombreProv = prov.razon_social || usuario?.nombre_empresa || `Proveedor ${prov.id}`;

  try {
    const carpeta = obtenerCarpetaProveedor(prov.id);
    eliminarCarpetaRecursiva(carpeta);

    db.prepare('DELETE FROM notas_proveedor WHERE proveedor_id = ?').run(prov.id);
    db.prepare('DELETE FROM recordatorios WHERE proveedor_id = ?').run(prov.id);
    db.prepare('DELETE FROM historial WHERE proveedor_id = ?').run(prov.id);
    db.prepare('DELETE FROM documentos WHERE proveedor_id = ?').run(prov.id);
    db.prepare('DELETE FROM proveedores WHERE id = ?').run(prov.id);
    db.prepare('DELETE FROM usuarios WHERE id = ?').run(prov.usuario_id);

    registrarLogSeguridad(admin.id, admin.email, 'eliminar_proveedor', true, `Eliminado: ${nombreProv}`, req);

    emitirAdmin('proveedores_actualizados');
    emitirAdmin('estadisticas_actualizadas');

    res.json({ ok: true, mensaje: `Proveedor "${nombreProv}" eliminado completamente` });
  } catch (err) {
    registrarLogSeguridad(admin.id, admin.email, 'eliminar_proveedor_error', false, err.message, req);
    res.status(500).json({ error: 'Error al eliminar el proveedor' });
  }
});

app.get('/api/admin/plantillas', requiereAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM plantillas').all());
});

app.post('/api/admin/plantilla', requiereAdmin, uploadPlantilla.single('archivo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Archivo requerido' });

  const { tipo } = req.body;

  if (!DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo)) return res.status(400).json({ error: 'Tipo inválido' });

  const existente = db.prepare('SELECT archivo FROM plantillas WHERE tipo = ?').get(tipo);

  const nombreArchivo = `${tipo}-${Date.now()}${path.extname(req.file.originalname)}`;
  const ruta = path.join(plantillasDir, nombreArchivo);

  if (existente) {
    const rutaVieja = path.join(plantillasDir, existente.archivo);
    if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);

    db.prepare('UPDATE plantillas SET archivo = ?, nombre_original = ? WHERE tipo = ?').run(nombreArchivo, req.file.originalname, tipo);
  } else {
    db.prepare('INSERT INTO plantillas (tipo, archivo, nombre_original) VALUES (?, ?, ?)').run(tipo, nombreArchivo, req.file.originalname);
  }

  fs.writeFileSync(ruta, req.file.buffer);

  res.json({ ok: true });
});

app.get('/api/admin/habeas-data/export', requiereAdmin, (req, res) => {
  try {
    const registros = db.prepare(`
      SELECT hdc.id, u.email, u.nombre_empresa, p.razon_social, hdc.aceptado, hdc.fecha_aceptacion, hdc.ip_origen, hdc.user_agent, hdc.version, hdc.creado_en
      FROM habeas_data_consent hdc
      JOIN usuarios u ON hdc.usuario_id = u.id
      LEFT JOIN proveedores p ON u.id = p.usuario_id
      ORDER BY hdc.creado_en DESC
    `).all();

    if (!registros || registros.length === 0) {
      return res.status(404).json({
        error: 'No hay registros de Habeas Data para exportar'
      });
    }

    const headers = [
      'ID',
      'Email',
      'Nombre Empresa',
      'Razón Social',
      'Aceptado',
      'Fecha Aceptación',
      'IP Origen',
      'User Agent',
      'Versión',
      'Creado En'
    ];

    const rows = registros.map(r => {
      return [
        r.id,
        `"${r.email || ''}"`,
        `"${r.nombre_empresa || ''}"`,
        `"${r.razon_social || ''}"`,
        r.aceptado === 1 ? 'Sí' : 'No',
        `"${r.fecha_aceptacion || ''}"`,
        `"${r.ip_origen || ''}"`,
        `"${(r.user_agent || '').substring(0, 100)}"`,
        `"${r.version || ''}"`,
        `"${r.creado_en || ''}"`
      ].join(',');
    });

    const csvContent = [headers.join(','), ...rows].join('\n');
    const BOM = '\uFEFF';
    const contenidoFinal = BOM + csvContent;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=habeas_data_export.csv');
    res.setHeader('Cache-Control', 'no-cache');

    res.send(contenidoFinal);

    console.log(`✅ Exportación de Habeas Data: ${registros.length} registros`);
  } catch (err) {
    console.error('❌ Error exportando habeas data:', err.message);
    res.status(500).json({
      error: 'Error al exportar: ' + err.message
    });
  }
});

app.post('/api/admin/exportar-excel', requiereAdmin, async (req, res) => {
  try {
    const { proveedores } = req.body;

    if (!proveedores || proveedores.length === 0) {
      return res.status(400).json({ error: 'No hay proveedores para exportar' });
    }

    const ExcelJS = require('exceljs');

    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Sistema de Proveedores';
    workbook.created = new Date();

    const worksheet = workbook.addWorksheet('Proveedores');

worksheet.columns = [
{ header: 'Razón Social', key: 'razon_social', width: 35 },
{ header: 'NIT / RUT', key: 'nit', width: 18 },
{ header: 'Correo', key: 'correo', width: 30 },
{ header: 'Teléfono', key: 'telefono', width: 15 },
{ header: 'Representante Legal', key: 'representante', width: 25 },
{ header: 'Dirección', key: 'direccion', width: 40 },
{ header: 'Estado', key: 'estado', width: 16 },
{ header: 'Fecha Aprobación', key: 'fecha_aprobacion', width: 22 },
{ header: 'Fecha Movimiento', key: 'numero_registro', width: 18 },
{ header: 'Tipo Gestión', key: 'tipo_gestion', width: 14 },
{ header: 'Tipo Proveedor', key: 'tipo_proveedor', width: 18 },
{ header: 'Nota', key: 'nota', width: 40 }
];

    const headerRow = worksheet.getRow(1);

    headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF1E40AF' }
    };
    headerRow.alignment = { vertical: 'middle', horizontal: 'center' };
    headerRow.height = 25;

    proveedores.forEach(p => {
      const fechaAprob = p.fecha_aprobacion ? formatearFechaExcel(p.fecha_aprobacion) : 'Pendiente';

const row = worksheet.addRow({
razon_social: p.razon_social || p.nombre_empresa || '',
nit: p.rfc || '',
correo: p.email || '',
telefono: p.telefono || '',
representante: p.representante || '',
direccion: (p.direccion || '').replace(/[\n\r]+/g, ' '),
estado: estadoLegibleServer(p),
fecha_aprobacion: fechaAprob,
numero_registro: p.numero_registro || '',
tipo_gestion: p.tipo_gestion || '',
tipo_proveedor: p.tipo_proveedor || '',
nota: p.notas_gestion || ''
});

      row.eachCell(cell => {
        cell.border = {
          top: { style: 'thin' },
          left: { style: 'thin' },
          bottom: { style: 'thin' },
          right: { style: 'thin' }
        };

        cell.alignment = { vertical: 'middle', wrapText: true };
      });

const estadoCell = row.getCell('estado');
const estadoTexto = estadoLegibleServer(p);
if (estadoTexto === 'Registrado') {
estadoCell.font = { bold: true, color: { argb: 'FF059669' } };
} else if (estadoTexto === 'Rechazado') {
estadoCell.font = { bold: true, color: { argb: 'FFDC2626' } };
} else {
estadoCell.font = { bold: true, color: { argb: 'FFD97706' } };
}
});

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=proveedores_${fechaArchivo()}.xlsx`);

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando Excel:', err);
    res.status(500).json({ error: 'Error al generar el archivo Excel: ' + err.message });
  }
});

app.get('/api/admin/configuracion-seguridad', requiereAdmin, (req, res) => {
  const config = obtenerConfiguracionSeguridad();

  res.json({
    configuracion: config,
    encripcionKeyConfigurada: !!process.env.ENCRYPTION_KEY,
    sessionSecretConfigurada: !!process.env.SESSION_SECRET,
    smtpConfigurado: !!process.env.SMTP_HOST
  });
});

app.get('/api/admin/diagnosticar-cifrado', requiereAdmin, (req, res) => {
  const resultado = verificarSistemaCifrado(ENCRYPTION_KEY);
  res.json(resultado);
});

app.get('/api/admin/documento/:id/verificar-integridad', requiereAdmin, (req, res) => {
  const doc = db.prepare('SELECT * FROM documentos WHERE id = ?').get(req.params.id);

  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });

  const ruta = path.join(uploadsDir, doc.archivo);

  if (!fs.existsSync(ruta)) {
    return res.json({ integro: false, mensaje: 'Archivo no encontrado en disco' });
  }

  const buffer = fs.readFileSync(ruta);
  const esIntegro = verificarHash(buffer, doc.hash_archivo);

  res.json({
    integro: esIntegro,
    hashEsperado: doc.hash_archivo,
    hashActual: calcularHash(buffer),
    mensaje: esIntegro ? '✅ Documento íntegro' : '⚠️ Documento modificado'
  });
});

app.post('/api/admin/documento/:id/verificar', requiereAdmin, (req, res) => {
  const { verificado } = req.body;

  console.log(`🔍 [VERIFICAR] Recibida petición para documento ID ${req.params.id}, verificado=${verificado}`);

  if (typeof verificado !== 'boolean') {
    return res.status(400).json({ error: 'El campo "verificado" debe ser booleano' });
  }

  const doc = db.prepare('SELECT * FROM documentos WHERE id = ?').get(req.params.id);

  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });

  console.log(`🔍 [VERIFICAR] Documento encontrado: ID ${doc.id}, tipo ${doc.tipo}, estado ${doc.estado}, verificado actual ${doc.verificado}, no_aplica ${doc.no_aplica}`);

  if (doc.estado === 'aprobado') {
    return res.status(400).json({ error: 'No se puede modificar un documento aprobado' });
  }

  if (verificado && doc.estado === 'rechazado') {
    return res.status(400).json({ error: 'No se puede verificar un documento rechazado. Debe subir uno nuevo.' });
  }

  if (doc.es_historico === 1) {
    return res.status(400).json({
      error: 'Este documento es histórico y no puede modificarse.'
    });
  }

  console.log(`🔍 [VERIFICACIÓN] Documento ID ${doc.id} (tipo: ${doc.tipo}, proveedor: ${doc.proveedor_id}) ${verificado ? '✅ VERIFICADO' : '❌ DESMARCADO'} por ${req.session.usuario.email}`);

  db.prepare('UPDATE documentos SET verificado = ? WHERE id = ?').run(verificado ? 1 : 0, doc.id);

  actualizarEstadoProveedor(doc.proveedor_id);

  const prov = db.prepare('SELECT todos_subidos, todos_verificados, etapa FROM proveedores WHERE id = ?').get(doc.proveedor_id);

  if (prov.todos_subidos && prov.todos_verificados && prov.etapa === 'verificacion') {
    db.prepare(`UPDATE proveedores SET etapa = 'aprobacion' WHERE id = ?`).run(doc.proveedor_id);

    console.log(`✅ Proveedor ${doc.proveedor_id} pasa a etapa APROBACION (todos verificados)`);

    registrarHistorial(
      doc.proveedor_id,
      req.session.usuario,
      'cambio_etapa',
      'Todos los documentos verificados. El proveedor pasa a APROBACIÓN.',
      null,
      null,
      req
    );
  }

  registrarHistorial(
    doc.proveedor_id,
    req.session.usuario,
    'documento_verificado',
    verificado ? `Documento marcado como verificado` : `Verificación desmarcada`,
    doc.tipo,
    doc.id,
    req
  );

  emitirTodos(doc.proveedor_id, 'documento_verificado', {
    documentoId: doc.id,
    verificado: verificado,
    proveedorId: doc.proveedor_id
  });

  return res.json({ ok: true, verificado });
});

// ==========================================
// 9. SERVICIO DE ARCHIVOS
// ==========================================
app.get('/uploads/:path(*)', requiereLogin, (req, res) => {
// 🛡️ A2: prevenir path traversal. Resolver la ruta y exigir que quede DENTRO de uploadsDir.
const rutaArchivo = path.resolve(uploadsDir, req.params.path);
const uploadsRoot = path.resolve(uploadsDir) + path.sep;
if (!rutaArchivo.startsWith(uploadsRoot)) {
registrarLogSeguridad(
req.session.usuario?.id || null,
req.session.usuario?.email || 'desconocido',
'path_traversal_bloqueado',
false,
`Intento de acceso fuera de uploads: ${req.params.path}`,
req
);
return res.status(403).json({ error: 'Ruta inválida' });
}
const usuario = req.session.usuario;

  let tieneAcceso = false;
  let documentoInfo = null;

  if (usuario.rol === 'admin') {
    tieneAcceso = true;
    documentoInfo = db.prepare('SELECT nombre_original, tipo FROM documentos WHERE archivo = ?').get(req.params.path);
  } else {
    const prov = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(usuario.id);

    if (prov) {
      const doc = db.prepare(`
        SELECT archivo, nombre_original, tipo
        FROM documentos
        WHERE proveedor_id = ?
          AND archivo = ?
      `).get(prov.id, req.params.path);

      if (doc) {
        tieneAcceso = true;
        documentoInfo = doc;
      }
    }
  }

  if (!tieneAcceso) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  if (!fs.existsSync(rutaArchivo)) {
    return res.status(404).json({ error: 'Archivo no encontrado' });
  }

  try {
    const bufferArchivo = fs.readFileSync(rutaArchivo);
    const esPDFSinCifrar = bufferArchivo.slice(0, 4).toString() === '%PDF';

    let bufferFinal;

    if (esPDFSinCifrar) {
      bufferFinal = bufferArchivo;
    } else {
      bufferFinal = descifrarArchivo(bufferArchivo, ENCRYPTION_KEY);
    }

    const esDescarga = req.query.download === 'true';

    res.setHeader('Content-Type', 'application/pdf');

    if (esDescarga) {
      const nombreArchivo = nombreFormatoServer(documentoInfo?.tipo) || documentoInfo?.nombre_original || path.basename(req.params.path);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(nombreArchivo)}"`);
    } else {
      res.setHeader('Content-Disposition', 'inline');
    }

    res.setHeader('Content-Length', bufferFinal.length);
    res.send(bufferFinal);
  } catch (err) {
    console.error('Error leyendo archivo:', err.message);
    res.status(500).json({ error: 'Error al leer el documento' });
  }
});

// ==========================================
// 10. ERROR HANDLER Y SERVIDOR
// ==========================================
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.message });
  if (err) return res.status(400).json({ error: err.message });

  next();
});

cron.schedule('0 8 * * *', async () => {
  console.log(`\n🕐 Ejecutando recordatorios automáticos - ${new Date().toLocaleString()}`);
  await enviarRecordatoriosFaltantes();
}, {
  timezone: "America/Bogota"
});

console.log('⏰ Cron job de recordatorios configurado para las 8:00 AM (Colombia)');

cron.schedule('0 0 * * *', async () => {
  console.log(`\n🕐 Ejecutando procesamiento de vencimientos - ${new Date().toLocaleString()}`);
  await procesarVencimientos();
}, {
  timezone: "America/Bogota"
});

console.log('⏰ Cron job de vencimientos configurado para las 12:00 AM (Colombia)');

app.post('/api/admin/proveedor/:id/reiniciar-proceso', requiereAdmin, (req, res) => {
  const proveedorId = parseInt(req.params.id);

  try {
    const proveedor = db.prepare(`
      SELECT id, etapa, evaluacion_inicial, razon_social
      FROM proveedores
      WHERE id = ?
    `).get(proveedorId);

    if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });

    if (proveedor.etapa !== 'rechazado') {
      return res.status(400).json({ error: 'El proveedor no está en estado rechazado' });
    }

    db.prepare(`
      UPDATE proveedores
      SET etapa = 'verificacion',
          estado_general = 'pendiente',
          evaluacion_inicial = NULL,
          evaluacion_estado = 'pendiente',
          evaluacion_fecha = NULL,
          numero_registro = NULL,
          tipo_gestion = NULL,
          notas_gestion = NULL,
          fecha_gestion = NULL,
          tipo_proveedor = NULL,
          todos_subidos = 0,
          todos_verificados = 0
      WHERE id = ?
    `).run(proveedorId);

    db.prepare(`
      UPDATE documentos
      SET comentario = 'Debes subir una nueva versión (reinicio de proceso)'
      WHERE proveedor_id = ?
        AND estado = 'rechazado'
        AND es_historico = 0
    `).run(proveedorId);

    if (proveedor.evaluacion_inicial) {
      const ruta = path.join(uploadsDir, proveedor.evaluacion_inicial);
      if (fs.existsSync(ruta)) fs.unlinkSync(ruta);
    }

    actualizarEstadoProveedor(proveedorId);

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'proceso_reiniciado',
      `Proceso reiniciado desde estado rechazado para ${proveedor.razon_social || 'proveedor'}`,
      null,
      null,
      req
    );

    res.json({
      ok: true,
      mensaje: 'Proceso reiniciado. El proveedor vuelve a verificación con documentos activos en estado rechazado y comentario de corrección.'
    });
  } catch (err) {
    console.error('Error reiniciando proceso:', err);
    res.status(500).json({ error: 'Error al reiniciar el proceso' });
  }
});

app.post('/api/admin/proveedor/:id/solicitar-actualizacion', requiereAdmin, async (req, res) => {
  const proveedorId = parseInt(req.params.id);
  const { mensaje } = req.body;

  try {
    const proveedor = db.prepare(`
      SELECT p.id, p.etapa, p.razon_social, p.numero_registro, p.evaluacion_inicial, u.email, u.nombre_empresa
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      WHERE p.id = ?
    `).get(proveedorId);

    if (!proveedor) {
      return res.status(404).json({ error: 'Proveedor no encontrado' });
    }

    if (proveedor.etapa !== 'registrado') {
      return res.status(400).json({ error: 'Solo se puede solicitar actualización a proveedores registrados' });
    }

    const nombreProveedor = proveedor.razon_social || proveedor.nombre_empresa || 'Proveedor';
    const añoActual = new Date().getFullYear();

    const cicloPrevio = proveedor.numero_registro || obtenerCicloActivo(proveedorId)?.numero_registro || null;

    if (cicloPrevio) {
      db.prepare(`
        UPDATE documentos
        SET ciclo = ?
        WHERE proveedor_id = ?
          AND es_historico = 0
          AND (ciclo IS NULL OR ciclo = '')
      `).run(cicloPrevio, proveedorId);

      console.log(`📌 Documentos activos asociados al ciclo previo ${cicloPrevio} antes de archivar.`);
    }

    cerrarCicloAnterior(proveedorId);

    const docsActivos = db.prepare(`
      SELECT id, proveedor_id, archivo, ciclo
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).all(proveedorId);

    for (const doc of docsActivos) {
      moverDocumentoAHistorico(doc);
    }

    if (proveedor.evaluacion_inicial) {
      const docEvaluacion = {
        id: null,
        proveedor_id: proveedorId,
        archivo: proveedor.evaluacion_inicial,
        ciclo: cicloPrevio || 'sin_ciclo'
      };

      const exito = moverDocumentoAHistorico(docEvaluacion);

      if (exito) {
        console.log(`📄 Evaluación inicial del proveedor ${proveedorId} movida a histórico.`);
      }
    }

    db.prepare(`
      UPDATE proveedores
      SET etapa = 'verificacion',
          estado_general = 'pendiente',
          tipo_gestion = 'actualizacion',
          evaluacion_inicial = NULL,
          evaluacion_estado = 'pendiente',
          evaluacion_fecha = NULL,
          numero_registro = NULL,
          tipo_proveedor = NULL,
          notas_gestion = ?,
          fecha_gestion = NULL,
          todos_subidos = 0,
          todos_verificados = 0
      WHERE id = ?
    `).run(mensaje || `Solicitud de actualización de documentos ${añoActual}`, proveedorId);

    const mensajeRecordatorio = `🔄 Se te ha solicitado actualizar tus documentos para el año ${añoActual}. Por favor, sube toda tu documentación actualizada.`;

    db.prepare(`
      INSERT INTO recordatorios (proveedor_id, admin_id, admin_nombre, mensaje)
      VALUES (?, ?, ?, ?)
    `).run(proveedorId, req.session.usuario.id, req.session.usuario.email, mensajeRecordatorio);

    registrarHistorial(
      proveedorId,
      req.session.usuario,
      'solicitud_actualizacion',
      `Solicitud de actualización anual de documentos ${añoActual}${mensaje ? '. Mensaje: ' + mensaje : ''}`,
      null,
      null,
      req
    );

    const htmlEmail = emailSolicitudActualizacion(nombreProveedor, mensaje, añoActual);

    await enviarEmail(proveedor.email, `🔄 Actualización de Documentos ${añoActual} - Portal de Proveedores`, htmlEmail)
      .then(result => {
        if (result.ok) {
          console.log(`✅ Correo de solicitud de actualización enviado a ${proveedor.email}`);
        } else {
          console.error(`❌ Error enviando correo de actualización: ${result.error}`);
        }
      })
      .catch(err => console.error('Error enviando correo de actualización:', err));

    emitirProveedor(proveedorId, 'nuevo_recordatorio', { mensaje: mensajeRecordatorio });
    emitirAdmin('proveedores_actualizados');
    emitirAdmin('estadisticas_actualizadas');

    res.json({
      ok: true,
      mensaje: `✅ Solicitud de actualización enviada a ${nombreProveedor}. El proveedor ha sido movido a verificación y debe subir sus documentos actualizados.`
    });
  } catch (err) {
    console.error('❌ Error solicitando actualización:', err);
    res.status(500).json({ error: 'Error al solicitar la actualización: ' + err.message });
  }
});

function recuperarDocumentosHuérfanos() {
  try {
    if (!fs.existsSync(uploadsDir)) return;

    const carpetas = fs.readdirSync(uploadsDir);
    let totalRecuperados = 0;

    for (const carpeta of carpetas) {
      if (!/^\d+$/.test(carpeta)) continue;

      const proveedorId = parseInt(carpeta);
      const rutaCarpeta = path.join(uploadsDir, carpeta);

      if (!fs.statSync(rutaCarpeta).isDirectory()) continue;

      const archivos = fs.readdirSync(rutaCarpeta).filter(a => a.endsWith('.enc'));

      for (const archivo of archivos) {
        const relativa = `${carpeta}/${archivo}`;

        const existente = db.prepare(`
          SELECT id
          FROM documentos
          WHERE proveedor_id = ?
            AND archivo = ?
        `).get(proveedorId, relativa);

        if (!existente) {
          let tipo = archivo.split('_')[0];

          const mapTipos = {
            'camara': 'camara_comercio',
            'cedula': 'cedula_rl',
            'cuenta': 'cuenta_bancaria',
            'estados': 'estados_financieros'
          };

          if (mapTipos[tipo]) {
            tipo = mapTipos[tipo];
          }

          if (tipo === 'evaluacion') continue;

          const nombreOriginal = archivo.replace('.enc', '.pdf');

          db.prepare(`
            INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, verificado, no_aplica, subido_en)
            VALUES (?, ?, ?, ?, 'pendiente', 0, 0, datetime('now', 'localtime'))
          `).run(proveedorId, tipo, relativa, nombreOriginal);

          console.log(`🔁 Recuperado automáticamente: ${archivo} para proveedor ${proveedorId}`);
          totalRecuperados++;
        }
      }

      if (archivos.length > 0) {
        actualizarEstadoProveedor(proveedorId);
      }
    }

    if (totalRecuperados > 0) {
      console.log(`✅ ${totalRecuperados} documentos huérfanos recuperados automáticamente.`);
    }
  } catch (err) {
    console.error('❌ Error en recuperación de documentos huérfanos:', err.message);
  }
}

recuperarDocumentosHuérfanos();

function notificarAdminDocumento(proveedorId, usuario, config, nombreArchivoOriginal, accion) {
  console.log(`🔔 [notificarAdminDocumento] Ejecutando para proveedor ${proveedorId}, accion: ${accion}`);

  try {
    const proveedorInfo = db.prepare(`
      SELECT p.id, p.razon_social, u.email, u.nombre_empresa
      FROM proveedores p
      JOIN usuarios u ON p.usuario_id = u.id
      WHERE p.id = ?
    `).get(proveedorId);

    if (!proveedorInfo) return;

    const nombreProveedor = proveedorInfo.razon_social || proveedorInfo.nombre_empresa || 'Proveedor';

    const docs = db.prepare(`
      SELECT tipo, estado, no_aplica
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).all(proveedorId);

    let todosSubidos = true;
    let totalDocumentosSubidos = 0;
    let tieneRechazados = false;

    for (const req of DOCUMENTOS_REQUERIDOS) {
      const docsTipo = docs.filter(d => d.tipo === req.tipo);
      const noAplica = docsTipo.some(d => d.no_aplica === 1);

      if (req.opcional && noAplica) {
        console.log(`   📌 ${req.tipo} (${req.nombre}) → NO APLICA, saltando`);
        continue;
      }

      const subidosValidos = docsTipo.filter(d => d.estado === 'pendiente' || d.estado === 'aprobado').length;
      const rechazados = docsTipo.filter(d => d.estado === 'rechazado').length;

      if (rechazados > 0) {
        tieneRechazados = true;
        console.log(`   ⚠️ ${req.tipo} (${req.nombre}) tiene ${rechazados} documento(s) rechazado(s)`);
      }

      if (subidosValidos < req.cantidadMin) {
        todosSubidos = false;
        console.log(`   ⚠️ ${req.tipo} (${req.nombre}) → Faltan documentos (${subidosValidos}/${req.cantidadMin})`);
      }

      totalDocumentosSubidos += subidosValidos;
    }

    if (todosSubidos && !tieneRechazados && totalDocumentosSubidos > 0) {
      console.log(`\n📋 Proveedor ${nombreProveedor} completó todos los documentos (${totalDocumentosSubidos} docs válidos)`);

      const yaNotificado = db.prepare(`
        SELECT id
        FROM historial
        WHERE proveedor_id = ?
          AND accion = 'notificacion_admin_completos'
          AND creado_en > datetime('now', '-1 day')
      `).get(proveedorId);

      if (!yaNotificado) {
        const htmlEmail = emailProveedorCompletoDocumentos(
          nombreProveedor,
          proveedorInfo.email,
          totalDocumentosSubidos
        );

        enviarEmail(
          process.env.ADMIN_EMAIL,
          `📋 Proveedor completó documentación: ${nombreProveedor}`,
          htmlEmail
        ).then(result => {
          if (result.ok) {
            console.log(`✅ Email enviado al admin sobre proveedor: ${nombreProveedor}`);

            registrarHistorial(
              proveedorId,
              { id: null, email: 'Sistema' },
              'notificacion_admin_completos',
              `Notificación enviada al admin: ${nombreProveedor} completó documentos (${totalDocumentosSubidos} docs)`,
              null,
              null,
              null
            );
          } else {
            console.error(`❌ Error enviando email: ${result.error}`);
          }
        }).catch(err => {
          console.error('❌ Error enviando notificación al admin:', err);
        });
      } else {
        console.log(`⏳ Proveedor ${nombreProveedor} ya fue notificado en las últimas 24h, saltando.`);
      }
    } else {
      console.log(`⏳ Proveedor ${nombreProveedor} aún no completa todos los documentos:`);
      if (!todosSubidos) console.log('   - Faltan documentos por subir');
      if (tieneRechazados) console.log('   - Hay documentos rechazados');
      if (totalDocumentosSubidos === 0) console.log('   - No hay documentos válidos subidos');
    }
  } catch (err) {
    console.error('❌ Error en notificarAdminDocumento:', err.message);
  }
}

function actualizarEstadoProveedor(proveedorId) {
  console.log(`\n🔍 [actualizarEstadoProveedor] Recalculando estado y flags para proveedor ID ${proveedorId}`);

  const prov = db.prepare('SELECT etapa FROM proveedores WHERE id = ?').get(proveedorId);

  if (prov && prov.etapa === 'rechazado') {
    const activosCount = db.prepare(`
      SELECT COUNT(*) as total
      FROM documentos
      WHERE proveedor_id = ?
        AND es_historico = 0
    `).get(proveedorId).total;

    if (activosCount > 0) {
      console.log(`ℹ️ Proveedor ${proveedorId} en etapa 'rechazado' con documentos activos. Reiniciando proceso automáticamente.`);

      db.prepare(`
        UPDATE proveedores
        SET etapa = 'verificacion',
            estado_general = 'pendiente',
            evaluacion_inicial = NULL,
            evaluacion_estado = 'pendiente',
            evaluacion_fecha = NULL,
            numero_registro = NULL,
            tipo_gestion = NULL,
            notas_gestion = NULL,
            fecha_gestion = NULL,
            tipo_proveedor = NULL,
            todos_subidos = 0,
            todos_verificados = 0
        WHERE id = ?
      `).run(proveedorId);

      db.prepare(`
        UPDATE documentos
        SET estado = 'pendiente',
            verificado = 0,
            comentario = 'Elimina el documento rechazado y sube uno nuevo (reinicio de proceso)'
        WHERE proveedor_id = ?
          AND es_historico = 0
      `).run(proveedorId);

      registrarHistorial(
        proveedorId,
        { id: 1, email: 'Sistema' },
        'reinicio_automatico',
        'Proceso reiniciado automáticamente al subir documentos desde rechazado.',
        null,
        null,
        null
      );
    }
  }

  const docs = db.prepare(`
    SELECT tipo, estado, verificado, no_aplica
    FROM documentos
    WHERE proveedor_id = ?
      AND es_historico = 0
  `).all(proveedorId);

  let todoOk = true;
  let hayRechazados = false;
  let todosSubidos = true;
  let todosVerificados = true;

  for (const req of DOCUMENTOS_REQUERIDOS) {
    const docsTipo = docs.filter(d => d.tipo === req.tipo);

    const aprobados = docsTipo.filter(d => d.estado === 'aprobado').length;
    const noAplica = docsTipo.filter(d => d.no_aplica === 1).length;
    const rechazados = docsTipo.filter(d => d.estado === 'rechazado').length;
    const verificados = docsTipo.filter(d => d.verificado === 1).length;

    if (req.opcional && noAplica > 0) {
      continue;
    }

    const subidosValidos = docsTipo.filter(d =>
      d.estado === 'pendiente' ||
      d.estado === 'aprobado' ||
      d.estado === 'rechazado' ||
      d.no_aplica === 1
    ).length;

    if (subidosValidos < req.cantidadMin) {
      todosSubidos = false;
    }

    if (subidosValidos >= req.cantidadMin && rechazados === 0) {
      if (verificados < req.cantidadMin) {
        todosVerificados = false;
      }
    } else {
      todosVerificados = false;
    }

    if (aprobados < req.cantidadMin) {
      todoOk = false;
    }

    if (rechazados > 0) {
      hayRechazados = true;
    }
  }

  let nuevoEstado = 'pendiente';

  if (todoOk) {
    nuevoEstado = 'aprobado';
  } else if (hayRechazados) {
    nuevoEstado = 'rechazado';
  }

  console.log(`🏷️ Estado calculado: ${nuevoEstado}`);
  console.log(`📋 todos_subidos: ${todosSubidos}`);
  console.log(`📋 todos_verificados: ${todosVerificados}`);

  if (nuevoEstado === 'aprobado') {
    db.prepare(`
      UPDATE proveedores
      SET estado_general = ?,
          fecha_aprobacion = datetime('now', 'localtime'),
          todos_subidos = ?,
          todos_verificados = ?
      WHERE id = ?
    `).run(nuevoEstado, todosSubidos ? 1 : 0, todosVerificados ? 1 : 0, proveedorId);
  } else {
    db.prepare(`
      UPDATE proveedores
      SET estado_general = ?,
          todos_subidos = ?,
          todos_verificados = ?
      WHERE id = ?
    `).run(nuevoEstado, todosSubidos ? 1 : 0, todosVerificados ? 1 : 0, proveedorId);
  }

  const provActual = db.prepare('SELECT etapa, fecha_aprobacion FROM proveedores WHERE id = ?').get(proveedorId);

  if (!provActual || !provActual.etapa || provActual.etapa === '') {
    let etapaInicial = 'verificacion';

    if (nuevoEstado === 'aprobado' && provActual && provActual.fecha_aprobacion) {
      etapaInicial = 'registrado';
    } else if (nuevoEstado === 'aprobado') {
      etapaInicial = 'aprobacion';
    } else {
      etapaInicial = 'verificacion';
    }

    db.prepare(`UPDATE proveedores SET etapa = ? WHERE id = ?`).run(etapaInicial, proveedorId);
  }

  return nuevoEstado;
}

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n🚀 Servidor: http://localhost:${PORT}`);
    console.log(`🔐 Seguridad: AES-256-GCM + Rate Limiting + Helmet`);
    console.log(`👤 Admin: ${process.env.ADMIN_EMAIL || 'admin@empresa.com'}\n`);
  }).on('error', (err) => {
    console.error('❌ Error al iniciar el servidor:', err);
  });
} else {
  console.log('⚠️ El servidor se está ejecutando como módulo, no se inicia automáticamente.');
}

module.exports = {
  db,
  actualizarEstadoProveedor
};