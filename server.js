// ==========================================
// 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ==========================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Importar módulos personalizados
const { db, DOCUMENTOS_REQUERIDOS } = require('./database');
const { 
  cifrarArchivo, 
  descifrarArchivo, 
  esBufferCifrado,
  calcularHash, 
  verificarHash,
  validarPassword, 
  generarPasswordAleatoria,
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
  emailBienvenidaProveedor,
  emailRecordatorio
} = require('./email');

const app = express();
const PORT = process.env.PORT || 3000;

// 🔧 CRÍTICO para Railway/Render (proxy inverso)
app.set('trust proxy', 1);

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Validar variables de entorno críticas
if (!validarClaveMaestra(ENCRYPTION_KEY)) {
  console.error('❌ ENCRYPTION_KEY no es válida (mínimo 32 caracteres)');
  process.exit(1);
}

if (!validarClaveMaestra(SESSION_SECRET)) {
  console.error('❌ SESSION_SECRET no es válida (mínimo 32 caracteres)');
  process.exit(1);
}

// Usar volumen persistente en Railway, o local en desarrollo
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const uploadsDir = path.join(dataDir, 'uploads');
const plantillasDir = path.join(dataDir, 'plantillas');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(plantillasDir)) fs.mkdirSync(plantillasDir, { recursive: true });

// Mostrar configuración de seguridad al iniciar
console.log('\n🔐 Configuración de seguridad:');
console.table(obtenerConfiguracionSeguridad());

// Verificar sistema de cifrado
const testCifrado = verificarSistemaCifrado(ENCRYPTION_KEY);
console.log(testCifrado.mensaje);

if (!testCifrado.funcional) {
  console.error('❌ El sistema de cifrado NO está funcionando');
  process.exit(1);
}


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

// Rate Limiting
const limiterLogin = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: 'Demasiados intentos.' } });
const limiterGeneral = rateLimit({ windowMs: 1 * 60 * 1000, max: 100, message: { error: 'Demasiadas peticiones.' } });
const limiterUpload = rateLimit({ windowMs: 5 * 60 * 1000, max: 20, message: { error: 'Demasiadas subidas.' } });

app.use('/api/login', limiterLogin);
app.use('/api/registro', limiterLogin);
app.use('/api/', limiterGeneral);

// Parseo de datos
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 🔧 SESSION STORE PERSISTENTE CON ARCHIVOS (versión robusta)
const FileStore = require('session-file-store');
const FileStoreInstance = FileStore(session);

// Crear carpeta de sesiones en el volumen persistente
const sessionsDir = path.join(dataDir, 'sessions');
if (!fs.existsSync(sessionsDir)) fs.mkdirSync(sessionsDir, { recursive: true });

// 🧹 Función para limpiar sesiones corruptas al iniciar
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
        
        // Verificar que tenga la estructura correcta
        if (!sesion || !sesion.cookie || !sesion.cookie.expires) {
          fs.unlinkSync(rutaArchivo);
          limpiados++;
        }
      } catch (err) {
        // Si no se puede leer o parsear, eliminar el archivo
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

// Ejecutar limpieza al iniciar
limpiarSesionesCorruptas();

// Configuración robusta de session-file-store
const fileStoreOptions = {
  path: sessionsDir,
  ttl: 60 * 60 * 8,           // 8 horas
  retries: 0,                  // No reintentar
  logFn: () => {},             // Silenciar logs
  fallbackSessionFn: () => ({  // Sesión por defecto si falla
    cookie: {
      originalMaxAge: null,
      expires: null,
      secure: false,
      httpOnly: true,
      path: '/',
      sameSite: 'lax'
    }
  }),
  reapInterval: 60 * 60,       // Limpia expiradas cada hora
  reapAsync: true,             // Limpieza asíncrona
  useReapInterval: true
};

app.use(session({
  store: new FileStoreInstance(fileStoreOptions),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 8,
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// 🛡️ Middleware para manejar errores de sesión
app.use((err, req, res, next) => {
  // Si el error es de sesión corrupta, destruir la sesión y continuar
  if (err && err.message && err.message.includes('expires')) {
    console.log('⚠️ Sesión corrupta detectada, destruyendo...');
    if (req.session) {
      req.session.destroy(() => {});
    }
    // Limpiar cookie
    res.clearCookie('connect.sid');
    return res.redirect('/');
  }
  next(err);
});

// Archivos estáticos
app.use('/plantillas', express.static(plantillasDir));
app.use(express.static(path.join(__dirname, 'public')));


// ==========================================
// 3. FUNCIONES HELPER
// ==========================================
function obtenerIP(req) { 
  return req.ip || req.connection.remoteAddress || 'unknown'; 
}

function registrarLogSeguridad(usuarioId, email, accion, exitoso, detalle = '', req = null) {
  try {
    db.prepare(`INSERT INTO logs_seguridad (usuario_id, email, accion, ip_origen, user_agent, detalle, exitoso) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      usuarioId, email, accion, req ? obtenerIP(req) : null, req ? (req.headers['user-agent'] || '').substring(0, 200) : null, detalle, exitoso ? 1 : 0
    );
  } catch (e) { 
    console.error('Error log:', e.message); 
  }
}

function obtenerCarpetaProveedor(proveedorId) {
  const prov = db.prepare('SELECT id, razon_social FROM proveedores WHERE id = ?').get(proveedorId);
  if (!prov) return uploadsDir;
  const nombre = (prov.razon_social || `Proveedor_${prov.id}`).replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').substring(0, 50);
  const carpeta = `${prov.id}_${nombre}`;
  const ruta = path.join(uploadsDir, carpeta);
  if (!fs.existsSync(ruta)) fs.mkdirSync(ruta, { recursive: true });
  return ruta;
}

function obtenerRutaRelativa(proveedorId, nombreArchivo) {
  const prov = db.prepare('SELECT id, razon_social FROM proveedores WHERE id = ?').get(proveedorId);
  if (!prov) return nombreArchivo;
  const nombre = (prov.razon_social || `Proveedor_${prov.id}`).replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').substring(0, 50);
  return `${prov.id}_${nombre}/${nombreArchivo}`;
}

function registrarHistorial(proveedorId, usuario, accion, detalle, docTipo = null, docId = null, req = null) {
  db.prepare(`INSERT INTO historial (proveedor_id, usuario_id, usuario_nombre, accion, detalle, documento_tipo, documento_id, ip_origen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    proveedorId, usuario?.id || null, usuario?.email || 'Sistema', accion, detalle, docTipo, docId, req ? obtenerIP(req) : null
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
    .replace(/'/g, '&#039;');
}

function formatearFechaExcel(fecha) {
  if (!fecha) return '';
  const d = new Date(fecha.replace(' ', 'T'));
  return d.toLocaleString('es-CO', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function fechaArchivo() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}`;
}

// Función para enviar notificación al admin cuando un proveedor sube/reemplaza documento
function notificarAdminDocumento(proveedorId, usuario, config, nombreArchivoOriginal, accion) {
  try {
    const proveedorInfo = db.prepare('SELECT razon_social FROM proveedores WHERE id = ?').get(proveedorId);
    const nombreProveedor = proveedorInfo?.razon_social || 'Proveedor';
    
    const accionEmail = accion === 'documento_reemplazado' ? 'reemplazado' : 'subido';
    
    enviarEmail(
      process.env.ADMIN_EMAIL,
      `📄 Documento ${accionEmail}: ${config.nombre}`,
      emailProveedorSubioDocumento(nombreProveedor, config.nombre, nombreArchivoOriginal)
    ).catch(err => console.error('Error enviando notificación al admin:', err));
  } catch (err) {
    console.error('Error en notificarAdminDocumento:', err.message);
  }
}

// ==========================================
// 📊 ACTUALIZAR ESTADO DEL PROVEEDOR
// ==========================================
/**
 * Evalúa el estado general del proveedor basándose en sus documentos
 * Envía email de felicitaciones cada vez que todos los documentos estén aprobados
 * (Ideal para renovaciones anuales de proveedores)
 */
function actualizarEstadoProveedor(proveedorId) {
  const provAnterior = db.prepare('SELECT estado_general FROM proveedores WHERE id = ?').get(proveedorId);
  const estadoAnterior = provAnterior ? provAnterior.estado_general : null;
  
  const docs = db.prepare('SELECT tipo, estado, no_aplica FROM documentos WHERE proveedor_id = ?').all(proveedorId);
  const agrupado = {};
  docs.forEach(d => { 
    if (!agrupado[d.tipo]) agrupado[d.tipo] = []; 
    agrupado[d.tipo].push(d.estado); 
  });
  
  let todoOk = true;
  for (const req of DOCUMENTOS_REQUERIDOS) {
    const docsTipo = docs.filter(d => d.tipo === req.tipo);
    const aprobados = docsTipo.filter(d => d.estado === 'aprobado').length;
    const noAplica = docsTipo.filter(d => d.no_aplica === 1).length;
    
    if (req.opcional && noAplica > 0) continue;
    
    if (aprobados < req.cantidadMin) { 
      todoOk = false; 
      break; 
    }
  }
  
  const hayRechazados = docs.some(d => d.estado === 'rechazado');
  let estado = 'pendiente';
  if (todoOk) estado = 'aprobado';
  else if (hayRechazados) estado = 'rechazado';
  
  db.prepare('UPDATE proveedores SET estado_general = ? WHERE id = ?').run(estado, proveedorId);
  
  if (estado === 'aprobado') {
    console.log(`\n🎉 Proveedor aprobado: ID ${proveedorId}`);
    
    const proveedorInfo = db.prepare(`
      SELECT u.email, u.nombre_empresa, p.razon_social 
      FROM usuarios u 
      JOIN proveedores p ON u.id = p.usuario_id 
      WHERE p.id = ?
    `).get(proveedorId);
    
    if (proveedorInfo) {
      const nombreProveedor = proveedorInfo.razon_social || proveedorInfo.nombre_empresa || 'Proveedor';
      console.log(`📧 Enviando email a: ${proveedorInfo.email}`);
      
      try {
        const html = emailProveedorAprobado(nombreProveedor);
        enviarEmail(
          proveedorInfo.email,
          `🎉 ¡Felicidades! Tu registro como proveedor ha sido aprobado`,
          html
        ).then(result => {
          if (result.ok) {
            console.log(` ✅ Email enviado`);
          } else {
            console.error(`❌ Error email: ${result.error}`);
          }
        }).catch(err => {
          console.error(`❌ Error:`, err);
        });
      } catch (err) {
        console.error(`❌ Error generando HTML:`, err);
      }
    }
  }
  
  return estado;
}


// ==========================================
// 4. CONFIGURACIÓN DE MULTER (UPLOADS)
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


// ==========================================
// 6. ENDPOINTS DE AUTENTICACIÓN
// ==========================================
app.post('/api/registro', limiterUpload, (req, res) => {
  const { email, password, nombre_empresa } = req.body;
  if (!email || !password || !nombre_empresa) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  const validacion = validarPassword(password);
  if (!validacion.valido) return res.status(400).json({ error: validacion.mensaje });
  try {
    const existente = db.prepare('SELECT id FROM usuarios WHERE email = ?').get(email);
    if (existente) return res.status(400).json({ error: 'Email ya registrado' });
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare('INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password) VALUES (?, ?, ?, ?, 0)').run(email, hash, 'proveedor', nombre_empresa);
    const provResult = db.prepare('INSERT INTO proveedores (usuario_id, razon_social) VALUES (?, ?)').run(result.lastInsertRowid, nombre_empresa);
    registrarHistorial(provResult.lastInsertRowid, { id: result.lastInsertRowid, email }, 'registro', `Proveedor registrado: ${nombre_empresa}`, null, null, req);
    registrarLogSeguridad(result.lastInsertRowid, email, 'registro_proveedor', true, nombre_empresa, req);
    res.json({ ok: true });
  } catch (err) {
    registrarLogSeguridad(null, email, 'registro_proveedor', false, err.message, req);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
  if (!usuario) {
    registrarLogSeguridad(null, email, 'login', false, 'Email no encontrado', req);
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  if (usuario.bloqueado_hasta) {
    const bloqueoHasta = new Date(usuario.bloqueado_hasta);
    if (bloqueoHasta > new Date()) {
      const minutos = Math.ceil((bloqueoHasta - new Date()) / 60000);
      return res.status(423).json({ error: `Cuenta bloqueada. Intenta en ${minutos} minutos.` });
    } else {
      db.prepare('UPDATE usuarios SET bloqueado_hasta = NULL, intentos_fallidos = 0 WHERE id = ?').run(usuario.id);
    }
  }
  if (!bcrypt.compareSync(password, usuario.password)) {
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
  req.session.usuario = { id: usuario.id, email: usuario.email, rol: usuario.rol };
  registrarLogSeguridad(usuario.id, email, 'login_exitoso', true, null, req);
  res.json({ ok: true, rol: usuario.rol, debe_cambiar_password: usuario.debe_cambiar_password === 1 });
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
  if (req.session.usuario) registrarLogSeguridad(req.session.usuario.id, req.session.usuario.email, 'logout', true, null, req);
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.usuario) return res.json({ usuario: null });
  const u = db.prepare('SELECT debe_cambiar_password FROM usuarios WHERE id = ?').get(req.session.usuario.id);
  res.json({ usuario: req.session.usuario, debe_cambiar_password: u?.debe_cambiar_password === 1 });
});


// ==========================================
// 7. ENDPOINTS DE PROVEEDOR
// ==========================================
app.get('/api/proveedor/info', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT * FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  res.json(p);
});

app.post('/api/proveedor/datos', requiereLogin, (req, res) => {
    const { razon_social, rfc, representante, telefono, direccion } = req.body;
    
    // 🛡️ VALIDACIÓN OBLIGATORIA: El backend exige que los 5 campos estén llenos
    if (!razon_social || !rfc || !representante || !telefono || !direccion ||
        !razon_social.trim() || !rfc.trim() || !representante.trim() || !telefono.trim() || !direccion.trim()) {
        return res.status(400).json({ error: 'Todos los datos de la empresa son obligatorios para desbloquear el portal.' });
    }

    const prov = db.prepare('SELECT * FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
    
    // Guardar datos limpios (sin espacios extra)
    db.prepare('UPDATE proveedores SET razon_social=?, rfc=?, representante=?, telefono=?, direccion=? WHERE usuario_id=?')
        .run(razon_social.trim(), rfc.trim(), representante.trim(), telefono.trim(), direccion.trim(), req.session.usuario.id);
        
    registrarHistorial(prov.id, req.session.usuario, 'datos_actualizados', `Datos de empresa completados. Razón social: ${razon_social}`, null, null, req);
    
    // Devolvemos ok: true para que el frontend sepa que puede desbloquear el panel
    res.json({ ok: true, perfil_completo: true });
});

// 📄 PROVEEDOR SUBE/REEMPLAZA DOCUMENTO (con notificación al admin)
app.post('/api/proveedor/documento', requiereLogin, (req, res, next) => {
  // Si es JSON con no_aplica, procesar sin multer
  if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
    const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
    if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });
    
    const { tipo, no_aplica } = req.body;
    const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
    if (!config) return res.status(400).json({ error: 'Tipo inválido' });

    if (no_aplica === true || no_aplica === 'true') {
      if (!config.opcional) {
        return res.status(400).json({ error: 'Este documento no tiene opción "No aplica"' });
      }
      
      const existente = db.prepare('SELECT id FROM documentos WHERE proveedor_id=? AND tipo=?').get(proveedor.id, tipo);
      
      if (existente) {
        db.prepare('UPDATE documentos SET no_aplica = 1, estado = \'aprobado\', comentario = \'No aplica - Marcado por el proveedor\' WHERE id = ?')
          .run(existente.id);
        registrarHistorial(proveedor.id, req.session.usuario, 'documento_no_aplica',
          `Documento "${config.nombre}" marcado como NO APLICA`, tipo, existente.id, req);
      } else {
        const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, no_aplica, comentario) VALUES (?,?,?,?,?,?,?)')
          .run(proveedor.id, tipo, 'no_aplica', 'No aplica', 'aprobado', 1, 'No aplica - Marcado por el proveedor');
        registrarHistorial(proveedor.id, req.session.usuario, 'documento_no_aplica',
          `Documento "${config.nombre}" marcado como NO APLICA`, tipo, r.lastInsertRowid, req);
      }
      
      actualizarEstadoProveedor(proveedor.id);
      return res.json({ ok: true, mensaje: 'Documento marcado como No Aplica' });
    }
    
    return res.status(400).json({ error: 'Se requiere archivo o marcar no_aplica' });
  }
  
  // Si es FormData (archivo), continuar con multer
  next();
}, uploadDoc.single('archivo'), (req, res) => {
  const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });
  
  if (!req.file) return res.status(400).json({ error: 'Archivo PDF requerido' });
  
  const { tipo } = req.body;
  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
  if (!config) return res.status(400).json({ error: 'Tipo inválido' });

  try {
    const hashOriginal = calcularHash(req.file.buffer);
    const bufferCifrado = cifrarArchivo(req.file.buffer, ENCRYPTION_KEY);
    
    const nombreArchivoCifrado = `${req.body.tipo}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.enc`;
    const carpeta = obtenerCarpetaProveedor(proveedor.id);
    const rutaArchivo = path.join(carpeta, nombreArchivoCifrado);
    fs.writeFileSync(rutaArchivo, bufferCifrado);
    
    const rutaRelativa = obtenerRutaRelativa(proveedor.id, nombreArchivoCifrado);
    let docId, accion;

    if (config.cantidadMin === 1) {
      const existente = db.prepare('SELECT id, archivo FROM documentos WHERE proveedor_id=? AND tipo=?').get(proveedor.id, tipo);
      if (existente) {
        const rutaVieja = path.join(uploadsDir, existente.archivo);
        if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
        db.prepare('UPDATE documentos SET archivo=?, nombre_original=?, hash_archivo=?, estado=?, comentario=NULL, no_aplica=0 WHERE id=?')
          .run(rutaRelativa, req.file.originalname, hashOriginal, 'pendiente', existente.id);
        docId = existente.id;
        accion = 'documento_reemplazado';
      } else {
        const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica) VALUES (?,?,?,?,?,0)')
          .run(proveedor.id, tipo, rutaRelativa, req.file.originalname, hashOriginal);
        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    } else {
      const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo, no_aplica) VALUES (?,?,?,?,?,0)')
        .run(proveedor.id, tipo, rutaRelativa, req.file.originalname, hashOriginal);
      docId = r.lastInsertRowid;
      accion = 'documento_subido';
    }

    registrarHistorial(proveedor.id, req.session.usuario, accion,
      `Documento "${config.nombre}" subido: ${req.file.originalname}`, tipo, docId, req);
    
    actualizarEstadoProveedor(proveedor.id);
    
    // 📧 NOTIFICAR AL ADMIN QUE SE SUBIÓ/REEMPLAZÓ UN DOCUMENTO
    notificarAdminDocumento(proveedor.id, req.session.usuario, config, req.file.originalname, accion);
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Error cifrando archivo:', err);
    res.status(500).json({ error: 'Error al procesar el documento' });
  }
});

// 📋 PROVEEDOR MARCA DOCUMENTO COMO "NO APLICA"
app.post('/api/proveedor/documento/:id/no-aplica', requiereLogin, (req, res) => {
  const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  const doc = db.prepare('SELECT * FROM documentos WHERE id=? AND proveedor_id=?').get(req.params.id, proveedor.id);
  
  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });
  
  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);
  if (!config || !config.opcional) {
    return res.status(400).json({ error: 'Este documento no tiene opción "No aplica"' });
  }
  
  const { no_aplica } = req.body;
  
  if (no_aplica) {
    db.prepare('UPDATE documentos SET no_aplica = 1, estado = \'aprobado\', comentario = \'No aplica - Marcado por el proveedor\' WHERE id = ?').run(doc.id);
    registrarHistorial(proveedor.id, req.session.usuario, 'documento_no_aplica',
      `Documento "${config.nombre}" marcado como NO APLICA`, doc.tipo, doc.id, req);
  } else {
    db.prepare('UPDATE documentos SET no_aplica = 0, estado = \'pendiente\', comentario = NULL WHERE id = ?').run(doc.id);
    registrarHistorial(proveedor.id, req.session.usuario, 'documento_requiere_carga',
      `Documento "${config.nombre}" ahora requiere carga`, doc.tipo, doc.id, req);
  }
  
  actualizarEstadoProveedor(proveedor.id);
  res.json({ ok: true });
});

app.delete('/api/proveedor/documento/:id', requiereLogin, (req, res) => {
  const proveedor = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  const doc = db.prepare('SELECT * FROM documentos WHERE id=? AND proveedor_id=?').get(req.params.id, proveedor.id);
  if (!doc) return res.status(404).json({ error: 'No encontrado' });
  const ruta = path.join(uploadsDir, doc.archivo);
  if (fs.existsSync(ruta)) fs.unlinkSync(ruta);
  db.prepare('DELETE FROM documentos WHERE id=?').run(doc.id);
  registrarHistorial(proveedor.id, req.session.usuario, 'documento_eliminado', `Documento eliminado: ${doc.nombre_original}`, doc.tipo, doc.id, req);
  actualizarEstadoProveedor(proveedor.id);
  res.json({ ok: true });
});

app.get('/api/proveedor/documentos', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  res.json(db.prepare('SELECT * FROM documentos WHERE proveedor_id = ?').all(p.id));
});

app.get('/api/proveedor/requerimientos', requiereLogin, (req, res) => {
  const requeridos = DOCUMENTOS_REQUERIDOS.map(r => {
    let plantilla = null;
    if (r.esPlantilla) plantilla = db.prepare('SELECT archivo, nombre_original FROM plantillas WHERE tipo = ?').get(r.tipo);
    return { ...r, plantilla };
  });
  res.json(requeridos);
});

// 📥 DESCARGAR PLANTILLA (descarga forzada con nombre original)
app.get('/api/proveedor/plantilla/:tipo', requiereLogin, (req, res) => {
  const { tipo } = req.params;
  
  // Buscar la plantilla en la base de datos
  const plantilla = db.prepare('SELECT * FROM plantillas WHERE tipo = ?').get(tipo);
  if (!plantilla) {
    return res.status(404).json({ error: 'Plantilla no encontrada' });
  }
  
  const rutaPlantilla = path.join(plantillasDir, plantilla.archivo);
  
  if (!fs.existsSync(rutaPlantilla)) {
    return res.status(404).json({ error: 'Archivo de plantilla no encontrado' });
  }
  
  // Detectar MIME type según la extensión
  const extension = path.extname(plantilla.archivo).toLowerCase();
  const mimeTypes = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  };
  
  const mimeType = mimeTypes[extension] || 'application/octet-stream';
  
  // Configurar headers para descarga forzada
  res.setHeader('Content-Type', mimeType);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(plantilla.nombre_original)}"`);
  res.setHeader('Content-Length', fs.statSync(rutaPlantilla).size);
  
  // Enviar el archivo
  const fileStream = fs.createReadStream(rutaPlantilla);
  fileStream.pipe(res);
  
  fileStream.on('error', (err) => {
    console.error('Error enviando plantilla:', err);
    res.status(500).json({ error: 'Error al descargar la plantilla' });
  });
});

app.get('/api/proveedor/historial', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  res.json(db.prepare('SELECT * FROM historial WHERE proveedor_id = ? ORDER BY creado_en DESC LIMIT 200').all(p.id));
});

app.get('/api/proveedor/recordatorios', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  // 🔧 Solo mostrar recordatorios NO cerrados
  res.json(db.prepare(`
    SELECT * FROM recordatorios 
    WHERE proveedor_id = ? AND (cerrada = 0 OR cerrada IS NULL)
    ORDER BY creado_en DESC
  `).all(p.id));
});

app.post('/api/proveedor/recordatorio/:id/leido', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  db.prepare('UPDATE recordatorios SET leido = 1 WHERE id = ? AND proveedor_id = ?').run(req.params.id, p.id);
  res.json({ ok: true });
});

app.get('/api/proveedor/notas', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  // 🔧 Solo mostrar notas NO cerradas (cerrada = 0 o NULL)
  res.json(db.prepare(`
    SELECT * FROM notas_proveedor 
    WHERE proveedor_id = ? AND (cerrada = 0 OR cerrada IS NULL)
    ORDER BY creado_en DESC
  `).all(p.id));
});

app.post('/api/proveedor/nota/:id/leida', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  db.prepare('UPDATE notas_proveedor SET leida = 1 WHERE id = ? AND proveedor_id = ?').run(req.params.id, p.id);
  res.json({ ok: true });
});

// 🆕 CERRAR NOTA (no volverá a aparecer en el panel)
app.post('/api/proveedor/nota/:id/cerrar', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  if (!p) return res.status(404).json({ error: 'Proveedor no encontrado' });
  
  const nota = db.prepare('SELECT id FROM notas_proveedor WHERE id = ? AND proveedor_id = ?')
    .get(req.params.id, p.id);
  if (!nota) return res.status(404).json({ error: 'Nota no encontrada' });
  
  db.prepare('UPDATE notas_proveedor SET cerrada = 1, leida = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true, mensaje: 'Nota cerrada' });
});

// 🆕 CERRAR RECORDATORIO (no volverá a aparecer en el panel)
app.post('/api/proveedor/recordatorio/:id/cerrar', requiereLogin, (req, res) => {
  const p = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(req.session.usuario.id);
  if (!p) return res.status(404).json({ error: 'Proveedor no encontrado' });
  
  const rec = db.prepare('SELECT id FROM recordatorios WHERE id = ? AND proveedor_id = ?')
    .get(req.params.id, p.id);
  if (!rec) return res.status(404).json({ error: 'Recordatorio no encontrado' });
  
  db.prepare('UPDATE recordatorios SET cerrada = 1, leido = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true, mensaje: 'Recordatorio cerrado' });
});


// ==========================================
// 8. ENDPOINTS DE ADMINISTRADOR
// ==========================================
app.get('/api/admin/proveedores', requiereAdmin, (req, res) => {
  const proveedores = db.prepare(`SELECT p.*, u.email, u.nombre_empresa FROM proveedores p JOIN usuarios u ON p.usuario_id = u.id ORDER BY p.id DESC`).all();
  proveedores.forEach(p => {
    const docs = db.prepare('SELECT tipo, estado FROM documentos WHERE proveedor_id = ?').all(p.id);
    const agrupado = {};
    docs.forEach(d => { if (!agrupado[d.tipo]) agrupado[d.tipo] = []; agrupado[d.tipo].push(d.estado); });
    let aprobados = 0;
    DOCUMENTOS_REQUERIDOS.forEach(r => {
      if ((agrupado[r.tipo] || []).filter(e => e === 'aprobado').length >= r.cantidadMin) aprobados++;
    });
    p.aprobados = aprobados;
    p.total = DOCUMENTOS_REQUERIDOS.length;
    const recs = db.prepare('SELECT COUNT(*) as n FROM recordatorios WHERE proveedor_id=? AND leido=0').get(p.id);
    p.recordatorios_pendientes = recs.n;
    const notasCount = db.prepare('SELECT COUNT(*) as n FROM notas_proveedor WHERE proveedor_id=?').get(p.id);
    p.notas_count = notasCount.n;
    if (p.estado_general === 'aprobado') {
      const ultimaAprobacion = db.prepare(`SELECT creado_en FROM historial WHERE proveedor_id = ? AND accion = 'documento_aprobado' ORDER BY creado_en DESC LIMIT 1`).get(p.id);
      p.fecha_aprobacion = ultimaAprobacion ? ultimaAprobacion.creado_en : null;
    } else {
      p.fecha_aprobacion = null;
    }
  });
  res.json(proveedores);
});

app.get('/api/admin/proveedor/:id', requiereAdmin, (req, res) => {
  const p = db.prepare('SELECT p.*, u.email, u.nombre_empresa FROM proveedores p JOIN usuarios u ON p.usuario_id = u.id WHERE p.id = ?').get(req.params.id);
  if (!p) {
  return res.status(404).json({ error: 'Proveedor no encontrado' });}
  const docs = db.prepare('SELECT * FROM documentos WHERE proveedor_id = ?').all(p.id);
  res.json({ proveedor: p, documentos: docs, requeridos: DOCUMENTOS_REQUERIDOS });
});

app.post('/api/admin/documento/:id/estado', requiereAdmin, (req, res) => {
  const { estado, comentario } = req.body;
  if (!['pendiente','aprobado','rechazado'].includes(estado)) return res.status(400).json({ error: 'Estado inválido' });
  const doc = db.prepare('SELECT * FROM documentos WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'No encontrado' });
  
  db.prepare('UPDATE documentos SET estado=?, comentario=? WHERE id=?').run(estado, comentario || null, req.params.id);
  
  const nombreAccion = estado === 'aprobado' ? 'documento_aprobado' : estado === 'rechazado' ? 'documento_rechazado' : 'documento_revisado';
  const detalle = estado === 'aprobado' 
    ? `Documento aprobado: ${doc.nombre_original}` 
    : `Documento rechazado: ${doc.nombre_original}${comentario ? '. Motivo: ' + comentario : ''}`;
  
  registrarHistorial(doc.proveedor_id, req.session.usuario, nombreAccion, detalle, doc.tipo, doc.id, req);
  actualizarEstadoProveedor(doc.proveedor_id);
  
  // 📧 SOLO enviar email cuando se RECHAZA (NO cuando se aprueba)
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
  
  // ✅ Si se aprueba, NO se envía email individual (solo al final cuando todos estén aprobados)
  if (estado === 'aprobado') {
    console.log(`✅ Documento aprobado individualmente (no se envía email): ${doc.nombre_original}`);
  }
  
  res.json({ ok: true });
});

app.get('/api/admin/proveedor/:id/historial', requiereAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM historial WHERE proveedor_id = ? ORDER BY creado_en DESC LIMIT 500').all(req.params.id));
});

app.post('/api/admin/proveedor/:id/recordatorio', requiereAdmin, (req, res) => {
  const { mensaje } = req.body;
  if (!mensaje || !mensaje.trim()) return res.status(400).json({ error: 'Mensaje requerido' });
  const prov = db.prepare('SELECT id FROM proveedores WHERE id = ?').get(req.params.id);
  if (!prov) return res.status(404).json({ error: 'Proveedor no encontrado' });
  db.prepare('INSERT INTO recordatorios (proveedor_id, admin_id, admin_nombre, mensaje) VALUES (?,?,?,?)').run(prov.id, req.session.usuario.id, req.session.usuario.email, mensaje.trim());
  registrarHistorial(prov.id, req.session.usuario, 'recordatorio_enviado', `Recordatorio enviado: ${mensaje.trim()}`, null, null, req);
  res.json({ ok: true });
});

// 🧹 ENDPOINT PARA LIMPIAR SESIONES (solo admin)
app.post('/api/admin/limpiar-sesiones', requiereAdmin, (req, res) => {
  try {
    limpiarSesionesCorruptas();
    
    // También limpiar todas las sesiones
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

// 📄 ADMIN SUBE DOCUMENTO PARA PROVEEDOR
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
    
    const nombreArchivoCifrado = `${req.body.tipo}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.enc`;
    const carpeta = obtenerCarpetaProveedor(proveedorId);
    const rutaArchivo = path.join(carpeta, nombreArchivoCifrado);
    fs.writeFileSync(rutaArchivo, bufferCifrado);
    
    const rutaRelativa = obtenerRutaRelativa(proveedorId, nombreArchivoCifrado);
    let docId, accion;

    if (config.cantidadMin === 1) {
      const existente = db.prepare('SELECT id, archivo FROM documentos WHERE proveedor_id=? AND tipo=?').get(proveedorId, tipo);
      if (existente) {
        const rutaVieja = path.join(uploadsDir, existente.archivo);
        if (fs.existsSync(rutaVieja)) fs.unlinkSync(rutaVieja);
        db.prepare('UPDATE documentos SET archivo=?, nombre_original=?, hash_archivo=?, estado=?, comentario=NULL WHERE id=?')
          .run(rutaRelativa, req.file.originalname, hashOriginal, 'pendiente', existente.id);
        docId = existente.id;
        accion = 'documento_reemplazado';
      } else {
        const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo) VALUES (?,?,?,?,?)')
          .run(proveedorId, tipo, rutaRelativa, req.file.originalname, hashOriginal);
        docId = r.lastInsertRowid;
        accion = 'documento_subido';
      }
    } else {
      const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, hash_archivo) VALUES (?,?,?,?,?)')
        .run(proveedorId, tipo, rutaRelativa, req.file.originalname, hashOriginal);
      docId = r.lastInsertRowid;
      accion = 'documento_subido';
    }

    registrarHistorial(proveedorId, req.session.usuario, accion,
      `Documento "${config.nombre}" subido por admin: ${req.file.originalname}`, tipo, docId, req);
    
    actualizarEstadoProveedor(proveedorId);
    
    res.json({ 
      ok: true, 
      mensaje: `Documento "${config.nombre}" subido exitosamente para el proveedor`,
      docId: docId
    });
  } catch (err) {
    console.error('Error subiendo documento como admin:', err);
    res.status(500).json({ error: 'Error al procesar el documento: ' + err.message });
  }
});

app.get('/api/admin/proveedor/:id/notas', requiereAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM notas_proveedor WHERE proveedor_id = ? ORDER BY creado_en DESC').all(req.params.id));
});

app.post('/api/admin/proveedor/:id/nota', requiereAdmin, (req, res) => {
  const { titulo, nota } = req.body;
  if (!nota || !nota.trim()) return res.status(400).json({ error: 'Nota requerida' });
  const prov = db.prepare('SELECT id FROM proveedores WHERE id = ?').get(req.params.id);
  if (!prov) return res.status(404).json({ error: 'Proveedor no encontrado' });
  db.prepare('INSERT INTO notas_proveedor (proveedor_id, admin_id, admin_nombre, titulo, nota) VALUES (?,?,?,?,?)').run(prov.id, req.session.usuario.id, req.session.usuario.email, (titulo || 'Nota').trim(), nota.trim());
  registrarHistorial(prov.id, req.session.usuario, 'nota_agregada', `Nota agregada: ${titulo || 'Sin título'} - ${nota.trim().substring(0, 100)}`, null, null, req);
  
  // 📧 Notificar al proveedor sobre la nueva nota
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
  res.json({ ok: true });
});

// 📋 ADMIN MARCAR DOCUMENTO COMO "NO APLICA"
app.post('/api/admin/proveedor/:id/documento/:docId/no-aplica', requiereAdmin, (req, res) => {
  const proveedorId = parseInt(req.params.id);
  const docId = parseInt(req.params.docId);
  const { no_aplica, tipo } = req.body;
  
  const proveedor = db.prepare('SELECT * FROM proveedores WHERE id = ?').get(proveedorId);
  if (!proveedor) return res.status(404).json({ error: 'Proveedor no encontrado' });
  
  if (docId === 0 || !docId) {
    const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === tipo);
    if (!config) return res.status(400).json({ error: 'Tipo de documento inválido' });
    
    const r = db.prepare('INSERT INTO documentos (proveedor_id, tipo, archivo, nombre_original, estado, no_aplica, comentario) VALUES (?,?,?,?,?,?,?)')
      .run(proveedorId, tipo, 'no_aplica', 'No aplica', 'aprobado', 1, 'No aplica - Marcado por admin');
    
    registrarHistorial(proveedorId, req.session.usuario, 'documento_no_aplica',
      `Documento "${config.nombre}" marcado como NO APLICA por admin`, tipo, r.lastInsertRowid, req);
    
    actualizarEstadoProveedor(proveedorId);
    return res.json({ ok: true, mensaje: 'Documento marcado como No Aplica' });
  }
  
  const doc = db.prepare('SELECT * FROM documentos WHERE id = ? AND proveedor_id = ?').get(docId, proveedorId);
  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });
  
  const config = DOCUMENTOS_REQUERIDOS.find(d => d.tipo === doc.tipo);
  
  if (no_aplica) {
    db.prepare('UPDATE documentos SET no_aplica = 1, estado = \'aprobado\', comentario = \'No aplica - Marcado por admin\' WHERE id = ?').run(doc.id);
    registrarHistorial(proveedorId, req.session.usuario, 'documento_no_aplica',
      `Documento "${config?.nombre || doc.tipo}" marcado como NO APLICA por admin`, doc.tipo, doc.id, req);
  } else {
    db.prepare('UPDATE documentos SET no_aplica = 0, estado = \'pendiente\', comentario = NULL WHERE id = ?').run(doc.id);
    registrarHistorial(proveedorId, req.session.usuario, 'documento_requiere_carga',
      `Documento "${config?.nombre || doc.tipo}" ahora requiere carga (admin quitó "No aplica")`, doc.tipo, doc.id, req);
  }
  
  actualizarEstadoProveedor(proveedorId);
  res.json({ ok: true });
});

// 🆕 CREAR PROVEEDOR DESDE ADMIN
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
    const result = db.prepare('INSERT INTO usuarios (email, password, rol, nombre_empresa, debe_cambiar_password) VALUES (?, ?, ?, ?, 1)')
      .run(email, hash, 'proveedor', nombre_empresa);
    
    const provResult = db.prepare('INSERT INTO proveedores (usuario_id, razon_social, rfc, representante, telefono, direccion) VALUES (?, ?, ?, ?, ?, ?)')
      .run(result.lastInsertRowid, razon_social || nombre_empresa, rfc || '', representante || '', telefono || '', direccion || '');
    
    registrarHistorial(provResult.lastInsertRowid, req.session.usuario, 'registro', 
      `Proveedor creado por admin: ${nombre_empresa}`, null, null, req);
    registrarLogSeguridad(result.lastInsertRowid, email, 'proveedor_creado_admin', true, nombre_empresa, req);
    
    // 📧 Enviar email con credenciales usando la plantilla centralizada
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
    res.json({ ok: true, mensaje: `Proveedor "${nombreProv}" eliminado completamente` });
  } catch (err) {
    registrarLogSeguridad(admin.id, admin.email, 'eliminar_proveedor_error', false, err.message, req);
    res.status(500).json({ error: 'Error al eliminar el proveedor' });
  }
});

app.get('/api/admin/plantillas', requiereAdmin, (req, res) => res.json(db.prepare('SELECT * FROM plantillas').all()));

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
    db.prepare('UPDATE plantillas SET archivo=?, nombre_original=? WHERE tipo=?').run(nombreArchivo, req.file.originalname, tipo);
  } else {
    db.prepare('INSERT INTO plantillas (tipo, archivo, nombre_original) VALUES (?,?,?)').run(tipo, nombreArchivo, req.file.originalname);
  }
  fs.writeFileSync(ruta, req.file.buffer);
  res.json({ ok: true });
});

// EXPORTAR EXCEL
app.post('/api/admin/exportar-excel', requiereAdmin, (req, res) => {
  try {
    const { proveedores } = req.body;
    if (!proveedores || proveedores.length === 0) {
      return res.status(400).json({ error: 'No hay proveedores para exportar' });
    }

    let html = `
      <html xmlns:o="urn:schemas-microsoft-com:office:office" 
            xmlns:x="urn:schemas-microsoft-com:office:excel" 
            xmlns="http://www.w3.org/TR/REC-html40">
      <head>
        <meta charset="UTF-8">
        <style>
          table { border-collapse: collapse; width: 100%; }
          th { background-color: #1E40AF; color: white; padding: 10px; text-align: left; border: 1px solid #1e3a8a; font-weight: bold; }
          td { padding: 8px; border: 1px solid #d1d5db; }
          tr:nth-child(even) { background-color: #f9fafb; }
          .estado-aprobado { color: #065f46; font-weight: bold; }
          .estado-pendiente { color: #92400e; font-weight: bold; }
          .estado-rechazado { color: #991b1b; font-weight: bold; }
        </style>
      </head>
      <body>
        <table>
          <thead>
            <tr>
              <th>Razón Social</th>
              <th>NIT/RUT</th>
              <th>Correo</th>
              <th>Teléfono</th>
              <th>Representante Legal</th>
              <th>Dirección</th>
              <th>Estado</th>
              <th>Docs Aprobados</th>
              <th>Total</th>
              <th>Fecha Aprobación</th>
            </tr>
          </thead>
          <tbody>
    `;

    proveedores.forEach(p => {
      const estadoClase = `estado-${p.estado_general || 'pendiente'}`;
      const fechaAprob = p.fecha_aprobacion ? formatearFechaExcel(p.fecha_aprobacion) : 'Pendiente';
      html += `
        <tr>
          <td>${escapeHtml(p.razon_social || p.nombre_empresa || '')}</td>
          <td>${escapeHtml(p.rfc || '')}</td>
          <td>${escapeHtml(p.email || '')}</td>
          <td>${escapeHtml(p.telefono || '')}</td>
          <td>${escapeHtml(p.representante || '')}</td>
          <td>${escapeHtml((p.direccion || '').replace(/[\n\r]+/g, ' '))}</td>
          <td class="${estadoClase}">${escapeHtml(p.estado_general || '')}</td>
          <td style="text-align:center;">${p.aprobados || 0}</td>
          <td style="text-align:center;">${p.total || 0}</td>
          <td>${escapeHtml(fechaAprob)}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
      </body>
      </html>
    `;

    const BOM = '\uFEFF';
    const contenido = BOM + html;

    res.setHeader('Content-Type', 'application/vnd.ms-excel; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=proveedores_${fechaArchivo()}.xls`);
    res.send(contenido);
  } catch (err) {
    console.error('Error exportando Excel:', err);
    res.status(500).json({ error: 'Error al generar el archivo Excel' });
  }
});

// 🔐 ENDPOINTS DE DIAGNÓSTICO DE SEGURIDAD
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


// ==========================================
// 9. SERVICIO DE ARCHIVOS
// ==========================================
app.get('/uploads/:path(*)', requiereLogin, (req, res) => {
  const rutaArchivo = path.join(uploadsDir, req.params.path);
  const usuario = req.session.usuario;
  let tieneAcceso = false;
  let documentoInfo = null;
  
  if (usuario.rol === 'admin') {
    tieneAcceso = true;
    documentoInfo = db.prepare('SELECT nombre_original FROM documentos WHERE archivo = ?').get(req.params.path);
  } else {
    const prov = db.prepare('SELECT id FROM proveedores WHERE usuario_id = ?').get(usuario.id);
    if (prov) {
      const doc = db.prepare('SELECT archivo, nombre_original FROM documentos WHERE proveedor_id = ? AND archivo = ?').get(prov.id, req.params.path);
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
      const nombreArchivo = documentoInfo?.nombre_original || path.basename(req.params.path);
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
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.message });
  if (err) return res.status(400).json({ error: err.message });
  next();
});

app.listen(PORT, () => {
  console.log(`\n🚀 Servidor: http://localhost:${PORT}`);
  console.log(`🔐 Seguridad: AES-256-GCM + Rate Limiting + Helmet`);
  console.log(`👤 Admin: ${process.env.ADMIN_EMAIL || 'admin@empresa.com'}\n`);
});