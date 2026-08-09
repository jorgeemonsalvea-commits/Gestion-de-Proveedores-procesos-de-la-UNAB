const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();
// ==========================================
// CONFIGURACIÓN DEL CLIENTE BREVO
// ==========================================
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY;
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
// ==========================================
// 🔗 URL BASE NORMALIZADA (a prueba de errores en .env)
// Previene errores como "Cannot GET /;/proveedor.html"
// limpiando ; , espacios y barras sobrantes automáticamente
// ==========================================
const BASE_URL = (process.env.APP_URL || 'http://localhost:3000/')
.trim()                    // quita espacios al inicio/final
.replace(/[;,\s]+$/g, '')  // quita ; , y espacios al final
.replace(/\/+$/g, '');     // quita barras al final
// 🛡️ M4 (Fase 3): escape de HTML para prevenir XSS en correos.
// Todo dato del usuario (nombres, motivos, notas) DEBE pasar por aquí
// antes de inyectarse en el HTML del email.
function escapeHtml(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;')
.replace(/"/g, '&quot;')
.replace(/'/g, '&#39;');
}
// ==========================================
// FUNCIÓN BASE: enviarEmail
// ==========================================
/**
* Envía un correo usando la API de Brevo
* @param {string} toEmail - Correo del destinatario
* @param {string} subject - Asunto del correo
* @param {string} htmlContent - Contenido HTML del correo
* @returns {Promise<{ok: boolean, messageId?: string, error?: string}>}
*/
async function enviarEmail(toEmail, subject, htmlContent) {
try {
if (!process.env.BREVO_API_KEY) {
throw new Error('BREVO_API_KEY no está configurada en variables de entorno');
}
if (!toEmail) {
throw new Error('Correo destinatario no proporcionado');
}
const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
sendSmtpEmail.subject = subject;
sendSmtpEmail.htmlContent = htmlContent;
sendSmtpEmail.sender = {
name: process.env.BREVO_SENDER_NAME || 'Portal de Proveedores',
email: process.env.BREVO_SENDER_EMAIL || 'padminprog@gmail.com'
};
sendSmtpEmail.to = [{ email: toEmail }];
const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
console.log(`✅ Correo enviado a ${toEmail}. MessageID:`, data.messageId);
return { ok: true, messageId: data.messageId };
} catch (error) {
const errorDetail = error.response?.body || error.message;
console.error(`❌ Error enviando correo a ${toEmail}:`, errorDetail);
return { ok: false, error: typeof errorDetail === 'string' ? errorDetail : JSON.stringify(errorDetail) };
}
}
// ==========================================
// 🎨 PALETA UNAB EN CORREOS (R6) — referencia de los hex usados:
//   Marca / acción / header neutro : #8600dd  (hover/oscuro #6b00b0)
//   Acento / filete / borde marca  : #e9a427  (texto sobre claro #8a5a00)
//   Éxito                          : #059669 / #047857
//   Peligro                        : #dc2626
//   Proceso / actualización        : #2563eb / #1d4ed8
//   Advertencia (semántico)        : #fef3c7 / #f59e0b / #92400e  (intacto)
//   Regla WCAG: el dorado NUNCA es fondo de texto blanco.
// ==========================================
// ==========================================
// PLANTILLA: Proveedor subió documento (para admin) — MARCA (morado)
// ==========================================
function emailProveedorSubioDocumento(nombreProveedor, nombreDocumento, nombreArchivo) {

const prov = escapeHtml(nombreProveedor);
const doc = escapeHtml(nombreDocumento);
const arch = escapeHtml(nombreArchivo);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #8600dd; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">📄 Nuevo documento recibido</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>El proveedor <strong>${prov}</strong> ha subido/reemplazado un documento.</p>
<div style="background: #f3f4f6; padding: 15px; border-left: 4px solid #e9a427; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>Tipo:</strong> ${doc}</p>
<p style="margin: 5px 0 0 0;"><strong>Archivo:</strong> ${arch}</p>
</div>
<p>Ingresa al panel de administración para revisarlo.</p>
<div style="text-align: center; margin-top: 20px;">
<a href="${BASE_URL}/admin.html" style="background: #8600dd; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
Ir al Panel Admin
</a>
</div>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Documento rechazado (para proveedor) — PELIGRO (rojo)
// ==========================================
function emailDocumentoRechazado(nombreProveedor, nombreDocumento, motivo) {
////////////////////
const prov = escapeHtml(nombreProveedor);
const doc = escapeHtml(nombreDocumento);
const mot = escapeHtml(motivo);
const motivoHtml = motivo ? `
<div style="background: #fee2e2; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>Motivo del rechazo:</strong></p>
<p style="margin: 5px 0 0 0;">${mot}</p>
</div>
` : '';
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">❌ Documento Rechazado</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${prov}</strong>,</p>
<p>El siguiente documento fue <strong>rechazado</strong> y requiere tu atención:</p>
<div style="background: #f3f4f6; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>Documento:</strong> ${doc}</p>
</div>
${motivoHtml}
<p>Por favor, ingresa al portal para eliminar el documento rechazado y luego subir una versión corregida.</p>
<div style="text-align: center; margin-top: 20px;">
<a href="${BASE_URL}/proveedor.html" style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
Ir al Portal
</a>
</div>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Proveedor completó todos los documentos (para ADMIN) — ÉXITO (verde, intacta)
// ==========================================
function emailProveedorCompletoDocumentos(nombreProveedor, emailProveedor, totalDocumentos) {
////////////////////
const prov = escapeHtml(nombreProveedor);
const email = escapeHtml(emailProveedor);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #059669 0%, #10b981 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0; font-size: 28px;">📋 Documentos Completados</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<h2 style="color: #059669; margin-top: 0;">Proveedor ha completado su documentación</h2>
<div style="background: #d1fae5; padding: 20px; border-left: 4px solid #059669; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0 0 10px 0; font-size: 18px; font-weight: bold; color: #065f46;">👤 ${prov}</p>
<p style="margin: 0; color: #047857;">📧 ${email}</p>
</div>
<p>El proveedor ha subido <strong>todos los documentos requeridos</strong> (${totalDocumentos} documentos en total) y están listos para su revisión.</p>
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>⚠️ Acción requerida:</strong></p>
<p style="margin: 10px 0 0 0;">Ingresa al panel de administración para revisar y aprobar/rechazar cada documento.</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/admin.html" style="background: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
Ir al Panel de Administración
</a>
</div>
<div style="background: #f3f4f6; padding: 15px; border-radius: 4px; margin-top: 20px;">
<p style="margin: 0; font-size: 14px; color: #6b7280;">
<strong>Resumen:</strong><br>
✅ Todos los documentos han sido subidos<br>
📋 Estado: Pendiente de revisión<br>
📋 Total de documentos: ${totalDocumentos}
</p>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Saludos,<br>
<strong>Sistema de Gestión de Proveedores</strong>
</p>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Proveedor completamente aprobado (¡Felicidades!) — ÉXITO (verde)
// ==========================================
function emailProveedorAprobado(nombreProveedor) {
////////////////////
const prov = escapeHtml(nombreProveedor);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #059669 0%, #047857 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0; font-size: 32px;">🎉 ¡Felicidades!</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<h2 style="color: #059669; margin-top: 0;">Proveedor Aprobado</h2>
<p>Hola <strong>${prov}</strong>,</p>
<p>¡Nos complace informarte que has completado exitosamente todos los requisitos de documentación!</p>
<div style="background: #d1fae5; padding: 20px; border-left: 4px solid #059669; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; font-size: 16px;">
✅ Todos tus documentos han sido aprobados<br>
✅ Tu cuenta de proveedor está activa<br>
✅ Ya puedes participar en nuestros procesos de compra
</p>
</div>
<p>Ahora formas parte de nuestro directorio de proveedores autorizados. Nuestro equipo de compras podrá contactarte para futuras oportunidades de negocio.</p>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/proveedor.html" style="background: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
Ir a mi Panel de Proveedor
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Si tienes alguna pregunta o necesitas actualizar tu información, no dudes en contactarnos.
</p>
<p>¡Bienvenido a nuestro equipo de proveedores!<br>
<strong>Equipo de Compras</strong></p>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Actualización de documentos aprobada (renovación) — ÉXITO (verde)
// Diferencia una RENOVACIÓN de un alta nueva: no dice "¡Felicidades, ya eres
// proveedor", sino "tu actualización fue aprobada y tu registro continúa activo".
// Mismo lenguaje visual de aprobación (header verde + filete dorado) por coherencia.
// ==========================================
function emailProveedorActualizacionAprobada(nombreProveedor) {
const prov = escapeHtml(nombreProveedor);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #059669 0%, #047857 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0; font-size: 30px;">✅ Actualización Aprobada</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<h2 style="color: #059669; margin-top: 0;">Tu renovación de documentos fue aprobada</h2>
<p>Hola <strong>${prov}</strong>,</p>
<p>Hemos revisado y <strong>aprobado</strong> la documentación actualizada que enviaste para el período vigente. ¡Gracias por mantener tu información al día!</p>
<div style="background: #d1fae5; padding: 20px; border-left: 4px solid #059669; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; font-size: 16px; color: #065f46;">
✅ Tus documentos actualizados fueron aprobados<br>
✅ Tu proceso de renovación avanza correctamente<br>
⏳ El cierre administrativo de tu registro se completará en breve
</p>
</div>
<p>Tu registro como proveedor continúa su curso. Nuestro equipo finalizará el trámite administrativo correspondiente; por ahora <strong>no necesitas realizar ninguna acción adicional</strong>.</p>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/proveedor.html" style="background: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
Ir a mi Panel de Proveedor
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Si tienes alguna pregunta o detectas algún dato por corregir, no dudes en contactarnos.<br><br>
Saludos,<br>
<strong>Equipo de Compras</strong>
</p>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Nueva nota del admin (para proveedor) — MARCA (morado)
// ==========================================
function emailNuevaNota(nombreProveedor, titulo, nota) {
////////////////////
const prov = escapeHtml(nombreProveedor);
const tit = escapeHtml(titulo);
const nt = escapeHtml(nota);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #8600dd; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">📝 Nueva nota del administrador</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${prov}</strong>,</p>
<p>El administrador ha dejado una nueva nota para ti:</p>
<div style="background: #fdf4e3; padding: 20px; border-left: 4px solid #e9a427; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0 0 10px 0; font-weight: bold; color: #8a5a00;">${tit}</p>
<p style="margin: 0; white-space: pre-wrap;">${nt}</p>
</div>
<p>Ingresa al portal para ver más detalles.</p>
<div style="text-align: center; margin-top: 20px;">
<a href="${BASE_URL}/proveedor.html" style="background: #8600dd; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
Ver en el Portal
</a>
</div>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Bienvenida con credenciales (para proveedor nuevo) — MARCA (morado)
// ==========================================
function emailBienvenidaProveedor(email, password, nombreEmpresa) {
const emp = escapeHtml(nombreEmpresa);
const eml = escapeHtml(email);
const pass = escapeHtml(password);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #8600dd 0%, #6b00b0 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0;">🏢 Bienvenido al Portal de Proveedores</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${emp}</strong>,</p>
<p>Tu cuenta ha sido creada exitosamente. Aquí están tus credenciales de acceso:</p>
<div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; font-family: monospace;">
<p style="margin: 0 0 10px 0;"><strong>📧 Email:</strong> ${eml}</p>
<p style="margin: 0;"><strong>🔑 Contraseña:</strong> ${pass}</p>
</div>
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>⚠️ Importante:</strong> Por seguridad, el sistema te pedirá cambiar esta contraseña la primera vez que ingreses.</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/" style="background: #8600dd; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
Ingresar al Portal
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Si no reconoces esta cuenta o tienes problemas para acceder, contacta al administrador.
</p>
<p>Saludos,<br><strong>Equipo de Compras</strong></p>
</div>
</div>
`;
}

// ==========================================
// PLANTILLA: Bienvenida con enlace de activación (sin contraseña) — MARCA (morado)
// ==========================================
function emailBienvenidaConActivacion(email, nombreEmpresa, enlaceActivacion) {
const emp = escapeHtml(nombreEmpresa);
const eml = escapeHtml(email);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #8600dd 0%, #6b00b0 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0;">🏢 Bienvenido al Portal de Proveedores</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${emp}</strong>,</p>
<p>Tu cuenta ha sido creada exitosamente. Para activar tu acceso, haz clic en el siguiente enlace y crea tu contraseña:</p>
<div style="text-align: center; margin: 30px 0;">
<a href="${enlaceActivacion}" style="background: #8600dd; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
Activar mi cuenta
</a>
</div>
<p style="word-break: break-all; background: #f3f4f6; padding: 10px; border-radius: 4px; font-size: 0.85rem;">${enlaceActivacion}</p>
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>⚠️ Importante:</strong> Este enlace expira en 7 días y solo puede usarse una vez. Si no lo activas, contacta al administrador.</p>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Si no reconoces esta cuenta o tienes problemas para acceder, contacta al administrador.
</p>
<p>Saludos,<br><strong>Equipo de Compras</strong></p>
</div>
</div>
`;
}

// ==========================================
// PLANTILLA: Recordatorio (para proveedor) — MARCA (morado)
// ==========================================
function emailRecordatorio(nombreProveedor, mensaje) {
const prov = escapeHtml(nombreProveedor);
const msg = escapeHtml(mensaje);
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #8600dd; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">📨 Recordatorio del administrador</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${prov}</strong>,</p>
<p>Has recibido un recordatorio del administrador:</p>
<div style="background: #fdf4e3; padding: 20px; border-left: 4px solid #e9a427; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0; white-space: pre-wrap; color: #8a5a00;">${msg}</p>
</div>
<p>Por favor, ingresa al portal para atender este recordatorio.</p>
<div style="text-align: center; margin-top: 20px;">
<a href="${BASE_URL}/proveedor.html" style="background: #8600dd; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
Ir al Portal
</a>
</div>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Recordatorio de documentos faltantes — MARCA (morado)
// ==========================================
function emailRecordatorioDocumentosFaltantes(nombreProveedor, documentosFaltantes) {
const prov = escapeHtml(nombreProveedor);
const listaHtml = documentosFaltantes.map(doc => {
const nombreDoc = escapeHtml(doc.nombre);
let estadoTexto = '';
if (doc.estado === 'rechazado') {
estadoTexto = ' <span style="color:#dc2626;font-weight:bold;">(Rechazado - Debes corregirlo)</span>';
} else {
estadoTexto = ' <span style="color:#6b7280;">(No subido)</span>';
}
return `<li style="margin-bottom: 6px; color: #1f2937;">📄 ${nombreDoc}${estadoTexto}</li>`;
}).join('');
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #8600dd; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">⚠️ Recordatorio de Documentos Pendientes</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p style="font-size: 16px; color: #1f2937; margin: 0 0 16px 0;">
Hola <strong>${prov}</strong>,
</p>
<p style="color: #374151; line-height: 1.6; margin: 0 0 16px 0;">
Hemos notado que aún tienes documentos pendientes para completar tu registro como proveedor.
Para agilizar el proceso, por favor sube los siguientes documentos lo antes posible:
</p>
<div style="background: #fee2e2; padding: 20px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #dc2626;">
<h4 style="margin: 0 0 12px 0; color: #991b1b;">📋 Documentos requeridos:</h4>
<ul style="margin: 0; padding-left: 20px; color: #7f1d1d; line-height: 1.8;">
${listaHtml}
</ul>
</div>
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; color: #92400e; font-size: 14px;">
<strong>⚠️ Importante:</strong> Ingresa a tu panel para subir los documentos faltantes;
recuerda que es de suma importancia para continuar con el proceso.
</p>
</div>
<p style="color: #374151; line-height: 1.6; margin: 0 0 20px 0;">
Ingresa a tu panel para subir los documentos o resolver cualquier duda.
</p>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/proveedor.html" style="background: #8600dd; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
Ir a mi Panel
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Este es un recordatorio automático del Sistema de Gestión de Proveedores.
</p>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Evaluación inicial rechazada — PELIGRO (rojo, intacta)
// ==========================================
function emailEvaluacionRechazada(nombreProveedor, motivo) {
const prov = escapeHtml(nombreProveedor);
const mot = escapeHtml(motivo);
const motivoHtml = motivo ? `
<div style="background: #fee2e2; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>Motivo del rechazo:</strong></p>
<p style="margin: 5px 0 0 0;">${mot}</p>
</div>
` : '';
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h2 style="margin: 0;">❌ Evaluación Inicial Rechazada</h2>
</div>
<div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p>Hola <strong>${prov}</strong>,</p>
<p>Lamentamos informarte que tu evaluación inicial para ser proveedor ha sido rechazada.</p>
<p><strong>Como consecuencia, todos tus documentos han sido rechazados y deberás volver a subirlos.</strong></p>
${motivoHtml}
<p>Por favor, ingresa al portal para corregir los documentos y comenzar nuevamente el proceso.</p>
<div style="text-align: center; margin-top: 20px;">
<a href="${BASE_URL}/proveedor.html" style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
Ir al Portal
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Saludos,<br>
<strong>Equipo de Compras</strong>
</p>
</div>
</div>
`;
}
// ==========================================
// PLANTILLA: Solicitud de actualización anual — PROCESO (azul, intacta)
// ==========================================
function emailSolicitudActualizacion(nombreProveedor, mensajeAdmin, año) {
////////////////////
const prov = escapeHtml(nombreProveedor);
const msgAdmin = escapeHtml(mensajeAdmin);
const mensajeHtml = mensajeAdmin ? `
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 15px 0; border-radius: 4px;">
<p style="margin: 0;"><strong>Mensaje del administrador:</strong></p>
<p style="margin: 5px 0 0 0; white-space: pre-wrap;">${msgAdmin}</p>
</div>
` : '';
return `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; border-bottom: 4px solid #e9a427;">
<h1 style="margin: 0; font-size: 28px;">🔄 Actualización de Documentos ${año}</h1>
</div>
<div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
<p style="font-size: 16px; color: #1f2937;">Hola <strong>${prov}</strong>,</p>
<p style="color: #374151; line-height: 1.6;">
Te informamos que es necesario realizar la <strong>actualización anual de tus documentos</strong> para mantener tu registro activo como proveedor.
</p>
<div style="background: #dbeafe; padding: 20px; border-left: 4px solid #2563eb; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; font-size: 16px; color: #1e40af;">
<strong>📋 Acción requerida:</strong><br>
Debes ingresar al portal y subir toda tu documentación actualizada. Una vez completada, nuestro equipo la revisará y aprobará.
</p>
</div>
${mensajeHtml}
<div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; color: #92400e; font-size: 14px;">
<strong>⚠️ Importante:</strong> Tu documentación anterior será archivada y deberás subir nueva documentación para continuar como proveedor activo.
</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="${BASE_URL}/proveedor.html" style="background: #2563eb; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
Actualizar mis Documentos
</a>
</div>
<p style="color: #6b7280; font-size: 14px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
Si tienes alguna pregunta, no dudes en contactar al área de compras.<br><br>
Saludos,<br>
<strong>Equipo de Compras</strong>
</p>
</div>
</div>
`;
}
// ==========================================
// EXPORTACIONES
// ==========================================
module.exports = {
enviarEmail,
emailProveedorSubioDocumento,
emailDocumentoRechazado,
emailProveedorAprobado,
emailProveedorActualizacionAprobada,
emailNuevaNota,
emailBienvenidaProveedor,
emailBienvenidaConActivacion,
emailRecordatorio,
emailProveedorCompletoDocumentos,
emailRecordatorioDocumentosFaltantes,
emailEvaluacionRechazada,
emailSolicitudActualizacion
};