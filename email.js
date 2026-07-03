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
            email: process.env.BREVO_SENDER_EMAIL || 'adminempresapruebas1@gmail.com'
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
// PLANTILLA: Proveedor subió documento (para admin)
// ==========================================
function emailProveedorSubioDocumento(nombreProveedor, nombreDocumento, nombreArchivo) {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #7c3aed; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">📄 Nuevo documento recibido</h2>
            </div>
            <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <p>El proveedor <strong>${nombreProveedor}</strong> ha subido/reemplazado un documento.</p>
                <div style="background: #f3f4f6; padding: 15px; border-left: 4px solid #7c3aed; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0;"><strong>Tipo:</strong> ${nombreDocumento}</p>
                    <p style="margin: 5px 0 0 0;"><strong>Archivo:</strong> ${nombreArchivo}</p>
                </div>
                <p>Ingresa al panel de administración para revisarlo.</p>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}/admin.html" 
                       style="background: #7c3aed; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                        Ir al Panel Admin
                    </a>
                </div>
            </div>
        </div>
    `;
}

// ==========================================
// PLANTILLA: Documento rechazado (para proveedor)
// ==========================================
function emailDocumentoRechazado(nombreProveedor, nombreDocumento, motivo) {
    const motivoHtml = motivo ? `
        <div style="background: #fee2e2; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
            <p style="margin: 0;"><strong>Motivo del rechazo:</strong></p>
            <p style="margin: 5px 0 0 0;">${motivo}</p>
        </div>
    ` : '';

    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">❌ Documento Rechazado</h2>
            </div>
            <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <p>Hola <strong>${nombreProveedor}</strong>,</p>
                <p>El siguiente documento fue <strong>rechazado</strong> y requiere tu atención:</p>
                <div style="background: #f3f4f6; padding: 15px; border-left: 4px solid #dc2626; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0;"><strong>Documento:</strong> ${nombreDocumento}</p>
                </div>
                ${motivoHtml}
                <p>Por favor, ingresa al portal para subir una versión corregida.</p>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}/proveedor.html" 
                       style="background: #c2410c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                        Ir al Portal
                    </a>
                </div>
            </div>
        </div>
    `;
}

// ==========================================
// PLANTILLA: Proveedor completó todos los documentos (para ADMIN)
// ==========================================
// Se envía UN SOLO correo al admin cuando el proveedor sube TODOS los documentos
function emailProveedorCompletoDocumentos(nombreProveedor, emailProveedor, totalDocumentos) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #059669 0%, #10b981 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1 style="margin: 0; font-size: 28px;">📋 Documentos Completados</h1>
      </div>
      <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
        <h2 style="color: #059669; margin-top: 0;">Proveedor ha completado su documentación</h2>
        
        <div style="background: #d1fae5; padding: 20px; border-left: 4px solid #059669; margin: 20px 0; border-radius: 4px;">
          <p style="margin: 0 0 10px 0; font-size: 18px; font-weight: bold; color: #065f46;">
            👤 ${nombreProveedor}
          </p>
          <p style="margin: 0; color: #047857;">
            📧 ${emailProveedor}
          </p>
        </div>
        
        <p>El proveedor ha subido <strong>todos los documentos requeridos</strong> (${totalDocumentos} documentos en total) y están listos para su revisión.</p>
        
        <div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 20px 0; border-radius: 4px;">
          <p style="margin: 0;"><strong>️ Acción requerida:</strong></p>
          <p style="margin: 10px 0 0 0;">Ingresa al panel de administración para revisar y aprobar/rechazar cada documento.</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.SISTEMA_URL || 'http://localhost:3000'}/admin.html" 
             style="background: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
            Ir al Panel de Administración
          </a>
        </div>
        
        <div style="background: #f3f4f6; padding: 15px; border-radius: 4px; margin-top: 20px;">
          <p style="margin: 0; font-size: 14px; color: #6b7280;">
            <strong>Resumen:</strong><br>
            ✅ Todos los documentos han sido subidos<br>
             Estado: Pendiente de revisión<br>
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
// PLANTILLA: Proveedor completamente aprobado (¡Felicidades!)
// ==========================================
function emailProveedorAprobado(nombreProveedor) {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #7c3aed 0%, #c2410c 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 32px;">🎉 ¡Felicidades!</h1>
            </div>
            <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <h2 style="color: #059669; margin-top: 0;">Proveedor Aprobado</h2>
                <p>Hola <strong>${nombreProveedor}</strong>,</p>
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
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}/proveedor.html" 
                       style="background: #059669; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
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
// PLANTILLA: Nueva nota del admin (para proveedor)
// ==========================================
function emailNuevaNota(nombreProveedor, titulo, nota) {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #c2410c; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">📝 Nueva nota del administrador</h2>
            </div>
            <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <p>Hola <strong>${nombreProveedor}</strong>,</p>
                <p>El administrador ha dejado una nueva nota para ti:</p>
                
                <div style="background: #fff7ed; padding: 20px; border-left: 4px solid #c2410c; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 10px 0; font-weight: bold; color: #9a3412;">${titulo}</p>
                    <p style="margin: 0; white-space: pre-wrap;">${nota}</p>
                </div>
                
                <p>Ingresa al portal para ver más detalles.</p>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}/proveedor.html" 
                       style="background: #c2410c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                        Ver en el Portal
                    </a>
                </div>
            </div>
        </div>
    `;
}

// ==========================================
// PLANTILLA: Bienvenida con credenciales (para proveedor nuevo)
// ==========================================
function emailBienvenidaProveedor(email, password, nombreEmpresa) {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #7c3aed 0%, #c2410c 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0;">🏢 Bienvenido al Portal de Proveedores</h1>
            </div>
            <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <p>Hola <strong>${nombreEmpresa}</strong>,</p>
                <p>Tu cuenta ha sido creada exitosamente. Aquí están tus credenciales de acceso:</p>
                
                <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; font-family: monospace;">
                    <p style="margin: 0 0 10px 0;"><strong>📧 Email:</strong> ${email}</p>
                    <p style="margin: 0;"><strong>🔑 Contraseña:</strong> ${password}</p>
                </div>
                
                <div style="background: #fef3c7; padding: 15px; border-left: 4px solid #f59e0b; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0;"><strong>⚠️ Importante:</strong> Por seguridad, el sistema te pedirá cambiar esta contraseña la primera vez que ingreses.</p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}" 
                       style="background: #7c3aed; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
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
// PLANTILLA: Recordatorio (para proveedor)
// ==========================================
function emailRecordatorio(nombreProveedor, mensaje) {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #c2410c; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">📨 Recordatorio del administrador</h2>
            </div>
            <div style="background: white; padding: 25px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <p>Hola <strong>${nombreProveedor}</strong>,</p>
                <p>Has recibido un recordatorio del administrador:</p>
                
                <div style="background: #fed7aa; padding: 20px; border-left: 4px solid #c2410c; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0; white-space: pre-wrap;">${mensaje}</p>
                </div>
                
                <p>Por favor, ingresa al portal para atender este recordatorio.</p>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="${process.env.APP_URL || 'https://gestion-de-proveedores-production.up.railway.app/'}/proveedor.html" 
                       style="background: #c2410c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                        Ir al Portal
                    </a>
                </div>
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
    emailNuevaNota,
    emailBienvenidaProveedor,
    emailRecordatorio,
    emailProveedorCompletoDocumentos
};