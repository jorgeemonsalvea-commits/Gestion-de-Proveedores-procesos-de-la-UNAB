// ==========================================
// 🧩 F8: UTILIDADES COMPARTIDAS (admin + proveedor)
// Fuente única de verdad para los helpers que estaban duplicados
// en /js/admin.js y /js/proveedor.js. Cargar ANTES que ambos.
// ==========================================

// 📅 Fecha civil Bogotá → presentación es-CO (FIX TZ global: nunca toISOString)
function formatearFecha(f) {
if (!f) return '';
return new Date(String(f).replace(' ', 'T') + '-05:00').toLocaleString('es-CO', {
year: 'numeric', month: '2-digit', day: '2-digit',
hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'America/Bogota'
});
}

// 🛡️ Escape para texto visible (innerHTML)
function escapeHtml(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
.replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// 🛡️ Escape para VALORES de atributos HTML (data-*, href)
function escapeAttr(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;')
.replace(/"/g, '&quot;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;');
}

// 📅 Estado de vencimiento (vigente / próximo / vencido / sin fecha)
function obtenerEstadoVencimiento(fechaVencimiento) {
if (!fechaVencimiento) return { clase: 'sin-fecha', texto: 'Sin fecha', icono: '⚪' };
const hoy = new Date();
const venc = new Date(String(fechaVencimiento).replace(' ', 'T') + '-05:00');
const diffDias = Math.ceil((venc - hoy) / (1000 * 60 * 60 * 24));
if (diffDias < 0) return { clase: 'vencido', texto: 'Vencido', icono: '🔴' };
else if (diffDias <= 30) return { clase: 'proximo-a-vencer', texto: 'Próximo a vencer', icono: '🟡' };
else return { clase: 'vigente', texto: 'Vigente', icono: '🟢' };
}

// 🏷️ Nombre del FORMATO/categoría (lee el global `requeridos` de cada página)
function nombreFormato(tipo) {
const r = (requeridos || []).find(x => x.tipo === tipo);
return r ? r.nombre : (tipo || 'Documento');
}

// 🛡️ Abre el visor leyendo datos desde data-attributes (anti-XSS en onclick)
function verDocumentoBtn(btn) {
verDocumento(btn.dataset.url, btn.dataset.nombre || 'Documento');
}

// ==========================================
// 🪪 G7: TIPO DE DOCUMENTO CO (espejo del server)
// ==========================================
const TIPOS_DOCUMENTO_CO = ['nit', 'cc', 'ce', 'pas'];
function normalizarNumeroDocumento(v) { return String(v || '').replace(/[\s.\-]/g, '').toUpperCase(); }
function validarDocumentoCO(tipo, numero) {
const t = String(tipo || 'nit').toLowerCase();
const n = normalizarNumeroDocumento(numero);
if (!TIPOS_DOCUMENTO_CO.includes(t)) return { valido: false, mensaje: 'Tipo de documento inválido.' };
if (!n) return { valido: true, numero: '' }; // vacío = opcional al crear
if (t === 'nit' && !/^\d{7,15}$/.test(n)) return { valido: false, mensaje: 'NIT: 7 a 15 dígitos sin puntos ni guion.' };
if (t === 'cc' && !/^\d{6,12}$/.test(n)) return { valido: false, mensaje: 'Cédula: 6 a 12 dígitos.' };
if (t === 'ce' && !/^\d{6,15}$/.test(n)) return { valido: false, mensaje: 'C.E.: 6 a 15 dígitos.' };
if (t === 'pas' && !/^[A-Z0-9]{6,15}$/.test(n)) return { valido: false, mensaje: 'Pasaporte: 6 a 15 caracteres alfanuméricos.' };
return { valido: true, numero: n };
}

// ==========================================
// 📞 G11: TELÉFONO CO (máscara 3-3-4 + validación)
// ==========================================
const TEL_CO_RE = { cel: /^3\d{9}$/, fijo: /^(60|70)\d{8}$/ };
function normalizarDigitosCO(v) {
let d = String(v || '').replace(/\D+/g, '');
if (d.length === 12 && d.startsWith('57')) d = d.slice(2);
return d;
}
function formatearTelefonoCO(v) {
const d = normalizarDigitosCO(v).slice(0, 10);
return d.replace(/^(.{3})(.{0,3})(.{0,4})$/, (m, a, b, c) => [a, b, c].filter(Boolean).join(' '));
}
function validarTelefonoCO(v) {
const d = normalizarDigitosCO(v);
if (!d) return { valido: true, mensaje: '' };
if (TEL_CO_RE.cel.test(d)) return { valido: true, mensaje: '📱 Celular válido' };
if (TEL_CO_RE.fijo.test(d)) return { valido: true, mensaje: '☎️ Fijo válido' };
return { valido: false, mensaje: 'Formato CO: 3XX XXX XXXX (celular) o 60X XXX XXXX (fijo) · 10 dígitos' };
}
// ==========================================
// 🧹 F9: MOTIVO DE RECHAZO LIMPIO (sube desde proveedor.js a utils)
// Retira sufijos automáticos legados para mostrar solo el motivo real.
// ==========================================
function limpiarMotivoRechazo(comentario) {
if (!comentario) return '';
let texto = String(comentario).trim();
const sufijos = [
'— Debes eliminar este documento antes de subir uno nuevo.',
'Debes eliminar este documento antes de subir uno nuevo.',
'Debes eliminar este documento rechazado antes de subir uno nuevo',
'Debes subir una nueva versión (reinicio de proceso)'
];
sufijos.forEach(sufijo => {
if (texto.endsWith(sufijo)) texto = texto.substring(0, texto.length - sufijo.length).trim();
const idx = texto.indexOf('— ' + sufijo);
if (idx !== -1) texto = texto.substring(0, idx).trim();
});
texto = texto.replace(/\s*—\s*Debes eliminar.*$/i, '').trim();
texto = texto.replace(/^Documento rechazado\.\s*/i, '').trim();
return texto || 'Sin motivo especificado';
}
// ==========================================
// 📄 F9: COLUMNA INFORMATIVA UNIFICADA DE .doc-row
// Único builder para admin y proveedor. opts:
//  extra               → HTML local antes del cierre (checkbox, spans de estado)
//  conBadgeNoAplica    → badge "NO APLICA" si no_aplica+verificado (admin)
//  badgeVerificadoPend → badge "✅ Verificado" si pendiente+verificado (proveedor)
// ==========================================
function infoDocRow(doc, opts = {}) {
const { extra = '', conBadgeNoAplica = false, badgeVerificadoPend = false } = opts;
const verificado = doc.verificado === 1;
const esNoAplica = doc.no_aplica === 1;
let badgeEstado;
if (conBadgeNoAplica && esNoAplica && verificado) {
badgeEstado = '<span class="badge badge-aprobado">NO APLICA</span>';
} else if (badgeVerificadoPend && doc.estado === 'pendiente' && verificado) {
badgeEstado = '<span class="badge badge-verificado-pendiente">✅ Verificado</span>';
} else {
badgeEstado = `<span class="badge badge-${doc.estado || 'pendiente'}">${doc.estado || 'pendiente'}</span>`;
}
const motivo = doc.comentario
? `<div style="color:#991b1b;font-size:0.95rem;font-weight:600;margin:0.35rem 0;line-height:1.4;">💬 Motivo: ${escapeHtml(limpiarMotivoRechazo(doc.comentario))}</div>`
: '';
const vencimiento = doc.fecha_vencimiento ? `
<br><small style="color:#6b7280;">📅 Vence: ${formatearFecha(doc.fecha_vencimiento)}</small>
<span class="badge badge-${obtenerEstadoVencimiento(doc.fecha_vencimiento).clase}" style="margin-left:0.5rem;font-size:0.7rem;">
${obtenerEstadoVencimiento(doc.fecha_vencimiento).icono} ${obtenerEstadoVencimiento(doc.fecha_vencimiento).texto}
</span>` : '';
return `<div style="flex:1;min-width:180px;">
<small>📎 ${escapeHtml(nombreFormato(doc.tipo))} ${badgeEstado}</small>
${motivo}
<br><small style="color:#9ca3af;">📅 ${formatearFecha(doc.subido_en)}</small>
${vencimiento}
${extra}
</div>`;
}