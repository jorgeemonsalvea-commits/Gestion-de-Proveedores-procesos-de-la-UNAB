// ==========================================
//  F8: UTILIDADES COMPARTIDAS (admin + proveedor)
// Fuente única de verdad para los helpers que estaban duplicados
// en /js/admin.js y /js/proveedor.js. Cargar ANTES que ambos.
// ==========================================

//  Fecha civil Bogotá → presentación es-CO (FIX TZ global: nunca toISOString)
function formatearFecha(f) {
if (!f) return '';
return new Date(String(f).replace(' ', 'T') + '-05:00').toLocaleString('es-CO', {
year: 'numeric', month: '2-digit', day: '2-digit',
hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'America/Bogota'
});
}

//  Escape para texto visible (innerHTML)
function escapeHtml(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
.replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

//  Escape para VALORES de atributos HTML (data-*, href)
function escapeAttr(text) {
if (!text) return '';
return String(text)
.replace(/&/g, '&amp;')
.replace(/"/g, '&quot;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;');
}

//  Estado de vencimiento (vigente / próximo / vencido / sin fecha)
function obtenerEstadoVencimiento(fechaVencimiento) {
if (!fechaVencimiento) return { clase: 'sin-fecha', texto: 'Sin fecha', icono: ico('help', 'ico-muted') };
const hoy = new Date();
const venc = new Date(String(fechaVencimiento).replace(' ', 'T') + '-05:00');
const diffDias = Math.ceil((venc - hoy) / (1000 * 60 * 60 * 24));
if (diffDias < 0) return { clase: 'vencido', texto: 'Vencido', icono: ico('x-circle', 'ico-peligro') };
else if (diffDias <= 30) return { clase: 'proximo-a-vencer', texto: 'Próximo a vencer', icono: ico('clock', 'ico-advertencia') };
else return { clase: 'vigente', texto: 'Vigente', icono: ico('check-circle', 'ico-exito') };
}

//  Nombre del FORMATO/categoría (lee el global `requeridos` de cada página)
function nombreFormato(tipo) {
const r = (requeridos || []).find(x => x.tipo === tipo);
return r ? r.nombre : (tipo || 'Documento');
}

//  Abre el visor leyendo datos desde data-attributes (anti-XSS en onclick)
function verDocumentoBtn(btn) {
verDocumento(btn.dataset.url, btn.dataset.nombre || 'Documento');
}

// ==========================================
//  G7: TIPO DE DOCUMENTO CO (espejo del server)
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
//  G11: TELÉFONO CO (máscara 3-3-4 + validación)
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
if (TEL_CO_RE.cel.test(d)) return { valido: true, mensaje: 'Celular válido' };
if (TEL_CO_RE.fijo.test(d)) return { valido: true, mensaje: 'Fijo válido' };
return { valido: false, mensaje: 'Formato CO: 3XX XXX XXXX (celular) o 60X XXX XXXX (fijo) · 10 dígitos' };
}
// ==========================================
//  F9: MOTIVO DE RECHAZO LIMPIO (sube desde proveedor.js a utils)
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
//  F9: COLUMNA INFORMATIVA UNIFICADA DE .doc-row
// Único builder para admin y proveedor. opts:
//  extra               → HTML local antes del cierre (checkbox, spans de estado)
//  conBadgeNoAplica    → badge "NO APLICA" si no_aplica+verificado (admin)
//  badgeVerificadoPend → badge " Verificado" si pendiente+verificado (proveedor)
// ==========================================
function infoDocRow(doc, opts = {}) {
const { extra = '', conBadgeNoAplica = false, badgeVerificadoPend = false } = opts;
const verificado = doc.verificado === 1;
const esNoAplica = doc.no_aplica === 1;
let badgeEstado;
if (conBadgeNoAplica && esNoAplica && verificado) {
badgeEstado = '<span class="badge badge-aprobado">NO APLICA</span>';
} else if (badgeVerificadoPend && doc.estado === 'pendiente' && verificado) {
badgeEstado = '<span class="badge badge-verificado-pendiente">' + ico('check', 'ico-exito') + ' Verificado</span>';
} else {
badgeEstado = `<span class="badge badge-${doc.estado || 'pendiente'}">${doc.estado || 'pendiente'}</span>`;
}
const motivo = doc.comentario
? `<div class="doc-motivo"> Motivo: ${escapeHtml(limpiarMotivoRechazo(doc.comentario))}</div>`
: '';
const vencimiento = doc.fecha_vencimiento ? `
<small class="txt-suave">${ico('calendar')} Vence: ${formatearFecha(doc.fecha_vencimiento)}</small>
<span class="badge badge-${obtenerEstadoVencimiento(doc.fecha_vencimiento).clase} badge-mini">
${obtenerEstadoVencimiento(doc.fecha_vencimiento).icono} ${obtenerEstadoVencimiento(doc.fecha_vencimiento).texto}
</span>` : '';
return `<div class="doc-row-info">
<small>${ico('file')} ${escapeHtml(nombreFormato(doc.tipo))} ${badgeEstado}</small>
${motivo}
<small class="txt-muted">${ico('calendar')} ${formatearFecha(doc.subido_en)}</small>
${vencimiento}
${extra}
</div>`;
}

// ==========================================
//  V2: ICONOS DE LÍNEA (fuente única, estilo empresarial)
// Glifos SVG stroke=currentColor, viewBox 24, trazo 2.
// Cero emojis: todo pictograma del proyecto apunta a este catálogo.
// Cargar ANTES que admin.js / proveedor.js (orden F1).
// ==========================================
const ICONOS = {
  check: '<svg class="ico" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',
  'check-circle': '<svg class="ico" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  x: '<svg class="ico" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  'x-circle': '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  eye: '<svg class="ico" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  'eye-off': '<svg class="ico" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
  download: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  upload: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
  trash: '<svg class="ico" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  zip: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>',
  plus: '<svg class="ico" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  save: '<svg class="ico" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
  users: '<svg class="ico" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  user: '<svg class="ico" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  'user-check': '<svg class="ico" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><polyline points="17 11 19 13 23 9"/></svg>',
  'user-x': '<svg class="ico" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="18" y1="8" x2="23" y2="13"/><line x1="23" y1="8" x2="18" y2="13"/></svg>',
  file: '<svg class="ico" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
  'file-text': '<svg class="ico" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  'file-check': '<svg class="ico" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="9 15 11 17 15 13"/></svg>',
  'file-x': '<svg class="ico" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  folder: '<svg class="ico" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  archive: '<svg class="ico" viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>',
  clock: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  calendar: '<svg class="ico" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>',
  bell: '<svg class="ico" viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
  'bell-off': '<svg class="ico" viewBox="0 0 24 24"><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><path d="M18 8a6 6 0 0 0-9.33-5"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
  settings: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  grid: '<svg class="ico" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
  chart: '<svg class="ico" viewBox="0 0 24 24"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
  activity: '<svg class="ico" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
  refresh: '<svg class="ico" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
  edit: '<svg class="ico" viewBox="0 0 24 24"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  mail: '<svg class="ico" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,6 12,13 2,6"/></svg>',
  send: '<svg class="ico" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>',
  inbox: '<svg class="ico" viewBox="0 0 24 24"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
  shield: '<svg class="ico" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  'shield-check': '<svg class="ico" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>',
  lock: '<svg class="ico" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  key: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  search: '<svg class="ico" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  filter: '<svg class="ico" viewBox="0 0 24 24"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
  list: '<svg class="ico" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
  external: '<svg class="ico" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
  database: '<svg class="ico" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
  logout: '<svg class="ico" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
  alert: '<svg class="ico" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  info: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  help: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  home: '<svg class="ico" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
  briefcase: '<svg class="ico" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>',
  award: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>',
  tool: '<svg class="ico" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
  printer: '<svg class="ico" viewBox="0 0 24 24"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
  ban: '<svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
phone: '<svg class="ico" viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>',
building: '<svg class="ico" viewBox="0 0 24 24"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="9" y1="6" x2="10" y2="6"/><line x1="14" y1="6" x2="15" y2="6"/><line x1="9" y1="10" x2="10" y2="10"/><line x1="14" y1="10" x2="15" y2="10"/><line x1="9" y1="14" x2="10" y2="14"/><line x1="14" y1="14" x2="15" y2="14"/><path d="M10 22v-4h4v4"/></svg>',
clipboard: '<svg class="ico" viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>',
clip: '<svg class="ico" viewBox="0 0 24 24"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>',
message: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
tag: '<svg class="ico" viewBox="0 0 24 24"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.83z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',
star: '<svg class="ico" viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
zap: '<svg class="ico" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
pin: '<svg class="ico" viewBox="0 0 24 24"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>',
  outbox: '<svg class="ico" viewBox="0 0 24 24"><polyline points="17 8 12 3 7 8"/><path d="M3 12h4l2 3h6l2-3h4"/><path d="M3 12v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/></svg>',
  maximize: '<svg class="ico" viewBox="0 0 24 24"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/></svg>',
  minimize: '<svg class="ico" viewBox="0 0 24 24"><path d="M8 3v3a2 2 0 0 1-2 2H3"/><path d="M21 8h-3a2 2 0 0 1-2-2V3"/><path d="M3 16h3a2 2 0 0 1 2 2v3"/><path d="M16 21v-3a2 2 0 0 1 2-2h3"/></svg>',
  "sun": "<svg class=\"ico\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"5\"/><line x1=\"12\" y1=\"1\" x2=\"12\" y2=\"3\"/><line x1=\"12\" y1=\"21\" x2=\"12\" y2=\"23\"/><line x1=\"4.22\" y1=\"4.22\" x2=\"5.64\" y2=\"5.64\"/><line x1=\"18.36\" y1=\"18.36\" x2=\"19.78\" y2=\"19.78\"/><line x1=\"1\" y1=\"12\" x2=\"3\" y2=\"12\"/><line x1=\"21\" y1=\"12\" x2=\"23\" y2=\"12\"/><line x1=\"4.22\" y1=\"19.78\" x2=\"5.64\" y2=\"18.36\"/><line x1=\"18.36\" y1=\"5.64\" x2=\"19.78\" y2=\"4.22\"/></svg>",
  "moon": "<svg class=\"ico\" viewBox=\"0 0 24 24\"><path d=\"M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z\"/></svg>",
  "volume": "<svg class=\"ico\" viewBox=\"0 0 24 24\"><polygon points=\"11 5 6 9 2 9 2 15 6 15 11 19 11 5\"/><path d=\"M15.54 8.46a5 5 0 0 1 0 7.07\"/></svg>",
  "volume-off": "<svg class=\"ico\" viewBox=\"0 0 24 24\"><polygon points=\"11 5 6 9 2 9 2 15 6 15 11 19 11 5\"/><line x1=\"23\" y1=\"9\" x2=\"17\" y2=\"15\"/><line x1=\"17\" y1=\"9\" x2=\"23\" y2=\"15\"/></svg>",
 };
// Helper V2: devuelve el glifo con clase extra (tamaño/color semántico).
// Ej.: ico('check', 'ico-exito ico-sm') · ico('alert', 'ico-peligro')
function ico(nombre, clase = '') {
  const svg = (typeof ICONOS !== 'undefined' && ICONOS[nombre]) || '';
  if (!svg) return '';
  if (!clase) return svg;
  return svg.replace('class="ico"', 'class="ico ' + clase + '"');
}

// ==========================================
//  D18: DELEGACIÓN GLOBAL DE ACCIONES (CSP sin unsafe-inline)
// Los handlers inline onclick=/onchange= se migran a data-accion/data-cambio
// con argumentos JSON en data-args. El listener resuelve la función global
// por nombre en el momento del evento (el orden de carga ya no importa).
// Convención de args: "__EL__" = el elemento, "__EL_VALUE__" = el.value del elemento.
// ==========================================
function attrJSON(v) {
  return escapeAttr(JSON.stringify(v));
}
function ejecutarAccionDelegada(el, nombre, argsRaw) {
  const fn = window[nombre];
  if (typeof fn !== 'function') return false;
  let args = [];
  if (argsRaw) {
    try { args = JSON.parse(argsRaw); } catch (e) { return false; }
  }
  args = args.map(a =>
    a === '__EL__' ? el : (a === '__EL_VALUE__' ? (el.value !== undefined ? el.value : el) : a)
  );
  // Fallback seguro: si el handler espera el elemento y el markup no trajo
  // data-args (migraciones antiguas), se le pasa el elemento clickeado.
  if (args.length === 0 && fn.length >= 1) args = [el];
  fn.apply(null, args);
  return true;
}
function instalarDelegacionGlobal() {
  document.addEventListener('click', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-accion]') : null;
    if (el) ejecutarAccionDelegada(el, el.dataset.accion, el.dataset.args);
  });
  document.addEventListener('change', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-cambio]') : null;
    if (el) ejecutarAccionDelegada(el, el.dataset.cambio, el.dataset.args);
  });
  // Fallback de imágenes (antes onerror inline): captura en fase capture
  document.addEventListener('error', (e) => {
    const el = e.target;
    if (el && el.tagName === 'IMG' && el.dataset.imgFallback && !el.dataset.imgFallbackOk) {
      el.dataset.imgFallbackOk = '1';
      el.src = el.dataset.imgFallback;
    }
  }, true);
}
if (typeof document !== 'undefined') instalarDelegacionGlobal();
