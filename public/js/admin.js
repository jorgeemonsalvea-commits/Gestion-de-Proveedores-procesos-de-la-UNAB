// ==========================================
//  FUNCIÓN HELPER: fetchAPI
// ==========================================
function fetchAPI(url, options = {}) {
marcarAccionPropia(); //  D4: ventana de acción propia (1.5s) para que el eco del socket no suene
return fetch(url, { ...options, credentials: 'include' });
}
// ==========================================
//  D1: MODO OSCURO — tema persistido + fallback al sistema operativo
// Sin valor guardado sigue prefers-color-scheme (y reacciona a sus cambios).
// ==========================================
const TEMA_KEY = 'unab_tema';
function aplicarTemaD1(tema) {
document.documentElement.setAttribute('data-tema', tema);
const btn = document.getElementById('btnTemaD1');
if (btn) {
btn.innerHTML = tema === 'oscuro' ? ico('sun') : ico('moon');
btn.setAttribute('aria-label', tema === 'oscuro' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro');
btn.title = tema === 'oscuro' ? 'Modo claro' : 'Modo oscuro';
}
}
function toggleTemaD1() {
const actual = document.documentElement.getAttribute('data-tema') === 'oscuro' ? 'oscuro' : 'claro';
const nuevo = actual === 'oscuro' ? 'claro' : 'oscuro';
localStorage.setItem(TEMA_KEY, nuevo);
aplicarTemaD1(nuevo);
}
(function initTemaD1() {
const guardado = localStorage.getItem(TEMA_KEY);
const sistema = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'oscuro' : 'claro';
aplicarTemaD1(guardado || sistema);
if (window.matchMedia) {
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
if (!localStorage.getItem(TEMA_KEY)) aplicarTemaD1(e.matches ? 'oscuro' : 'claro');
});
}
})();

// ==========================================
//  VARIABLES GLOBALES
// ==========================================
let requeridos = [];
let requeridosDefault = []; //  lista base (jurídica) para restaurar al cerrar modales
let moduloActual = 'registrados';
let proveedorActualId = null;
let proveedorActualNombre = '';
let listaProveedoresCache = [];
let listaFiltrada = [];
let filtroEstadoActual = 'todos';
let paginaActual = 1;
let limiteActual = 50; //  F5: página por defecto de 50 (agenda Sprint 6)
let totalPaginas = 1;
let totalRegistros = 0;
let adminFormSubmitted = false;
let noAplicaChanged = false;
let historicosCache = [];
let documentosActivosCache = []; //  C1: docs activos del proveedor abierto en el modal
let revisionEnfocada = { activa: false, modo: 'verificacion', cola: [], indice: 0 }; //  C1
//  R4: RBAC en cliente (D2/D6). El server sigue siendo la autoridad (403);
// aquí solo ocultamos/deshabilitamos lo que el perfil no puede usar.
let permisosActuales = [];
let esSuperadminUI = false;
function tienePermisoUI(clave) {
  if (esSuperadminUI) return true;
  return permisosActuales.includes(clave);
}
//  R4 (D6): revisor = solo docs.ver sin permisos de acción → solo lectura
function esSoloLectorUI() {
  if (esSuperadminUI) return false;
  return tienePermisoUI('docs.ver') &&
    !tienePermisoUI('docs.verificar') && !tienePermisoUI('docs.aprobar') &&
    !tienePermisoUI('docs.rechazar') && !tienePermisoUI('gestion.inscribir') &&
    !tienePermisoUI('proveedores.gestionar') && !tienePermisoUI('proveedores.crear');
}
//  F2: SUB-PESTAÑAS LAZY — flags por pestaña y por apertura de proveedor.
// Evita renderizar históricos/notas/recordatorios al abrir el modal:
// cada sub-pestaña se construye solo la primera vez que se visita.
let subTabLoadFlags = { provId: null, historicos: false, hist: false, notas: false, rec: false };
function resetSubTabFlags(provId) {
subTabLoadFlags = { provId: provId, historicos: false, hist: false, notas: false, rec: false };
}
function subTabYaCargada(t) {
return subTabLoadFlags.provId === proveedorActualId && subTabLoadFlags[t] === true;
}
function marcarSubTab(t) {
if (subTabLoadFlags.provId !== proveedorActualId) resetSubTabFlags(proveedorActualId);
subTabLoadFlags[t] = true;
}

// ==========================================
//  FUNCIONES AUXILIARES
// ==========================================
function fechaArchivo() {
const d = new Date(), p = n => String(n).padStart(2, '0');
return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
}
function descargarBlob(blob, n) {
const u = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = u; a.download = n;
document.body.appendChild(a); a.click(); document.body.removeChild(a);
URL.revokeObjectURL(u);
}
//  F8: formatearFecha → /js/utils.js
//  F8: escapeHtml → /js/utils.js
//  A1: escape para VALORES de atributos HTML (data-*, href). Escapa el delimitador " y &.
//  F8: escapeAttr → /js/utils.js

//  ANTI-AUTOFILL: evita el dropdown "Información guardada" del navegador
// en TODOS los buscadores (incluido el input dinámico de SweetAlert2 Ctrl+K).
// readonly hasta el foco: Chrome no despliega autofill sobre inputs readonly.
function esBuscadorBlindable(el) {
if (!el || !el.tagName || el.tagName !== 'INPUT') return false;
if (['password','checkbox','radio','file','date','datetime-local'].includes(el.type)) return false;
if (el.classList && el.classList.contains('swal2-input')) return true;
if (el.type === 'search') return true;
if (['buscador','historialBusqueda','historialRfc'].includes(el.id)) return true;
return false;
}
function blindarBuscador(el) {
if (!el || el.dataset.autofillBlind === '1') return;
el.dataset.autofillBlind = '1';
el.setAttribute('autocomplete', 'off');
el.setAttribute('autocorrect', 'off');
el.setAttribute('autocapitalize', 'off');
el.setAttribute('spellcheck', 'false');
el.setAttribute('name', 'q_' + Math.random().toString(36).substring(2, 10));
el.setAttribute('readonly', 'readonly');
if (document.activeElement === el) el.removeAttribute('readonly');
}
//  Libera readonly ANTES del foco (capture): teclados móviles sin retardo
document.addEventListener('pointerdown', (e) => {
if (e.target && e.target.dataset && e.target.dataset.autofillBlind === '1') e.target.removeAttribute('readonly');
}, true);
// Quita readonly al enfocar (permite escribir) y lo repone al salir
document.addEventListener('focusin', (e) => {
if (e.target && e.target.dataset && e.target.dataset.autofillBlind === '1') e.target.removeAttribute('readonly');
});
document.addEventListener('focusout', (e) => {
if (e.target && e.target.dataset && e.target.dataset.autofillBlind === '1') e.target.setAttribute('readonly', 'readonly');
});
// Blinda inputs de búsqueda existentes y los que se creen después (Swal, módulos)
const obsBlindaje = new MutationObserver((muts) => {
for (const m of muts) {
for (const n of m.addedNodes) {
if (!n || n.nodeType !== 1) continue;
if (esBuscadorBlindable(n)) blindarBuscador(n);
if (n.querySelectorAll) n.querySelectorAll('input').forEach((i) => { if (esBuscadorBlindable(i)) blindarBuscador(i); });
//  D2: todo modal creado en vuelo recibe rol de diálogo (WCAG 4.1.2)
if (n.classList && n.classList.contains('modal-overlay')) { n.setAttribute('role', 'dialog'); n.setAttribute('aria-modal', 'true'); }
if (n.querySelectorAll) n.querySelectorAll('.modal-overlay').forEach(ov => { ov.setAttribute('role', 'dialog'); ov.setAttribute('aria-modal', 'true'); });
}
}
});
if (document.body) obsBlindaje.observe(document.body, { childList: true, subtree: true });
document.addEventListener('DOMContentLoaded', () => {
document.querySelectorAll('input').forEach((i) => { if (esBuscadorBlindable(i)) blindarBuscador(i); });
});
// Iconografía UNAB v5 → fuente única en /js/utils.js (ICONOS + helper ico()).
// admin.js y proveedor.js consumen el catálogo global; aquí no se redecala nada.
// ==========================================
//  D4: SONIDO + TÍTULO DE PESTAÑA (notificaciones en tiempo real)
// ==========================================
let sonidoActivado = localStorage.getItem('unab_sonido') !== 'off';
let audioCtxD4 = null;
let pendienesD4 = 0;
const tituloBaseD4 = document.title;
let accionPropiaHasta = 0;
function marcarAccionPropia() { accionPropiaHasta = Date.now() + 1500; }
function esAccionPropia() { return Date.now() < accionPropiaHasta; }
// Beep sintetizado con WebAudio (sin archivos externos): 3 tonos por severidad.
function reproducirSonidoD4(tipo = 'info') {
if (!sonidoActivado) return;
try {
if (!audioCtxD4) audioCtxD4 = new (window.AudioContext || window.webkitAudioContext)();
if (audioCtxD4.state === 'suspended') audioCtxD4.resume();
const secuencia = { info: [660], success: [880, 1174], warning: [440, 440] }[tipo] || [660];
secuencia.forEach((freq, i) => {
const osc = audioCtxD4.createOscillator();
const gain = audioCtxD4.createGain();
osc.type = 'sine';
osc.frequency.value = freq;
const t0 = audioCtxD4.currentTime + (i * 0.12);
gain.gain.setValueAtTime(0.0001, t0);
gain.gain.exponentialRampToValueAtTime(0.18, t0 + 0.02);
gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.18);
osc.connect(gain); gain.connect(audioCtxD4.destination);
osc.start(t0); osc.stop(t0 + 0.2);
});
} catch (e) { /* sin audio disponible: silencio */ }
}
// Punto único de notificación: sonido siempre + contador de pestaña si está oculta.
function notificarD4(tipo = 'info') {
if (esAccionPropia()) return; //  no sonar por acciones propias
reproducirSonidoD4(tipo);
if (document.hidden) {
pendienesD4++;
document.title = `(${pendienesD4}) ${ico('bell')} ${tituloBaseD4}`;
}
}
function resetearTituloD4() {
//  D4-b: UN solo toast resumen al regresar (nunca uno por evento):
// "3 eventos mientras no estabas · último: X subió Y"
if (pendienesD4 > 0 && feedEventosD4.length) {
const ultimo = feedEventosD4[0];
mostrarNotificacion(`${ico('bell')} ${pendienesD4} evento(s) mientras no estabas · último: ${ultimo.titulo}`, 'info', 6000);
}
pendienesD4 = 0;
document.title = tituloBaseD4;
}
document.addEventListener('visibilitychange', () => {
if (!document.hidden) resetearTituloD4();
});
function toggleSonidoD4() {
sonidoActivado = !sonidoActivado;
localStorage.setItem('unab_sonido', sonidoActivado ? 'on' : 'off');
const btn = document.getElementById('btnSonidoD4');
if (btn) btn.innerHTML = sonidoActivado ? ico('volume') : ico('volume-off');
if (sonidoActivado) reproducirSonidoD4('success'); // beep de prueba + desbloquea AudioContext
}
// ==========================================
//  D4-b: FEED DE EVENTOS (campana con contador, bajo demanda, sin spam)
// ==========================================
const feedEventosD4 = [];
let feedNoLeidos = 0;
const FEED_MAX = 25;
function registrarEventoD4(ico, titulo, detalle) {
feedEventosD4.unshift({ ico, titulo, detalle, hora: new Date() });
if (feedEventosD4.length > FEED_MAX) feedEventosD4.pop();
feedNoLeidos++;
const badge = document.getElementById('campanaBadgeD4');
if (badge) { badge.style.display = 'flex'; badge.textContent = feedNoLeidos > 9 ? '9+' : String(feedNoLeidos); }
const btn = document.getElementById('btnCampanaD4');
if (btn) btn.title = `Último: ${titulo} — ${detalle}`;
const panel = document.getElementById('panelEventosD4');
if (panel && panel.classList.contains('open')) renderFeedD4();
}
function renderFeedD4() {
const panel = document.getElementById('panelEventosD4');
if (!panel) return;
if (!feedEventosD4.length) { panel.innerHTML = '<div class="feed-vacio">Sin eventos recientes.</div>'; return; }
panel.innerHTML = feedEventosD4.map(ev => `
<div class="feed-item">
<span class="feed-ico">${ev.ico}</span>
<div>
<div class="feed-titulo">${escapeHtml(ev.titulo)}</div>
<div class="feed-detalle">${escapeHtml(ev.detalle)}</div>
<div class="feed-detalle" style="font-size:.7rem;">${ico('clock')} ${ev.hora.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' })}</div>
</div>
</div>`).join('');
}
function togglePanelEventosD4() {
const panel = document.getElementById('panelEventosD4');
if (!panel) return;
const abrir = !panel.classList.contains('open');
panel.classList.toggle('open', abrir);
if (abrir) {
renderFeedD4();
feedNoLeidos = 0; // al leer el feed se limpia el contador
const badge = document.getElementById('campanaBadgeD4');
if (badge) badge.style.display = 'none';
}
}
// Cierra el panel al hacer clic fuera
document.addEventListener('click', (e) => {
const panel = document.getElementById('panelEventosD4');
if (!panel) return;
if (panel.classList.contains('open') && !e.target.closest('.feed-wrap')) togglePanelEventosD4();
});
// ==========================================
//  C5: RENDERIZADORES DE MINI-GRÁFICOS SVG
// ==========================================
/**
* Sparkline: polyline SVG de tendencia (14 puntos).
* @param {string} containerId - id del div contenedor
* @param {number[]} datos - array de valores numéricos
* @param {string} color - color del trazo
*/
function renderSparkline(containerId, datos, color) {
const el = document.getElementById(containerId);
if (!el || !datos || datos.length < 2) return;
const w = 90, h = 24, pad = 3;
const max = Math.max(...datos, 1);
const min = Math.min(...datos, 0);
const range = (max - min) || 1;
const points = datos.map((v, i) => {
const x = pad + (i / (datos.length - 1)) * (w - 2 * pad);
const y = h - pad - ((v - min) / range) * (h - 2 * pad);
return `${x.toFixed(1)},${y.toFixed(1)}`;
}).join(' ');
el.innerHTML = `<svg class="sparkline-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}
/**
* Mini bar-chart segmentado: aprobado (verde) sobre verificado (ámbar) sobre fondo gris.
* @param {number} aprobados - tipos aprobados
* @param {number} verificados - tipos verificados (incluye no-aplica)
* @param {number} total - tipos requeridos
* @returns {string} SVG inline
*/
function renderMiniBarSVG(aprobados, verificados, total) {
const w = 60, h = 6, r = 3;
const wVerif = total ? Math.round((verificados / total) * w) : 0;
const wAprob = total ? Math.round((aprobados / total) * w) : 0;
return `<svg class="minibar-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
<rect x="0" y="0" width="${w}" height="${h}" rx="${r}" fill="#e5e7eb"/>
${wVerif > 0 ? `<rect x="0" y="0" width="${wVerif}" height="${h}" rx="${r}" fill="#f59e0b"/>` : ''}
${wAprob > 0 ? `<rect x="0" y="0" width="${wAprob}" height="${h}" rx="${r}" fill="#059669"/>` : ''}
</svg>`;
}
/**
* Donut chart: anillos SVG por segmento con total al centro.
* @param {Array<{label:string, value:number, color:string}>} segments
* @param {number} size - diámetro del SVG
* @returns {string} SVG inline
*/
function renderDonutSVG(segments, size = 52) {
const total = segments.reduce((s, seg) => s + seg.value, 0);
if (!total) return '';
const cx = size / 2, cy = size / 2, r = (size / 2) - 5;
const circ = 2 * Math.PI * r;
let offset = 0;
let circles = '';
segments.forEach(seg => {
if (!seg.value) return;
const dash = (seg.value / total) * circ;
circles += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="5" stroke-dasharray="${dash.toFixed(2)} ${(circ - dash).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
offset += dash;
});
return `<svg class="donut-svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" aria-hidden="true">${circles}<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" font-size="${Math.round(size / 4)}" font-weight="700" fill="#1f1830">${total}</text></svg>`;
}
/**
* Genera la leyenda del donut.
*/
function renderDonutLegend(segments) {
return `<div class="donut-legend">` + segments.filter(s => s.value > 0).map(s =>
`<span class="donut-legend-item"><span class="donut-legend-dot" style="background:${s.color};"></span>${s.label}: <strong>${s.value}</strong></span>`
).join('') + `</div>`;
}

//  Escapa celdas CSV y neutraliza inyección de fórmulas (= + - @) para Excel.
function celdaCSV(c) {
let s = String(c ?? '');
if (/^[=+\-@]/.test(s)) s = "'" + s;
return `"${s.replace(/"/g, '""')}"`;
}

// ${ico('shield')} A1: abre el visor leyendo los datos desde data-attributes (evita inyectar el nombre en onclick)
//  F8: verDocumentoBtn → /js/utils.js
//  Muestra el nombre del FORMATO/categoría en vez del nombre físico del archivo
//  F8: nombreFormato → /js/utils.js

//  F8: obtenerEstadoVencimiento → /js/utils.js

//  Estado legible para exportaciones (diferencia las etapas reales)
function estadoLegible(p) {
const etapa = p.etapa || '';
if (etapa === 'registrado') return 'Registrado';
if (etapa === 'rechazado') return 'Rechazado';
if (etapa === 'verificacion') return 'Por verificar';
if (etapa === 'aprobacion') return 'Por aprobación';
if (etapa === 'inscripcion') return 'En inscripción';
// Fallback si la etapa viniera vacía
if (p.estado_general === 'aprobado') return 'Registrado';
if (p.estado_general === 'rechazado') return 'Rechazado';
return 'Pendiente';
}

//  F11: badgeDiasEtapa eliminado (sin llamadores; el panel de contexto y
// el listado muestran días en etapa directo desde p.dias_en_etapa).
// ==========================================
//  NOTIFICACIONES PUSH (TOAST) — SweetAlert2
// ==========================================
const SwalToast = (typeof Swal !== 'undefined') ? Swal.mixin({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    showCloseButton: true,
    timerProgressBar: true,
    didOpen: (self) => {
        self.addEventListener('mouseenter', Swal.stopTimer);
        self.addEventListener('mouseleave', Swal.resumeTimer);
    }
}) : null;
function mostrarNotificacion(mensaje, tipo = 'info', duracion = 4500) {
    if (SwalToast) {
        const iconos = { success: 'success', error: 'error', warning: 'warning', info: 'info' };
        SwalToast.fire({ icon: iconos[tipo] || 'info', title: mensaje, timer: duracion });
        return;
    }
    // Fallback si SweetAlert2 no cargó
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    const notif = document.createElement('div');
    notif.className = `notification notification-${tipo}`;
    notif.innerHTML = `<span class="notification-content">${mensaje}</span>`;
    container.appendChild(notif);
    setTimeout(() => notif.remove(), duracion);
}
//  F11: cerrarNotificacion eliminado (sin llamadores en admin; los toasts
// Swal se cierran solos por timer / mouseleave / botón de cierre).
// ==========================================
//  G10b: TOAST SWEETALERT2 — NUEVO PROVEEDOR REGISTRADO (con acción)
// ==========================================
function toastNuevoProveedor(data = {}) {
  const nombre = data.nombre || 'Sin nombre';
  const SwalToastAccion = Swal.mixin({
    toast: true,
    position: 'top-end',
    showConfirmButton: true,
    showCloseButton: true,
    timer: 9000,
    timerProgressBar: true,
    confirmButtonText: `${ico('search')} Revisar`,
    confirmButtonColor: '#8600dd',
    didOpen: (self) => {
      self.addEventListener('mouseenter', Swal.stopTimer);
      self.addEventListener('mouseleave', Swal.resumeTimer);
    }
  });
  SwalToastAccion.fire({
    icon: 'success',
    title: ' Nuevo proveedor registrado',
    html: `<strong style="color:#160a24;">${escapeHtml(nombre)}</strong><br><small style="color:#6b7280;">Entró a la etapa de Verificación</small>`
  }).then((r) => {
    if (r.isConfirmed && data.proveedorId) {
      // Salta directo al proveedor en el módulo Verificación
      moduloActual = 'verificacion';
      filtroEstadoActual = 'todos';
      paginaActual = 1;
      marcarModuloAdmin('verificacion');
      cargarModulo('verificacion');
      verProveedor(data.proveedorId, 'verificacion');
    }
  });
}
function mostrarAlerta(msg, tipo = 'error') {
const tiposMap = { 'error': 'error', 'success': 'success', 'info': 'info' };
mostrarNotificacion(msg, tiposMap[tipo] || 'info');
}
// ==========================================
//  SWEETALERT2 — reemplazo de confirm()/prompt() nativos
// ==========================================
function confirmarSwal({ titulo = '¿Estás seguro?', texto = '', icono = 'warning', textoConfirmar = 'Sí, continuar', textoCancelar = 'Cancelar', peligro = true } = {}) {
if (typeof Swal === 'undefined') return Promise.resolve(confirm(`${titulo}\n${texto}`));
return Swal.fire({
title: titulo,
text: texto,
icon: icono,
showCancelButton: true,
confirmButtonText: textoConfirmar,
cancelButtonText: textoCancelar,
confirmButtonColor: peligro ? '#dc2626' : '#8600dd',
cancelButtonColor: '#6b7280',
reverseButtons: true,
focusCancel: true
}).then(r => r.isConfirmed);
}
function promptSwal({ titulo = 'Ingresa un motivo', texto = '', placeholder = '', obligatorio = true } = {}) {
if (typeof Swal === 'undefined') return Promise.resolve(prompt(`${titulo}\n${texto}`));
return Swal.fire({
title: titulo,
text: texto,
icon: 'question',
input: 'textarea',
inputPlaceholder: placeholder,
showCancelButton: true,
confirmButtonText: 'Aceptar',
cancelButtonText: 'Cancelar',
confirmButtonColor: '#8600dd',
cancelButtonColor: '#6b7280',
reverseButtons: true,
inputValidator: obligatorio ? (v) => (!v || !v.trim()) ? 'Debes escribir un motivo.' : null : null
}).then(r => (r.isConfirmed ? (r.value || '') : null));
}

// ==========================================
//  EXPORTAR HABEAS DATA A CSV
// ==========================================
async function exportarHabeasData() {
try {
mostrarAlerta(' Generando archivo CSV...', 'info');
const response = await fetchAPI('/api/admin/habeas-data/export');
if (!response.ok) {
const errorData = await response.json().catch(() => ({}));
throw new Error(errorData.error || 'Error al exportar Habeas Data');
}
const blob = await response.blob();
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url; a.download = 'habeas_data_export.csv';
document.body.appendChild(a); a.click(); document.body.removeChild(a);
window.URL.revokeObjectURL(url);
mostrarAlerta(' Habeas Data exportado correctamente', 'success');
} catch (err) {
console.error(' Error exportando Habeas Data:', err);
mostrarAlerta(' Error al exportar: ' + err.message);
}
}

// ==========================================
//  SOCKET.IO - CONEXIÓN EN TIEMPO REAL
// ==========================================
let socket = null;
let timeoutRecargar = null;

function conectarSocket() {
//  Se conecta al mismo origen (funciona en local y en Railway/producción)
socket = io({
withCredentials: true,
reconnection: true,
reconnectionAttempts: 10,
reconnectionDelay: 1000
});

socket.on('connect', () => { console.log(' Conectado a Socket.IO · id=' + socket.id); });
socket.on('socket_info', (info) => { console.log(' Salas asignadas por el servidor:', info); });
socket.on('connect_error', (err) => {
  console.error(' Socket connect_error:', err.message);
  mostrarNotificacion(' Sin conexión en tiempo real: reintentando...', 'warning');
});
socket.on('disconnect', () => { console.log(' Desconectado del servidor Socket.IO'); });

//  F11: listeners duplicados de documento_actualizado/verificado fusionados
// en el par de más abajo (evento de feed + recarga de vista en un solo handler).
socket.on('documento_subido', (data) => {
console.log(' Documento subido:', data);
notificarD4('info');
registrarEventoD4(ico('upload'),  `${data.proveedorNombre || 'Un proveedor'} subió ${data.tipoNombre || data.tipo || 'un documento'}` ,  `Por: ${data.actor || 'el proveedor'}` );
recargarVistaActual();
});
socket.on('documento_verificado', (data) => {
console.log(' Documento verificado:', data);
registrarEventoD4(ico('check'),  `${data.proveedorNombre || 'Proveedor'} · ${data.tipoNombre || data.tipo || 'documento'}` ,  `Verificado por: ${data.actor || 'admin'}` );
recargarVistaActual();
});
socket.on('documento_actualizado', (data) => {
console.log(' Documento actualizado:', data);
registrarEventoD4(data.estado === 'rechazado' ? '' : '', `${data.proveedorNombre || 'Proveedor'} · ${data.tipoNombre || data.tipo || 'documento'} → ${data.estado || 'actualizado'}`, `Por: ${data.actor || 'admin'}`);
recargarVistaActual();
});
socket.on('evaluacion_actualizada', (data) => { console.log(' Evaluación actualizada:', data); notificarD4('info'); recargarVistaActual(); });
socket.on('proveedor_registrado', (data) => { console.log(' Proveedor registrado:', data); notificarD4('success'); recargarVistaActual(); });
socket.on('proveedores_actualizados', () => { console.log(' Proveedores actualizados'); recargarVistaActual(); });
//  G10b: toast en tiempo real cuando un proveedor se registra desde el portal público
socket.on('nuevo_proveedor_registrado', (data) => {
console.log(' [G10b] Evento recibido:', data);
notificarD4('success');
registrarEventoD4(ico('plus'),  `Nuevo proveedor: ${data.nombre || 'Sin nombre'}` , data.email || '');
  toastNuevoProveedor(data || {});
  actualizarEstadisticasGlobales();
  actualizarContadoresSidebar();
  recargarVistaActual();
});
socket.on('estadisticas_actualizadas', () => { console.log(' Estadísticas actualizadas'); actualizarEstadisticasGlobales(); if (moduloActual === 'metricas') cargarMetricas(); });
socket.on('vencimientos_procesados', (data) => {
console.log(' Vencimientos procesados:', data);
notificarD4('warning');
mostrarNotificacion(`${ico('archive')} Vencimientos: ${data.movidos} movidos, ${data.notificados} notificados`, 'info');
recargarVistaActual();
});
socket.on('nuevo_recordatorio', (data) => {
console.log(' Nuevo recordatorio:', data);
mostrarNotificacion(' Tienes un nuevo recordatorio', 'info');
if (proveedorActualId) cargarRecordatoriosEnviados();
});
socket.on('nueva_nota', (data) => {
console.log(' Nueva nota:', data);
mostrarNotificacion(' Tienes una nueva nota', 'info');
if (proveedorActualId) cargarNotas();
});
}

function recargarVistaActual() {
//  R4-perf: el eco de socket de una acción PROPIA ya tuvo su reload explícito;
// no duplicar el recargo (era lo que se sentía como "se demora recargando").
if (esAccionPropia()) return;
if (timeoutRecargar) clearTimeout(timeoutRecargar);
timeoutRecargar = setTimeout(() => {
if (moduloActual === 'configuracion') {
recargarConfiguracion();
} else if (moduloActual === 'historial') {
cargarHistorial(historialPaginaActual);
} else if (moduloActual === 'plant') {
cargarPlantillas();
} else if (moduloActual === 'metricas') {
cargarMetricas();
} else {
cargarProveedoresPorModulo(moduloActual, paginaActual);
}
if (proveedorActualId) recargarVistaProveedor();
timeoutRecargar = null;
}, 300);
}

// ==========================================
//  INICIALIZACIÓN
// ==========================================
async function init() {
try {
const me = await (await fetchAPI('/api/me')).json();
if (!me.usuario) return window.location.href = 'index.html';
if (me.usuario.rol !== 'admin') return window.location.href = 'proveedor.html';
//  R4: permisos una sola vez por sesión + gating inicial de sidebar/KPIs/subtabs
permisosActuales = Array.isArray(me.permisos) ? me.permisos : [];
esSuperadminUI = me.es_superadmin === true;
aplicarGatingRBAC();
document.getElementById('userEmail').textContent = me.usuario.email;
const av = document.getElementById('userAvatar');
if (av) av.textContent = ((me.usuario.email || 'UN').replace(/[^a-zA-Z]/g, '').slice(0, 2).toUpperCase()) || 'UN';

const reqResp = await fetchAPI('/api/proveedor/requerimientos');
if (reqResp.ok) {
requeridos = await reqResp.json();
requeridosDefault = requeridos.slice(); // 
console.log(' Requerimientos cargados:', requeridos.length);
} else {
console.error(' Error al cargar requerimientos');
requeridos = [];
}

marcarModuloAdmin('registrados');
actualizarPanelContexto(null);
await cargarModulo('registrados');
await actualizarEstadisticasGlobales();
actualizarContadorPlantillas();
sincronizarSidebarAdmin();
actualizarContadoresSidebar();
configurarTabs();
const cardInicial = document.querySelector('.kpi-tab[data-modulo="registrados"]:not([data-estado])');
if (cardInicial) cardInicial.classList.add('kpi-active');
//  D2: nombres accesibles en botones solo-ícono + rol de diálogo en modales estáticos
const bCamD2 = document.getElementById('btnCampanaD4');
if (bCamD2 && !bCamD2.getAttribute('aria-label')) bCamD2.setAttribute('aria-label', 'Eventos en tiempo real');
// V4-fix: la campana nació como pictograma estático en admin.html y el barrido
// (strip de nodos de texto) la dejó sin glifo. Se hidrata desde el catálogo
// único ICONOS antes del badge, idempotente (solo si no hay SVG previo).
if (bCamD2 && !bCamD2.querySelector('svg')) {
  bCamD2.insertAdjacentHTML('afterbegin', ico('bell'));
}
const bSonD2 = document.getElementById('btnSonidoD4');
if (bSonD2 && !bSonD2.getAttribute('aria-label')) bSonD2.setAttribute('aria-label', 'Activar o silenciar sonido de notificaciones');
document.querySelectorAll('.modal-overlay').forEach(ov => {
ov.setAttribute('role', 'dialog');
ov.setAttribute('aria-modal', 'true');
});

//  D4: reflejar el estado persistido del sonido en el botón de la topbar
const btnSonido = document.getElementById('btnSonidoD4');
if (btnSonido) btnSonido.innerHTML = sonidoActivado ? ico('volume') : ico('volume-off');
conectarSocket();

document.addEventListener('click', function(e) {
const dropdown = document.getElementById('exportDropdown');
if (dropdown && !e.target.closest('.dropdown')) dropdown.style.display = 'none';
const appsPanel = document.getElementById('appsMenuPanel');
if (appsPanel && appsPanel.classList.contains('open') && !e.target.closest('.apps-menu-wrap')) appsPanel.classList.remove('open');
});
} catch (err) {
console.error('Error en init:', err);
mostrarAlerta('Error al cargar: ' + err.message);
}
}

// ==========================================
//  CONTADOR DE PLANTILLAS (tarjeta visible)
// ==========================================
async function actualizarContadorPlantillas() {
    const el = document.getElementById('card-plantillas');
    if (!el) return;
    try {
        const r = await fetchAPI('/api/admin/plantillas');
        if (!r.ok) return;
        const list = await r.json();
        const total = (requeridos || []).filter(x => x.esPlantilla).length || list.length;
        el.textContent = `${list.length}/${total}`;
    } catch (e) { /* silencioso: la tarjeta muestra 0/0 */ }
}

// ==========================================
//  ACTUALIZAR ESTADÍSTICAS GLOBALES
// ==========================================
async function actualizarEstadisticasGlobales() {
try {
//  C5: stats y tendencia en paralelo (una sola espera)
const [statsRes, tendRes] = await Promise.all([
fetchAPI('/api/admin/stats'),
fetchAPI('/api/admin/stats/tendencia')
]);
if (!statsRes.ok) return;
const stats = await statsRes.json();
document.getElementById('card-registrados').textContent = stats.registrados || 0;
document.getElementById('card-verificacion').textContent = stats.verificacion || 0;
document.getElementById('card-aprobacion').textContent = stats.aprobacion || 0;
document.getElementById('card-inscripcion').textContent = stats.inscripcion || 0;
document.getElementById('card-rechazados').textContent = stats.rechazados || 0;
const setSide = (mod, v) => { const e = document.getElementById('side-' + mod); if (e) e.textContent = v || 0; };
setSide('registrados', stats.registrados); setSide('verificacion', stats.verificacion);
setSide('aprobacion', stats.aprobacion); setSide('inscripcion', stats.inscripcion);
setSide('rechazados', stats.rechazados); setSide('inactivos', stats.inactivos || 0);
//  C5: sparklines de tendencia por etapa (14 días)
if (tendRes.ok) {
const tend = await tendRes.json();
const colores = {
verificacion: '#d97706',
aprobacion: '#8600dd',
inscripcion: '#059669',
registrado: '#2563eb',
rechazado: '#dc2626'
};
if (tend.por_etapa_dia) {
Object.keys(tend.por_etapa_dia).forEach(etapa => {
const sparkId = 'spark-' + etapa;
renderSparkline(sparkId, tend.por_etapa_dia[etapa], colores[etapa] || '#6b7280');
});
}
}
} catch (err) {
console.error(' Error actualizando estadísticas:', err);
}
}
// ==========================================
//  MÉTRICAS (módulo del sidebar) — productividad 7 días desde auditoría
// ==========================================
async function cargarMetricas() {
const contenedor = document.getElementById('contenedor-modulos');
if (!contenedor) return;
contenedor.innerHTML = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
<h3 style="margin:0;">${ico('chart')} Métricas de productividad</h3>
<button class="btn btn-sm btn-secondary" onclick="cargarMetricas()">${ico('refresh')} Actualizar</button>
</div>
<div id="metricasContenido"><p style="color:#6b7280;text-align:center;padding:2rem;">${ico('clock')} Cargando métricas…</p></div>
</div>`;
try {
const r = await fetchAPI('/api/admin/stats/productividad');
if (!r.ok) throw new Error('Error al cargar métricas');
const data = await r.json();
const t = data.totales || {};
const dias = data.dias || [];
const chips = [
[`${ico('check-circle', 'ico-exito')} Verificados`, t.verificados, '#059669'],
[`${ico('check', 'ico-primario')} Aprobados`, t.aprobados, '#2563eb'],
[`${ico('x-circle', 'ico-peligro')} Rechazados`, t.rechazados, '#dc2626'],
[`${ico('edit', 'ico-primario')} Notas`, t.notas, '#8600dd'],
[`${ico('send', 'ico-acento')} Recordatorios`, t.recordatorios, '#d97706'],
[`${ico('file-text')} Gestiones`, t.gestiones, '#0891b2']
];
const totalAcciones = (t.verificados || 0) + (t.aprobados || 0) + (t.rechazados || 0) + (t.notas || 0) + (t.recordatorios || 0) + (t.gestiones || 0);
const mejorDia = dias.reduce((m, d) => {
const tot = d.verificados + d.aprobados + d.rechazados;
return tot > (m.tot || 0) ? { dia: d.dia, tot } : m;
}, { dia: '—', tot: 0 });
const max = Math.max(1, ...dias.map(d => d.verificados + d.aprobados + d.rechazados));
document.getElementById('metricasContenido').innerHTML = `
<div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
${chips.map(c => `<span class="badge-count" style="border:1px solid ${c[2]}33;color:${c[2]};background:${c[2]}11;padding:.4rem .7rem;font-size:.85rem;">${c[0]}: <strong>${c[1] || 0}</strong></span>`).join('')}
<span class="badge-count" style="border:1px solid #8600dd33;color:#8600dd;background:#8600dd11;padding:.4rem .7rem;font-size:.85rem;"> Total acciones: <strong>${totalAcciones}</strong></span>
<span class="badge-count" style="border:1px solid #05966933;color:#059669;background:#05966911;padding:.4rem .7rem;font-size:.85rem;"> Mejor día: <strong>${mejorDia.dia === '—' ? '—' : mejorDia.dia.slice(8, 10) + '/' + mejorDia.dia.slice(5, 7)} (${mejorDia.tot})</strong></span>
</div>
<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin-bottom:1rem;">
<h4 style="margin:0 0 .8rem 0;font-size:.9rem;">${ico('chart')} Documentos procesados por día (verificados / aprobados / rechazados)</h4>
${dias.map(d => {
const total = d.verificados + d.aprobados + d.rechazados;
const w = n => Math.round((n / max) * 100);
const partes = String(d.dia).split('-');
const esHoy = d.dia === data.hoyCivil;
return `
<div class="prod-fila" title="${d.dia} · Verificados: ${d.verificados} · Aprobados: ${d.aprobados} · Rechazados: ${d.rechazados} · Notas: ${d.notas} · Recordatorios: ${d.recordatorios} · Gestiones: ${d.gestiones}">
<span class="prod-dia${esHoy ? ' prod-hoy' : ''}">${partes[1]}/${partes[2]}</span>
<span class="prod-barra">
<span style="width:${w(d.verificados)}%;background:#059669;"></span>
<span style="width:${w(d.aprobados)}%;background:#2563eb;"></span>
<span style="width:${w(d.rechazados)}%;background:#dc2626;"></span>
</span>
<span class="prod-num">${total}</span>
</div>`;
}).join('')}
</div>
<div style="overflow-x:auto;">
<table style="width:100%;border-collapse:collapse;font-size:.88rem;">
<thead><tr style="background:#f3f4f6;border-bottom:2px solid #d1d5db;">
<th style="padding:.6rem;text-align:left;">Día</th>
<th style="padding:.6rem;text-align:center;">${ico('check')} Verificados</th>
<th style="padding:.6rem;text-align:center;"> Aprobados</th>
<th style="padding:.6rem;text-align:center;"> Rechazados</th>
<th style="padding:.6rem;text-align:center;"> Notas</th>
<th style="padding:.6rem;text-align:center;">${ico('send')} Recordatorios</th>
<th style="padding:.6rem;text-align:center;">${ico('file-text')} Gestiones</th>
</tr></thead>
<tbody>
${dias.slice().reverse().map(d => `
<tr style="border-bottom:1px solid #e5e7eb;">
<td style="padding:.55rem;font-weight:600;">${d.dia}${d.dia === data.hoyCivil ? ' <span class="badge-count" style="background:#ede9fe;color:#6d28d9;">hoy</span>' : ''}</td>
<td style="padding:.55rem;text-align:center;">${d.verificados}</td>
<td style="padding:.55rem;text-align:center;">${d.aprobados}</td>
<td style="padding:.55rem;text-align:center;">${d.rechazados}</td>
<td style="padding:.55rem;text-align:center;">${d.notas}</td>
<td style="padding:.55rem;text-align:center;">${d.recordatorios}</td>
<td style="padding:.55rem;text-align:center;">${d.gestiones}</td>
</tr>`).join('')}
</tbody></table>
</div>
<small style="color:#6b7280;display:block;margin-top:.8rem;">Fuente: auditoría interna (historial) de los últimos 7 días · solo acciones de administradores.</small>
`;
} catch (e) {
console.warn(' Métricas no disponibles:', e);
const cont = document.getElementById('metricasContenido');
if (cont) cont.innerHTML = `<div class="alert alert-error">${ico('x')} Error al cargar métricas: ${e.message}</div>`;
}
}

// ==========================================
//  CONFIGURAR PESTAÑAS
// ==========================================
function configurarTabs() {
document.querySelectorAll('.tab[data-tab]').forEach(tab => {
tab.addEventListener('click', function(e) {
const tabId = this.dataset.tab;
document.querySelectorAll('.tab[data-tab]').forEach(t => t.classList.remove('active'));
this.classList.add('active');
moduloActual = tabId;
paginaActual = 1;
cargarModulo(tabId);
});
});
}

// ==========================================
//  NAV SIDEBAR ADMIN (modelo convocatorias)
// ==========================================
const MODULOS_TITULO = {
registrados: 'Registrados', verificacion: 'Verificación', aprobacion: 'Aprobación',
inscripcion: 'Inscripción', rechazados: 'Rechazados', historial: 'Historial de actualizaciones',
configuracion: 'Configuración', plantillas: 'Plantillas', inactivos: 'Inactivos (+7 días sin documentos)',
metricas: 'Métricas de productividad',
auditoria: 'Auditoría',
equipo: 'Equipo'
};
function marcarModuloAdmin(mod) {
    document.querySelectorAll('.ad-item[data-mod]').forEach(b => b.classList.toggle('active', b.dataset.mod === mod));
    document.querySelectorAll('.kpi-tab').forEach(k => {
        const esRech = k.dataset.estado === 'rechazado';
        k.classList.toggle('kpi-active', k.dataset.modulo === mod || (mod === 'rechazados' && esRech));
    });
    const crumb = document.getElementById('crumbModulo');
    if (crumb) crumb.textContent = MODULOS_TITULO[mod] || mod;
}
//  Sincroniza el estado visual (sidebar + KPIs + breadcrumb) desde el estado actual
function sincronizarSidebarAdmin() {
    let efectivo = (moduloActual === 'registrados' && filtroEstadoActual === 'rechazado') ? 'rechazados' : moduloActual;
    if (efectivo === 'plant') efectivo = 'plantillas';
    marcarModuloAdmin(efectivo);
}
//  Refresca los badges contadores del sidebar desde /api/admin/stats
function actualizarContadoresSidebar() {
    fetchAPI('/api/admin/stats')
        .then(r => r.json())
        .then(s => {
            const set = (mod, v) => { const e = document.getElementById('side-' + mod); if (e) e.textContent = v || 0; };
          set('registrados', s.registrados);
          set('verificacion', s.verificacion);
          set('aprobacion', s.aprobacion);
          set('inscripcion', s.inscripcion);
          set('rechazados', s.rechazados);
          set('inactivos', s.inactivos || 0);
        })
        .catch(() => {});
}
function cambiarModuloSidebar(el) {
  const mod = el.dataset.mod;
  if (mod === 'rechazados') { filtroEstadoActual = 'rechazado'; moduloActual = 'registrados'; }
  else if (mod === 'plantillas') { filtroEstadoActual = 'todos'; moduloActual = 'plant'; }
  else { filtroEstadoActual = 'todos'; moduloActual = mod; }
  paginaActual = 1;
  marcarModuloAdmin(mod);
  cargarModulo(moduloActual);
  if (mod === 'registrados') {
    document.querySelectorAll('.filtro-estado').forEach(btn => btn.classList.toggle('active', btn.dataset.estado === 'todos'));
  }
}
function actualizarPanelContexto(p) {
  const side = document.getElementById('panelContexto');
  if (!side) return;
  if (!p) {
    side.innerHTML = `
      <div class="ad-panel">
        <h4>Contexto</h4>
        <p style="font-size:.82rem;color:var(--color-texto-suave);margin:0;">Selecciona un proveedor con el botón <strong>Revisar</strong> para ver aquí su resumen.</p>
      </div>`;
    return;
  }
  //  FIX: contar TIPOS completos (aprobados >= cantidadMin, u opcional con "No aplica"),
// mismo criterio que el listado y el portal del proveedor.
// Contar archivos crudos daba 16/14 porque experiencia aporta 3 certificados.
const mapDocs = {};
(p.documentos || []).forEach(d => { (mapDocs[d.tipo] = mapDocs[d.tipo] || []).push(d); });
//  C5-fix: mismo criterio que /api/admin/proveedores (p.aprobados):
// el tipo cuenta si sus docs aprobados >= cantidadMin. Los marcadores
// "No aplica" aprobados en Revisión Enfocada tienen estado='aprobado',
// por lo que entran aquí igual que en la fila del listado.
const aprobados = (requeridos || []).filter(r => {
const docs = mapDocs[r.tipo] || [];
const aps = docs.filter(d => d.estado === 'aprobado').length;
return aps >= r.cantidadMin;
}).length;
  side.innerHTML = `
    <div class="ad-panel">
      <h4>Proveedor seleccionado</h4>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M3 21h18"/><path d="M5 21V7l7-4 7 4v14"/></svg><div><span class="lbl">Razón social</span><span class="val">${escapeHtml(p.razon_social || p.nombre_empresa || '—')}</span></div></div>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="3" y1="10" x2="21" y2="10"/></svg><div><span class="lbl">${labelTipoDoc(p)}</span><span class="val">${escapeHtml(p.rfc || '—')}</span></div></div>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><div><span class="lbl">Tipo de persona</span><span class="val">${p.tipo_proveedor === 'natural' ? 'Persona Natural' : p.tipo_proveedor === 'juridica' ? 'Persona Jurídica' : 'Sin definir'}</span></div></div>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><div><span class="lbl">Estado general</span><span class="val">${escapeHtml(p.estado_general || 'pendiente')}</span></div></div>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/></svg><div><span class="lbl">Etapa</span><span class="val">${escapeHtml(p.etapa || 'verificacion')}</span></div></div>
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><div><span class="lbl">Tiempo en etapa</span><span class="val">${p.dias_en_etapa != null ? p.dias_en_etapa + ' días' : '—'}</span></div></div>      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><div><span class="lbl">Docs aprobados</span><span class="val">${aprobados}/${requeridos.length || 0}</span></div></div>
${(() => {
const docs = p.documentos || [];
//  C5-fix: segmentos MUTUAMENTE EXCLUYENTES. Antes un "No aplica"
// aprobado contaba en Aprobados Y en No aplica → centro inflado (20).
const segs = [
{ label: 'Aprobados', value: docs.filter(d => d.estado === 'aprobado' && d.no_aplica !== 1).length, color: '#059669' },
{ label: 'No aplica', value: docs.filter(d => d.no_aplica === 1).length, color: '#8b5cf6' },
{ label: 'Pendientes', value: docs.filter(d => d.estado === 'pendiente' && d.no_aplica !== 1).length, color: '#f59e0b' },
{ label: 'Rechazados', value: docs.filter(d => d.estado === 'rechazado' && d.no_aplica !== 1).length, color: '#dc2626' }
];
const hayDocs = segs.some(s => s.value > 0);
if (!hayDocs) return '';
return `<div class="donut-wrap">${renderDonutSVG(segs, 52)}${renderDonutLegend(segs)}</div>`;
})()}
      <div class="ad-row"><svg class="ico" viewBox="0 0 24 24"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg><div><span class="lbl">Correo</span><span class="val">${escapeHtml(p.email || '—')}</span></div></div>
    </div>`;
}

// ==========================================
//  TARJETAS-PESTAÑA (navegación principal)
// ==========================================
function cambiarModuloCard(el) {
  const modulo = el.dataset.modulo;
  const estado = el.dataset.estado || null;
  if (modulo === 'registrados') filtroEstadoActual = estado || 'todos';
  moduloActual = modulo;
  paginaActual = 1;
  marcarModuloAdmin(estado === 'rechazado' ? 'rechazados' : modulo);
  cargarModulo(modulo);
  if (modulo === 'registrados') {
    document.querySelectorAll('.filtro-estado').forEach(btn => btn.classList.toggle('active', btn.dataset.estado === (estado || 'todos')));
  }
}
// Accesibilidad: Enter/Espacio activan la tarjeta enfocada
document.addEventListener('keydown', function(e) {
if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('kpi-tab')) {
e.preventDefault();
cambiarModuloCard(e.target);
}
});

// ==========================================
//  MENÚ DE ACCESOS (estilo portal UNAB)
// ==========================================
function toggleAppsMenu() {
const p = document.getElementById('appsMenuPanel');
if (p) p.classList.toggle('open');
}
function cerrarAppsMenu() {
const p = document.getElementById('appsMenuPanel');
if (p) p.classList.remove('open');
}
function abrirModuloDesdeApps(mod) {
cerrarAppsMenu();
// Desmarca las pestañas: config/plant/historial ya no son tabs ni tarjetas
document.querySelectorAll('.tab[data-tab]').forEach(t => t.classList.remove('active'));
document.querySelectorAll('.kpi-tab').forEach(k => k.classList.remove('kpi-active'));
if (mod === 'plant') { moduloActual = 'plant'; renderizarPlantillas(); return; }
moduloActual = mod;
paginaActual = 1;
cargarModulo(mod);
}

// ==========================================
//  CARGAR MÓDULO
// ==========================================
function cargarModulo(modulo) {
    const contenedor = document.getElementById('contenedor-modulos');
    //  Normaliza el alias del sidebar: 'plantillas' → 'plant'
    if (modulo === 'plantillas') modulo = 'plant';
    sincronizarSidebarAdmin();
    if (modulo === 'configuracion') { cargarConfiguracion(); return; }
if (modulo === 'historial') { cargarHistorial(1); return; }
if (modulo === 'plant' || modulo === 'plantillas') { renderizarPlantillas(); return; }
if (modulo === 'metricas') { cargarMetricas(); return; }
if (modulo === 'auditoria') { cargarAuditoria(); return; }
//  R4: módulo Equipo solo superadmin (D4)
if (modulo === 'equipo') {
  if (!esSuperadminUI) { renderAccesoDenegado(); return; }
  cargarEquipo(); return;
}
//  R4: guard de módulo por permiso (el server también responde 403)
const MODULO_PERMISO = {
  verificacion: 'docs.verificar', aprobacion: 'docs.aprobar',
  inscripcion: 'gestion.inscribir', metricas: 'metricas.ver',
  auditoria: 'auditoria.ver', configuracion: 'config.gestionar'
};
if (MODULO_PERMISO[modulo] && !tienePermisoUI(MODULO_PERMISO[modulo])) {
  renderAccesoDenegado(); return;
}
const botonesAccion = modulo === 'registrados' ? `
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
<button class="btn btn-sm" onclick="mostrarModalCrearProveedor()" style="background:#059669;">${ICONOS.plus} Crear Proveedor</button>
<div class="dropdown" style="position:relative;display:inline-block;">
<button class="btn btn-sm btn-success" onclick="toggleExportDropdown()">${ico('file-text')} Exportar</button>
<div id="exportDropdown" style="display:none;position:absolute;background:white;min-width:160px;box-shadow:0px 8px 16px rgba(0,0,0,0.2);border-radius:6px;z-index:10;margin-top:4px;border:1px solid #e5e7eb;overflow:hidden;">
<button onclick="exportarCSV()" style="width:100%;padding:10px 16px;border:none;background:transparent;text-align:left;cursor:pointer;border-bottom:1px solid #f3f4f6;font-size:0.9rem;">${ico('file-text')} CSV</button>
<button onclick="exportarExcel()" style="width:100%;padding:10px 16px;border:none;background:transparent;text-align:left;cursor:pointer;font-size:0.9rem;">${ico('chart')} Excel (.xlsx)</button>
</div>
</div>
<button class="btn btn-sm btn-secondary" onclick="exportarHabeasData()">${ico('file-text')} Habeas Data</button>
</div>
` : (modulo === 'inactivos' ? `
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
<button class="btn btn-sm" style="background:#d97706;color:#fff;" onclick="recordarInactivos()">${ico('send')} Recordar a todos</button>
</div>
` : '');

let html = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
<h3 style="margin:0;">${getTituloModulo(modulo)}</h3>
${botonesAccion}
</div>
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1.5rem;">
<div style="display:grid;grid-template-columns:1fr auto;gap:1rem;margin-bottom:1rem;">
<div style="position:relative;">
<input type="text" id="buscador" placeholder="Buscar por nombre, NIT, email o representante..."
autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false"
style="width:100%;padding:0.7rem 1rem 0.7rem 2.5rem;border:1px solid #d1d5db;border-radius:6px;font-size:0.95rem;">
<span style="position:absolute;left:0.8rem;top:50%;transform:translateY(-50%);color:#9ca3af;">${ico('search')}</span>
</div>
<button class="btn btn-sm btn-secondary" onclick="limpiarFiltros()">${ico('trash')} Limpiar filtros</button>
</div>
${modulo === 'registrados' ? `
<div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;">
<button class="filtro-estado active" data-estado="todos" onclick="filtrarEstado('todos')">${ico('file-text')} Todos <span id="count-todos" class="badge-count">0</span></button>
<button class="filtro-estado" data-estado="aprobado" onclick="filtrarEstado('aprobado')">${ico('check')} Aprobados <span id="count-aprobado" class="badge-count badge-aprobado">0</span></button>
<button class="filtro-estado" data-estado="rechazado" onclick="filtrarEstado('rechazado')">${ico('x')} Rechazados <span id="count-rechazado" class="badge-count badge-rechazado">0</span></button>
</div>
` : ''}

<div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;">
<div style="flex:1;min-width:200px;">
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">Ordenar por:</label>
<select id="ordenar" onchange="aplicarFiltros()" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="reciente">Más recientes</option>
<option value="antiguo">Más antiguos</option>
<option value="nombre">Nombre (A-Z)</option>
</select>
</div>
<div style="flex:1;min-width:180px;">
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;"> Tipo de persona:</label>
<select id="filtroTipoPersona" onchange="paginaActual=1;cargarProveedoresPorModulo(moduloActual,1)" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="todos">Todos</option>
<option value="juridica">${ico('briefcase')} Persona Jurídica</option>
<option value="natural">${ico('user')} Persona Natural</option>
<option value="sindefinir">${ico('alert')} Sin definir</option>
</select>
</div>
<div style="flex:1;min-width:220px;">
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('file-text')} Documento faltante:</label>
<select id="filtroDocFaltante" onchange="paginaActual=1;cargarProveedoresPorModulo(moduloActual,1)" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="todos">— Cualquiera —</option>
${(requeridosDefault || []).map(r => `<option value="${r.tipo}">${escapeHtml(r.nombre)}</option>`).join('')}
</select>
</div>
</div>
<div id="paginacion" style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;flex-wrap:wrap;gap:0.5rem;">
<div style="display:flex;gap:0.5rem;align-items:center;">
<button id="btnAnterior" class="btn btn-sm btn-secondary" onclick="cambiarPagina(-1)"> Anterior</button>
<span id="infoPagina">Página 1 de 1</span>
<button id="btnSiguiente" class="btn btn-sm btn-secondary" onclick="cambiarPagina(1)">Siguiente </button>
</div>
<div style="display:flex;gap:0.5rem;align-items:center;">
<label style="font-size:0.85rem;">Mostrar:</label>
<select id="selectLimite" onchange="cambiarLimite()" style="padding:0.3rem;border-radius:4px;border:1px solid #d1d5db;">
<option value="10">10</option>
<option value="20">20</option>
<option value="50" selected>50</option>
<option value="100">100</option>
</select>
</div>
</div>
<div id="listaProveedores"></div>
</div>
</div>
`;
contenedor.innerHTML = html;
aplicarGatingBotones(); //  R4: oculta acciones sin permiso tras cada render
cargarProveedoresPorModulo(modulo, 1);
const buscador = document.getElementById('buscador');
if (buscador) {
//  F6: debounce 800ms — menos queries intermedias al teclear nombres largos.
// 300ms disparaba 3-4 peticiones por palabra; 800ms consulta al hacer pausa real.
let debounceBusqueda = null;
buscador.addEventListener('input', function() {
clearTimeout(debounceBusqueda);
debounceBusqueda = setTimeout(() => {
paginaActual = 1;
cargarProveedoresPorModulo(moduloActual, 1);
}, 800);
});
buscador.value = '';
buscador.addEventListener('blur', function() {
if (this.value === '') this.placeholder = 'Buscar por nombre, NIT, email o representante...';
});
}
}

function getTituloModulo(modulo) {
const titulos = {
'registrados': `${ico('users')} Proveedores registrados`,
'verificacion': `${ico('check-circle')} Verificación de documentos`,
'aprobacion': `${ico('check-circle')} Aprobación y evaluación inicial`,
'inscripcion': `${ico('edit')} Inscripción y actualización`,
'plant': `${ico('file-text')} Plantillas`,
'inactivos': `${ico('clock')} Proveedores inactivos (más de 7 días sin subir documentos)`,
'auditoria': `${ico('chart')} Auditoría del sistema`,
'equipo': `${ico('users')} Equipo y permisos`
};
return titulos[modulo] || 'Módulo';
}

// ==========================================
//  CARGAR PROVEEDORES POR MÓDULO
// ==========================================
async function cargarProveedoresPorModulo(modulo, pagina = 1) {
try {
const busqueda = document.getElementById('buscador')?.value?.trim() || '';
const estado = filtroEstadoActual || 'todos';
const limit = limiteActual;
const filtroVerificacion = document.getElementById('filtroVerificacion')?.value || '';

let url = `/api/admin/proveedores?page=${pagina}&limit=${limit}&estado=${estado}&modulo=${modulo}`;
if (busqueda) url += `&busqueda=${encodeURIComponent(busqueda)}`;
if (filtroVerificacion) url += `&filtroVerificacion=${encodeURIComponent(filtroVerificacion)}`;
//  A2: filtros avanzados (tipo de persona + documento faltante)
const tipoPersona = document.getElementById('filtroTipoPersona')?.value || 'todos';
const docFaltante = document.getElementById('filtroDocFaltante')?.value || 'todos';
if (tipoPersona && tipoPersona !== 'todos') url += `&tipoPersona=${encodeURIComponent(tipoPersona)}`;
if (docFaltante && docFaltante !== 'todos') url += `&docFaltante=${encodeURIComponent(docFaltante)}`;

const response = await fetchAPI(url);
const result = await response.json();
if (!response.ok) throw new Error(result.error || 'Error al cargar proveedores');

listaProveedoresCache = result.data || [];
totalRegistros = result.total || 0;
paginaActual = result.page || 1;
totalPaginas = result.totalPages || 1;
limiteActual = result.limit || 50;

aplicarFiltrosLocal();
actualizarPaginacion();
//  R4-perf: KPIs/sparklines fuera del camino crítico (no bloquean el listado)
actualizarEstadisticasGlobales();
if (modulo === 'registrados') actualizarContadoresEstado();
} catch (err) {
console.error(' Error cargando proveedores:', err);
mostrarAlerta('Error al cargar proveedores: ' + err.message);
}
}

function actualizarContadoresEstado() {
const proveedores = listaFiltrada.length > 0 ? listaFiltrada : listaProveedoresCache;
const total = proveedores.length;
const aprobados = proveedores.filter(p => p.estado_general === 'aprobado' && p.etapa === 'registrado').length;
const rechazados = proveedores.filter(p => p.estado_general === 'rechazado').length;
const cTodos = document.getElementById('count-todos');
const cAprob = document.getElementById('count-aprobado');
const cRech = document.getElementById('count-rechazado');
if (cTodos) cTodos.textContent = total;
if (cAprob) cAprob.textContent = aprobados;
if (cRech) cRech.textContent = rechazados;
}

// ==========================================
//  FUNCIONES DE PAGINACIÓN
// ==========================================
function actualizarPaginacion() {
const info = document.getElementById('infoPagina');
const btnAnt = document.getElementById('btnAnterior');
const btnSig = document.getElementById('btnSiguiente');
const selectLimite = document.getElementById('selectLimite');
if (totalRegistros === 0) {
if (info) info.textContent = 'No hay proveedores';
if (btnAnt) btnAnt.disabled = true;
if (btnSig) btnSig.disabled = true;
if (selectLimite) selectLimite.value = limiteActual;
return;
}
if (info) info.textContent = `Página ${paginaActual} de ${totalPaginas} (${totalRegistros} proveedores)`;
if (btnAnt) btnAnt.disabled = (paginaActual <= 1);
if (btnSig) btnSig.disabled = (paginaActual >= totalPaginas);
if (selectLimite) selectLimite.value = limiteActual;
}
function cambiarPagina(delta) {
const nuevaPagina = paginaActual + delta;
if (nuevaPagina < 1 || nuevaPagina > totalPaginas) return;
paginaActual = nuevaPagina;
cargarProveedoresPorModulo(moduloActual, paginaActual);
}
function cambiarLimite() {
const nuevoLimite = parseInt(document.getElementById('selectLimite').value);
if (nuevoLimite === limiteActual) return;
limiteActual = nuevoLimite;
paginaActual = 1;
cargarProveedoresPorModulo(moduloActual, 1);
}

// ==========================================
//  FILTROS LOCALES
// ==========================================
function aplicarFiltrosLocal() {
const ordenar = document.getElementById('ordenar')?.value || 'reciente';
let lista = listaProveedoresCache.slice();
lista.sort((a, b) => {
switch(ordenar) {
case 'reciente': return b.id - a.id;
case 'antiguo': return a.id - b.id;
case 'nombre': return (a.razon_social || a.nombre_empresa || '').localeCompare(b.razon_social || b.nombre_empresa || '');
default: return 0;
}
});
listaFiltrada = lista;
renderizarProveedores();
}
function aplicarFiltros() { aplicarFiltrosLocal(); }
function filtrarEstado(estado) {
filtroEstadoActual = estado;
document.querySelectorAll('.filtro-estado').forEach(btn => {
btn.classList.toggle('active', btn.dataset.estado === estado);
});
paginaActual = 1;
cargarProveedoresPorModulo(moduloActual, 1);
}
function limpiarFiltros() {
const buscador = document.getElementById('buscador');
if (buscador) { buscador.value = ''; buscador.blur(); }
document.getElementById('ordenar').value = 'reciente';
const filtroVerif = document.getElementById('filtroVerificacion');
if (filtroVerif) filtroVerif.value = '';
//  A2: restablecer filtros avanzados
const fTipo = document.getElementById('filtroTipoPersona'); if (fTipo) fTipo.value = 'todos';
const fDoc = document.getElementById('filtroDocFaltante'); if (fDoc) fDoc.value = 'todos';
filtroEstadoActual = 'todos';
document.querySelectorAll('.filtro-estado').forEach(btn => {
btn.classList.toggle('active', btn.dataset.estado === 'todos');
});
paginaActual = 1;
cargarProveedoresPorModulo(moduloActual, 1);
}

// ==========================================
//  RENDERIZAR PROVEEDORES
// ==========================================
function renderizarProveedores() {
const cont = document.getElementById('listaProveedores');
if (!cont) return;
if (listaFiltrada.length === 0) {
cont.innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">No se encontraron proveedores con los filtros aplicados.</p>';
return;
}
cont.innerHTML = listaFiltrada.map(p => {
//  Progreso del medidor según la pestaña: en Verificación cuenta tipos verificados (o no-aplica);
// en Aprobación/Inscripción cuenta tipos aprobados. Así el medidor "sube" con la acción de cada pestaña.
const progresoDocs = (moduloActual === 'verificacion') ? (p.verificados || 0) : (p.aprobados || 0);
const labelDocs = (moduloActual === 'verificacion') ? 'Verificados' : 'Aprobados';
let badgeModulo = '';
if (moduloActual === 'verificacion') {
  badgeModulo = `<span class="badge badge-pendiente">${ico('clock')} Pendiente verificar</span>`;
} else if (moduloActual === 'aprobacion') {
  badgeModulo = `<span class="badge badge-pendiente" style="background:#fbbf24;color:#78350f;">${ico('check-circle')} En aprobación</span>`;
} else if (moduloActual === 'inscripcion') {
  badgeModulo = `<span class="badge badge-aprobado">${ico('check')} En inscripción</span>`;
} else if (moduloActual === 'inactivos') {
  badgeModulo = `<span class="badge badge-pendiente" style="background:#fef3c7;color:#92400e;">${ico('clock')} Sin documentos</span>`;
} else {
  badgeModulo = `<span class="badge badge-${p.estado_general}">${p.estado_general}</span>`;
}

let gestionIcon = '';
if (p.numero_registro) {
gestionIcon = `<span style="font-size:0.8rem;color:#6b7280;margin-left:0.3rem;">${ico('file-text')} ${escapeHtml(p.numero_registro)}</span>`;
}
return `
<div class="proveedor-row" data-id="${p.id}" data-modulo="${moduloActual}" style="cursor:pointer;" title="Clic para abrir el proveedor">
<div style="flex:1;">
<h4 style="display:flex;flex-wrap:wrap;align-items:center;gap:0.5rem 1rem;margin:0;">
<span style="flex:1;min-width:150px;">${escapeHtml(p.razon_social || p.nombre_empresa || 'Sin nombre')} ${gestionIcon}</span>
<span style="display:flex;flex-wrap:wrap;gap:0.3rem;justify-content:flex-end;margin-left:auto;">
${p.recordatorios_pendientes > 0 ? `<span class="badge-recordatorio">${ico('send')} ${p.recordatorios_pendientes}</span>` : ''}
${p.notas_count > 0 ? `<span class="badge-recordatorio" style="background:#8b5cf6;"> ${p.notas_count}</span>` : ''}
${p.todos_subidos && p.estado_general === 'pendiente' && moduloActual === 'registrados'
? (p.todos_verificados
? `<span class="badge-verificado-pendiente">${ico('file-text')} Verificado - Pendiente aprobación</span>`
: `<span class="badge-pendiente-verificar">${ico('clock')} Pendiente por verificar</span>`)
: ''}
</span>
</h4>
<small>${ico('mail')} ${escapeHtml(p.email)} · ${labelTipoDoc(p)}: ${escapeHtml(p.rfc || '—')} ·  ${escapeHtml(p.telefono || '—')}${moduloActual === 'inactivos' && p.creado_en ? ` · ${ico('calendar')} Registro: ${formatearFecha(p.creado_en)}` : ''}</small>
</div>
${moduloActual !== 'registrados' ? `
<div style="text-align:center;">
<div style="font-size:0.85rem;color:#6b7280;">${labelDocs}</div>
<strong>${progresoDocs}/${p.total}</strong>
<div style="margin-top:0.3rem;">${renderMiniBarSVG(p.aprobados || 0, p.verificados || 0, p.total || 1)}</div>
</div>
` : ''}
${badgeModulo}
<button class="btn btn-sm" onclick="verProveedor(${p.id}, '${moduloActual}')">${ico('search')} Revisar</button>
</div>
`;
}).join('');
}
//  UX: clic en la fila (fuera de botones/enlaces/inputs) abre el modal del proveedor
document.addEventListener('click', function(e) {
const row = e.target.closest('.proveedor-row');
if (!row) return;
if (e.target.closest('button, a, input, select, textarea, label')) return;
const id = parseInt(row.dataset.id, 10);
if (!id) return;
verProveedor(id, row.dataset.modulo || moduloActual);
});
//  UX: Enter en el buscador abre el primer resultado filtrado
document.addEventListener('keydown', function(e) {
if (e.key !== 'Enter') return;
if (!e.target || e.target.id !== 'buscador') return;
e.preventDefault();
const primero = (listaFiltrada && listaFiltrada.length) ? listaFiltrada[0] : null;
if (primero) verProveedor(primero.id, moduloActual);
});
// ==========================================
//  VER PROVEEDOR (modal contextual)
// ==========================================
async function verProveedor(id, modulo) {
try {
const response = await fetchAPI(`/api/admin/proveedor/${id}`);
if (!response.ok) {
const errorData = await response.json().catch(() => ({}));
mostrarAlerta(`${ico('x')} Error al cargar proveedor: ${errorData.error || 'Proveedor no encontrado'}`);
return;
}
const data = await response.json();
if (!data.proveedor) {
mostrarAlerta(' No se encontró información del proveedor');
return;
}

proveedorActualId = id;
proveedorActualNombre = data.proveedor.razon_social || data.proveedor.nombre_empresa || `Proveedor ${id}`;
data.proveedor.documentos = data.documentos || [];
documentosActivosCache = data.documentos || []; //  C1
historicosCache = data.documentos_historicos || [];
//  F2: flags lazy en cero para este proveedor + badge de históricos
// pintado desde el conteo (sin construir el DOM de ciclos todavía).
resetSubTabFlags(id);
const badgeHistApertura = document.getElementById('countHistoricos');
if (badgeHistApertura) {
if (historicosCache.length) { badgeHistApertura.textContent = historicosCache.length; badgeHistApertura.style.display = 'inline-block'; }
else badgeHistApertura.style.display = 'none';
}
//  Cargar los requerimientos según el tipo de persona de ESTE proveedor
try {
const tipoProv = data.proveedor.tipo_proveedor;
if (tipoProv === 'natural' || tipoProv === 'juridica') {
const rr = await fetchAPI(`/api/proveedor/requerimientos?tipo=${tipoProv}`);
if (rr.ok) {
const listaTipo = await rr.json();
if (listaTipo.length) requeridos = listaTipo;
}
} else {
requeridos = requeridosDefault.slice(); //  tipo sin definir → lista estándar
}
} catch (e) { console.warn(' No se pudieron cargar requerimientos por tipo:', e); }
//  C5-fix: el panel se pinta DESPUÉS de refrescar requeridos.
// Antes calculaba con la lista del proveedor anterior (12/14 erróneo).
actualizarPanelContexto(data.proveedor);
document.getElementById('modalTitulo').textContent = proveedorActualNombre;
const contenedorDinamico = document.getElementById('modalContenidoDinamico');
const subTabsContainer = document.getElementById('subTabsContainer');
subTabsContainer.style.display = 'none';
contenedorDinamico.innerHTML = '';

const subTabs = ['docs','historicos','notas','hist','rec','eliminar'];

if (modulo === 'registrados') {
subTabsContainer.style.display = 'block';
document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
document.querySelector('[data-stab="docs"]').classList.add('active');
subTabs.forEach(t => document.getElementById(`subTab${t.charAt(0).toUpperCase() + t.slice(1)}`).classList.toggle('hidden', t !== 'docs'));
renderDocsCompleto(data.proveedor, data.documentos, historicosCache);
//  F2: históricos ya NO se renderiza al abrir (lazy al primer clic en )
} else if (modulo === 'verificacion') {
subTabsContainer.style.display = 'block';
document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
document.querySelector('[data-stab="docs"]').classList.add('active');
subTabs.forEach(t => document.getElementById(`subTab${t.charAt(0).toUpperCase() + t.slice(1)}`).classList.toggle('hidden', t !== 'docs'));
renderVerificacionCompleta(data.proveedor, data.documentos);
} else if (modulo === 'aprobacion') {
subTabsContainer.style.display = 'block';
document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
document.querySelector('[data-stab="docs"]').classList.add('active');
subTabs.forEach(t => document.getElementById(`subTab${t.charAt(0).toUpperCase() + t.slice(1)}`).classList.toggle('hidden', t !== 'docs'));
renderAprobacionCompleta(data.proveedor, data.documentos);
} else if (modulo === 'inscripcion') {
subTabsContainer.style.display = 'block';
document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
document.querySelector('[data-stab="docs"]').classList.add('active');
subTabs.forEach(t => document.getElementById(`subTab${t.charAt(0).toUpperCase() + t.slice(1)}`).classList.toggle('hidden', t !== 'docs'));
renderGestion(data.proveedor, data.documentos);
}

document.getElementById('modal').classList.add('active');
} catch (error) {
console.error(' Error en verProveedor:', error);
mostrarAlerta(`${ico('x')} Error de conexión: ${error.message}`);
}
}

// ==========================================
//  RENDERIZAR DOCUMENTOS HISTÓRICOS (solo lectura, agrupados por ciclo)
// ==========================================
function renderHistoricosProveedor(proveedor, historicos) {
const cont = document.getElementById('subTabHistoricos');
if (!cont) return;

const countBadge = document.getElementById('countHistoricos');

if (!historicos || historicos.length === 0) {
if (countBadge) countBadge.style.display = 'none';
cont.innerHTML = '<div class="historial-vacio"> Este proveedor no tiene documentos históricos archivados.</div>';
return;
}

if (countBadge) {
countBadge.textContent = historicos.length;
countBadge.style.display = 'inline-block';
}

const porCiclo = {};
historicos.forEach(d => {
const ciclo = d.ciclo || 'sin_ciclo';
if (!porCiclo[ciclo]) porCiclo[ciclo] = [];
porCiclo[ciclo].push(d);
});

const ciclosOrdenados = Object.keys(porCiclo).sort((a, b) => String(b).localeCompare(String(a)));

let html = `
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('archive')} Documentos históricos:</strong> Estos documentos fueron archivados automáticamente (por vencimiento o por solicitud de actualización) y son de <strong>solo lectura</strong>. Están agrupados por número de registro (ciclo).
</div>
`;

ciclosOrdenados.forEach(ciclo => {
const docs = porCiclo[ciclo];
html += `
<div class="card" style="margin-bottom:1rem;background:#f9fafb;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem;flex-wrap:wrap;gap:0.5rem;">
<h4 style="margin:0;">${ico('file-text')} Ciclo: ${escapeHtml(ciclo)}</h4>
<span class="badge-count">${docs.length} documento(s)</span>
</div>
<div class="doc-grid">
`;
docs.forEach(d => {
const nombreEscapado = escapeHtml(nombreFormato(d.tipo));
const ev = obtenerEstadoVencimiento(d.fecha_vencimiento);
html += `
<div class="doc-row" style="background:#fff;">
<div style="flex:1;min-width:200px;">
<small>${ico('file')} ${nombreEscapado} <span class="badge badge-rechazado">histórico</span> <span class="badge badge-${d.estado || 'rechazado'}">${d.estado || 'rechazado'}</span></small>
${d.comentario ? `<br><small style="color:#991b1b;"> ${escapeHtml(d.comentario)}</small>` : ''}
<br><small style="color:#9ca3af;">${ico('upload')} Subido: ${formatearFecha(d.subido_en)}</small>
${d.fecha_archivado ? `<br><small style="color:#6b7280;">${ico('archive')} Archivado: ${formatearFecha(d.fecha_archivado)}</small>` : ''}
${d.fecha_vencimiento ? `<br><small style="color:#6b7280;">${ico('calendar')} Vencimiento: ${formatearFecha(d.fecha_vencimiento)}</small> <span class="badge badge-${ev.clase}" style="font-size:0.7rem;">${ev.icono} ${ev.texto}</span>` : ''}
</div>
<div class="doc-row-actions">
${(d.no_aplica === 1 || d.archivo === 'no_aplica')
? '<small style="color:#92400e;font-weight:600;"> Sin archivo (No aplica)</small>'
: `
<button class="btn btn-sm btn-secondary" data-url="/uploads/${escapeAttr(d.archivo)}" data-nombre="${escapeAttr(nombreFormato(d.tipo))}" onclick="verDocumentoBtn(this)">${ICONOS.eye} Ver</button>
<a href="/uploads/${d.archivo}?download=true" class="btn btn-sm btn-success">${ICONOS.download}</a>
`}
</div>
</div>
`;
});
html += `</div></div>`;
});

cont.innerHTML = html;
}

// ==========================================
//  FUNCIONES DE RENDERIZADO
// ==========================================
function renderDocumentosConBotones(proveedor, documentos, mostrarSubida = true, modo = 'verificacion') {
if (!proveedor) {
console.error(' proveedor es undefined en renderDocumentosConBotones');
return '<div class="alert alert-error">Error: No se pudo cargar la información del proveedor.</div>';
}
const map = {};
documentos.forEach(d => { if (!map[d.tipo]) map[d.tipo] = []; map[d.tipo].push(d); });
let html = `
<div class="card" style="background:#f9fafb;padding:1rem;margin-bottom:1rem;">
<strong>Tipo de persona:</strong> ${proveedor.tipo_proveedor === 'natural' ? ' Persona Natural' : proveedor.tipo_proveedor === 'juridica' ? ' Persona Jurídica' : '<span style="color:#dc2626;"> Sin definir</span>'}<br>
<strong>Email:</strong> ${escapeHtml(proveedor.email || '')}<br>
<strong>NIT/RUT:</strong> ${escapeHtml(proveedor.rfc || '—')}<br>
<strong>Representante:</strong> ${escapeHtml(proveedor.representante || '—')}<br>
<strong>Teléfono:</strong> ${escapeHtml(proveedor.telefono || '—')}<br>
<strong>Dirección:</strong> ${escapeHtml(proveedor.direccion || '—')}
</div>
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
<h4 style="margin:0;">Documentos activos</h4>
<button class="btn btn-success" onclick="descargarZIP(${proveedor.id})" style="display:inline-flex;align-items:center;gap:0.5rem;">
${ICONOS.zip} Descargar activos en ZIP
</button>
</div>
<div class="doc-grid">
`;
requeridos.forEach((req, idx) => {
const sub = map[req.tipo] || [];
const ok = sub.filter(d => d.estado === 'aprobado').length >= req.cantidadMin;
const noAplica = sub.length > 0 && sub[0]?.no_aplica === 1;
//  Cupo múltiple (experiencia: jurídica hasta 3, natural 1 o 2)
const permiteMultiples = req.cantidadMin > 1 || (req.cantidadMax && req.cantidadMax > 1);
const puedeSubir = permiteMultiples
? true
: (sub.length === 0 || (sub[0]?.estado === 'rechazado' && !noAplica));
html += `<div class="doc-item doc-item-col">
<div class="doc-item-head">
<h4>${idx+1}. ${req.nombre}</h4>
<small style="color:#6b7280;">Requeridos: ${req.cantidadMin} · Subidos: ${sub.length}</small>
${ok ? '<span class="badge badge-aprobado" style="margin-left:0.5rem;">Completo</span>' : ''}
${noAplica ? '<span class="badge badge-aprobado" style="margin-left:0.5rem;background:#fef3c7;color:#92400e;">No aplica</span>' : ''}
</div>`;
// ---- DOCUMENTOS SUBIDOS ----
if (!sub.length) {
html += '<small style="color:#9ca3af;"> No ha subido</small>';
} else {
sub.forEach(d => {
const verificado = d.verificado === 1;
const aprobado = d.estado === 'aprobado';
const rechazado = d.estado === 'rechazado';
const esNoAplica = (d.no_aplica === 1 || d.archivo === 'no_aplica');
const checkDeshabilitado = rechazado || aprobado || esNoAplica || !tienePermisoUI('docs.verificar');
let extraInfo = '';
if (modo === 'verificacion') {
extraInfo += `
<br><label style="display:inline-flex;align-items:center;gap:0.3rem;font-size:0.85rem;cursor:${checkDeshabilitado ? 'not-allowed' : 'pointer'};margin-top:0.2rem;">
<input type="checkbox" class="checkbox-verificado" data-docid="${d.id}"
${verificado ? 'checked' : ''} ${checkDeshabilitado ? 'disabled' : ''}>
<span style="color:${verificado ? '#059669' : '#6b7280'};">${verificado ? ' Verificado' : 'Marcar como verificado'}</span>
</label>
${rechazado ? '<small style="color:#dc2626;display:block;"> Documento rechazado - Debe corregirse</small>' : ''}
`;
} else if (modo === 'aprobacion') {
if (esNoAplica) extraInfo += `<br><span style="color:#92400e;font-size:0.85rem;">${ico('file-text')} No aplica</span>`;
else if (aprobado) extraInfo += `<br><span style="color:#059669;font-size:0.85rem;">${ico('check')} Aprobado</span>`;
else if (verificado) extraInfo += `<br><span style="color:#059669;font-size:0.85rem;">${ico('check')} Verificado</span>`;
else extraInfo += `<br><span style="color:#dc2626;font-size:0.85rem;">${ico('x')} No verificado</span>`;
} else {
if (aprobado) extraInfo += `<br><span style="color:#059669;font-size:0.85rem;">${ico('check')} Aprobado</span>`;
else if (rechazado) extraInfo += `<br><span style="color:#dc2626;font-size:0.85rem;">${ico('x')} Rechazado</span>`;
else extraInfo += `<br><span style="color:#d97706;font-size:0.85rem;">${ico('clock')} Pendiente</span>`;
}
html += `<div class="doc-row">
${infoDocRow(d, { conBadgeNoAplica: true, extra: extraInfo })}
<div class="doc-row-actions" style="margin-left:auto;justify-content:flex-end;align-items:center;">
${esNoAplica
? '<small style="color:#92400e;font-weight:600;"> Sin archivo (No aplica)</small>'
: `
<button class="btn btn-sm btn-secondary" data-url="/uploads/${escapeAttr(d.archivo)}" data-nombre="${escapeAttr(nombreFormato(d.tipo))}" onclick="verDocumentoBtn(this)">${ICONOS.eye} Ver</button>
<a href="/uploads/${escapeAttr(d.archivo)}?download=true" class="btn btn-sm btn-success">${ICONOS.download}</a>
`}
${modo === 'verificacion' && !aprobado && tienePermisoUI('docs.rechazar') ? ` <button class= "btn btn-sm btn-danger " onclick= "rechazar(${d.id}) " >${ICONOS.x} Rechazar </button >` : ''}
${modo === 'verificacion' && !aprobado && tienePermisoUI('docs.verificar') ? ` <button class= "btn btn-sm btn-danger " onclick= "eliminarDocumentoAdmin(${d.id}, ${proveedor.id}) " > ${ICONOS.trash} Eliminar </button >` : ''}
${modo === 'aprobacion' && verificado && !aprobado ? `
${tienePermisoUI('docs.aprobar') ? ` <button class= "btn btn-sm " style= "background:#059669; " onclick= "cambiarEstado(${d.id},'aprobado') " >${ICONOS.check} Aprobar </button >` : ''}
${tienePermisoUI('docs.rechazar') ? ` <button class= "btn btn-sm btn-danger " onclick= "rechazar(${d.id}) " >${ICONOS.x} Rechazar </button >` : ''}
` : ''}
</div>
</div>`;
});
}
// ---- NO APLICA (solo verificación, documentos opcionales) ----
if (modo === 'verificacion' && req.opcional) {
const noAplicaChecked = sub.some(d => d.no_aplica === 1);
//  FIX: solo contar archivos REALES; un marcador 'no_aplica' rechazado no debe bloquear el re-marcado
const tieneArchivosReales = sub.some(d => d.archivo && d.archivo !== 'no_aplica');
const checkboxDisabled = tieneArchivosReales && !noAplicaChecked;
const docId = sub.length > 0 ? sub[0].id : '';
html += `<div class="box-noaplica">
 <label style="display:flex;align-items:flex-start;gap:0.5rem;flex-wrap:wrap;cursor:${checkboxDisabled ? 'not-allowed' : 'pointer'};">
 <input type="checkbox" class="checkbox-no-aplica-admin" style="flex-shrink:0;width:auto;margin-top:0.15rem;"
data-docid="${docId}" data-tipo="${req.tipo}" data-proveedorid="${proveedor.id}"
${noAplicaChecked ? 'checked' : ''} ${checkboxDisabled ? 'disabled' : ''}>
<span style="font-weight:500;color:#92400e;opacity:${checkboxDisabled ? 0.6 : 1};">${ico('file-text')} Este documento no aplica para este proveedor</span>
</label>
<small style="color:#78350f;display:block;margin-top:0.3rem;">
${noAplicaChecked
? ' Documento marcado como "No aplica". La carga de archivos está desactivada.'
: (checkboxDisabled
? ' Ya hay archivos subidos. No puedes marcar "No aplica" si ya hay documentos cargados.'
: 'Si marcas esta opción, el documento se aprobará automáticamente como "No aplica"')
}
</small>
</div>`;
}
// ---- EXPERIENCIA + SUBIDA ADMIN (solo verificación) ----
if (modo === 'verificacion') {
if (req.tipo === 'experiencia') {
const maxExp = req.cantidadMax || 3;
const subidosValidos = sub.filter(d => d.estado !== 'rechazado' && d.no_aplica === 0).length;
const subidosRechazados = sub.filter(d => d.estado === 'rechazado' && d.no_aplica === 0).length;
const maxAlcanzado = subidosValidos >= maxExp;
html += `<div class="box-exito">
 <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
 <span style="font-size:0.85rem;color:#065f46;">
${ico('file-text')} Certificados subidos: <strong>${subidosValidos}/${maxExp}</strong>
${subidosRechazados > 0 ? ` (${subidosRechazados} rechazados)` : ''}
${maxAlcanzado ? '  Límite alcanzado' : ''}
</span>
${(!maxAlcanzado || subidosRechazados > 0) && puedeSubir ? `
<form class="form-upload dropzone form-upload-admin" data-tipo="${req.tipo}" data-proveedorid="${proveedor.id}">
<div class="dz-icon">${ICONOS.upload}</div>
<div class="dz-text"><strong>Subir como administrador</strong><small>Adjunta el PDF en nombre del proveedor · PDF · máx. 15 MB</small></div>
<input type="file" name="archivo" required accept=".pdf">
<button type="submit" class="btn btn-sm" style="background:#0284c7;">${subidosRechazados > 0 ? ' Reemplazar rechazado' : ICONOS.upload + ' Subir PDF'}</button>
</form>
` : `
<span style="color:#6b7280;font-size:0.9rem;">
${maxAlcanzado && subidosRechazados === 0 ? `${ico('check')} Máximo de ${maxExp} certificados alcanzado` : 'No disponible'}
</span>
`}
</div>
</div>`;
}
if (req.tipo !== 'experiencia' && puedeSubir && !noAplica && mostrarSubida) {
const label = sub.length === 0 ? ICONOS.upload + ' Admin subir PDF' : (req.cantidadMin > 1 ? ICONOS.plus + ` Agregar PDF (${sub.length}/${req.cantidadMin})` : ICONOS.upload + ' Reemplazar PDF');
html += `<form class="form-upload dropzone form-upload-admin" data-tipo="${req.tipo}" data-proveedorid="${proveedor.id}">
<div class="dz-icon">${ICONOS.upload}</div>
<div class="dz-text"><strong>Subir como administrador</strong><small>Adjunta el PDF en nombre del proveedor · PDF · máx. 15 MB</small></div>
<input type="file" name="archivo" required accept=".pdf">
<button type="submit" class="btn btn-sm" style="background:#0284c7;">${label}</button>
</form>`;
} else if (req.tipo !== 'experiencia' && noAplica) {
html += `<div class="box-noaplica">
 <small style="color:#92400e;">${ico('file-text')} Documento marcado como "No aplica". La carga de archivos está desactivada.</small>
 </div>`;
}
}
html += '</div>';
});
html += '</div>';
return html;
}

//  Bloque para definir tipo de persona cuando no está definido
function renderDefinirTipoPersona(proveedor) {
return `
<div class="alert alert-warning" style="margin-bottom:1rem;background:#fef3c7;border-left:5px solid #f59e0b;padding:1.2rem;">
<strong style="color:#92400e;">${ico('alert')} Tipo de persona sin definir</strong>
<p style="color:#78350f;margin:0.4rem 0 0 0;">
Este proveedor aún no ha elegido si es <strong>Persona Natural</strong> o <strong>Persona Jurídica</strong>.
La lista de documentos requeridos depende de esta definición. Puedes definirla tú como administrador (el proveedor también puede hacerlo en su pestaña "Mis datos").
</p>
</div>
<div class="card" style="background:#f0f9ff;padding:1.5rem;margin-bottom:1rem;border:2px solid #bae6fd;">
<h4 style="margin-bottom:0.8rem;">${ico('file-text')} Definir tipo de persona</h4>
<div style="display:flex;gap:1.5rem;margin-bottom:1rem;flex-wrap:wrap;">
<label style="display:flex;align-items:center;gap:0.4rem;cursor:pointer;">
<input type="radio" name="tipoPersonaDefinicion" value="juridica"> ${ico('briefcase')} Persona Jurídica
</label>
<label style="display:flex;align-items:center;gap:0.4rem;cursor:pointer;">
<input type="radio" name="tipoPersonaDefinicion" value="natural"> ${ico('user')} Persona Natural
</label>
</div>
<button class="btn" onclick="guardarTipoPersona(${proveedor.id})" style="background:#2563eb;">${ico('save')} Guardar tipo y cargar documentos</button>
</div>
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('info')} Mientras tanto:</strong> La lista de documentos que se muestra abajo corresponde a la lista estándar (Persona Jurídica). Una vez definido el tipo, se recargará con los documentos correctos.
</div>
`;
}
async function guardarTipoPersona(proveedorId) {
    const seleccion = document.querySelector('input[name="tipoPersonaDefinicion"]:checked');
    if (!seleccion) {
        mostrarAlerta(' Debes seleccionar un tipo de persona', 'warning');
        return;
    }
    const tipo = seleccion.value;
    try {
        mostrarAlerta(' Guardando tipo de persona...', 'info');
        const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/tipo-persona`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tipo_proveedor: tipo })
        });
        const data = await res.json();
        if (res.ok) {
            mostrarAlerta(' Tipo de persona definido. Recargando documentos...', 'success');
            await recargarVistaProveedor();
            await cargarProveedoresPorModulo(moduloActual, paginaActual);
        } else if (data.requiere_confirmacion) {
            if (await confirmarSwal({ titulo: ' Forzar cambio de tipo', texto: data.error, textoConfirmar: 'Sí, forzar' })) {
                const res2 = await fetchAPI(`/api/admin/proveedor/${proveedorId}/tipo-persona`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tipo_proveedor: tipo, forzar: true })
                });
                if (res2.ok) {
                    mostrarAlerta(' Tipo de persona forzado. Recargando...', 'success');
                    await recargarVistaProveedor();
                    await cargarProveedoresPorModulo(moduloActual, paginaActual);
                } else {
                    mostrarAlerta(' Error al forzar el cambio');
                }
            }
        } else {
            mostrarAlerta(' ' + (data.error || 'Error al guardar el tipo'));
        }
    } catch (err) {
        console.error('Error guardando tipo:', err);
        mostrarAlerta(' Error de conexión');
    }
}

function renderVerificacionCompleta(proveedor, documentos) {
let html = '';
//  Si no hay tipo de persona definido, mostrar bloque de definición primero
if (!proveedor.tipo_proveedor) {
html += renderDefinirTipoPersona(proveedor);
}
html += `
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('check')} Módulo de Verificación:</strong> Marca el checkbox para verificar cada documento.
Puedes rechazar un documento si está mal. También puedes marcar "No aplica" para documentos opcionales.
Cuando todos estén verificados o marcados como "No aplica", el proveedor pasará automáticamente a Aprobación.
</div>
`;
html += `
<div style="display:flex;justify-content:flex-end;margin:-0.5rem 0 0.8rem;">
<button class="btn btn-sm" style="background:#8600dd;" onclick="iniciarRevisionEnfocada('verificacion')">${ico('search')} Revisión enfocada (uno por uno)</button>
</div>`;
html += renderDocumentosConBotones(proveedor, documentos, true, 'verificacion');
document.getElementById('modalContenidoDocs').innerHTML = html;
}

function renderAprobacionCompleta(proveedor, documentos) {
//  Un documento cuenta como "aprobado" si está aprobado o si es "no aplica"
const todosAprobados = documentos.length > 0 && documentos.every(d => d.estado === 'aprobado' || d.no_aplica === 1);

let html = `
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('file-text')} Módulo de Aprobación:</strong> Revisa los documentos (ya deben estar verificados).
Aprueba o rechaza cada documento. Cuando todos estén aprobados (o marcados como "No aplica"), podrás aprobar la Evaluación Inicial.
</div>
`;
html += `
<div style="display:flex;justify-content:flex-end;margin:-0.5rem 0 0.8rem;">
<button class="btn btn-sm" style="background:#8600dd;" onclick="iniciarRevisionEnfocada('aprobacion')">${ico('search')} Revisión enfocada (aprobar uno por uno)</button>
</div>`;
html += renderDocumentosConBotones(proveedor, documentos, false, 'aprobacion');

html += `
<div style="margin-top:2rem;border-top:2px solid #e5e7eb;padding-top:1.5rem;">
<h4>${ico('file-text')} Evaluación Inicial</h4>
${proveedor.evaluacion_inicial ? `
<div style="background:#f9fafb;padding:1rem;border-radius:6px;margin-bottom:1rem;">
<p><strong>${ico('file')} Archivo:</strong> Evaluación Inicial.pdf</p>
<p><strong>${ico('file-text')} Estado:</strong> ${proveedor.evaluacion_estado === 'aprobado' ? ' Aprobado' : proveedor.evaluacion_estado === 'rechazado' ? ' Rechazado' : ' Pendiente'}</p>
<p><strong>${ico('calendar')} Fecha:</strong> ${proveedor.evaluacion_fecha ? formatearFecha(proveedor.evaluacion_fecha) : ''}</p>
<div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="verDocumento('/uploads/${proveedor.evaluacion_inicial}','Evaluación Inicial')">${ICONOS.eye} Ver</button>
<a href="/api/admin/proveedor/${proveedor.id}/evaluacion/download" class="btn btn-sm btn-success">${ico('download')} Descargar</a>
${(proveedor.evaluacion_estado === 'pendiente' || proveedor.evaluacion_estado === 'rechazado') ? `
${todosAprobados && tienePermisoUI('evaluacion.gestionar') ? `
 <button class= "btn btn-sm " style= "background:#059669; " onclick= "cambiarEstadoEvaluacion(${proveedor.id},'aprobado') " >${ico('check')} Aprobar evaluación </button >
${proveedor.evaluacion_estado === 'pendiente' ? `<button class="btn btn-sm btn-danger" onclick="rechazarEvaluacion(${proveedor.id})">${ico('x')} Rechazar evaluación</button>` : ''}
<button class="btn btn-sm btn-danger" onclick="eliminarEvaluacion(${proveedor.id})" style="background:#dc2626;">${ICONOS.trash} Eliminar</button>
` : `
<button class="btn btn-sm" style="background:#9ca3af;cursor:not-allowed;" disabled>${ico('alert')} Primero aprueba todos los documentos</button>
`}
` : ''}
</div>
</div>
` : `
<div class="box-noaplica" style="margin-bottom:1rem;">
 <p>${ico('alert')} Aún no se ha subido la evaluación inicial. Sube el PDF a continuación.</p>
 </div>
${tienePermisoUI('evaluacion.gestionar') ? `
 <form id= "formEvaluacion " enctype= "multipart/form-data " class= "form-upload dropzone " >
<div class="dz-icon">${ICONOS.upload}</div>
<div class="dz-text"><strong>Evaluación Inicial</strong><small>Adjunta el PDF de evaluación firmado · PDF · máx. 15 MB</small></div>
<input type="file" name="archivo" required accept=".pdf">
 <button type= "submit " class= "btn " style= "background:#8600dd; " >${ICONOS.upload} Subir evaluación </button >
 </form >` : ''}
`}
</div>
`;
document.getElementById('modalContenidoDocs').innerHTML = html;
}

// ==========================================
//  RENDERIZAR MÓDULO INSCRIPCIÓN Y ACTUALIZACIÓN
// ==========================================
function renderGestion(proveedor, documentos) {
const map = {};
documentos.forEach(d => { if (!map[d.tipo]) map[d.tipo] = []; map[d.tipo].push(d); });

let html = `
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong> Inscripción y Actualización:</strong> Asigna número de registro, observaciones y tipo de gestión.
Al guardar, el proveedor pasará a "Registrado" si la evaluación está aprobada.
</div>
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1rem;">
<p><strong>${ico('file-text')} Estado del proveedor:</strong> ${proveedor.estado_general}</p>
<p><strong> Etapa actual:</strong> ${proveedor.etapa || 'inscripcion'}</p>
<p><strong>${ico('file-text')} Evaluación:</strong> ${proveedor.evaluacion_estado || 'pendiente'}</p>
${proveedor.numero_registro ? `<p><strong>${ico('file-text')} Fecha Movimiento actual:</strong> ${escapeHtml(proveedor.numero_registro)}</p>` : ''}
</div>
<div class="doc-grid">
`;

requeridos.forEach(req => {
const sub = map[req.tipo] || [];
const todosAprobados = sub.length > 0 && sub.every(d => d.estado === 'aprobado' || d.no_aplica === 1);
const tieneArchivos = sub.length > 0;

html += `<div class="doc-item doc-item-col">
<div class="doc-item-head">
<h4>${req.nombre}</h4>
<small style="color:#6b7280;">Requeridos: ${req.cantidadMin} · Subidos: ${sub.length}</small>
${todosAprobados && tieneArchivos ? '<span class="badge badge-aprobado" style="margin-left:0.5rem;"> Aprobado</span>' : ''}
</div>`;

if (!sub.length) {
html += '<small style="color:#9ca3af;"> No ha subido documentos</small>';
} else {
sub.forEach(d => {
const aprobado = d.estado === 'aprobado';
const extraGest = `<br>${aprobado ? '<span style="color:#059669;font-size:0.85rem;"> Aprobado</span>' : '<span style="color:#d97706;font-size:0.85rem;"> Pendiente</span>'}`;
html += `<div class="doc-row">
${infoDocRow(d, { extra: extraGest })}
<div class="doc-row-actions">
${(d.no_aplica === 1 || d.archivo === 'no_aplica')
? '<small style="color:#92400e;font-weight:600;"> Sin archivo (No aplica)</small>'
: `
<button class="btn btn-sm btn-secondary" data-url="/uploads/${escapeAttr(d.archivo)}" data-nombre="${escapeAttr(nombreFormato(d.tipo))}" onclick="verDocumentoBtn(this)">${ICONOS.eye} Ver</button>
<a href="/uploads/${d.archivo}?download=true" class="btn btn-sm btn-success">${ICONOS.download}</a>
`}
</div>
</div>`;
});
}
html += '</div>';
});
html += '</div>';

html += `
<div style="margin-top:2rem;border-top:2px solid #e5e7eb;padding-top:1.5rem;">
<h4>${ico('file-text')} Evaluación Inicial</h4>
${proveedor.evaluacion_inicial ? `
<div style="background:#f9fafb;padding:1rem;border-radius:6px;margin-bottom:1rem;">
<p><strong>${ico('file')} Archivo:</strong> Evaluación Inicial.pdf</p>
<p><strong>${ico('file-text')} Estado:</strong> ${proveedor.evaluacion_estado === 'aprobado' ? ' Aprobado' : proveedor.evaluacion_estado === 'rechazado' ? ' Rechazado' : ' Pendiente'}</p>
<p><strong>${ico('calendar')} Fecha:</strong> ${proveedor.evaluacion_fecha ? formatearFecha(proveedor.evaluacion_fecha) : ''}</p>
<div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="verDocumento('/uploads/${proveedor.evaluacion_inicial}','Evaluación Inicial')">${ICONOS.eye} Ver</button>
<a href="/api/admin/proveedor/${proveedor.id}/evaluacion/download" class="btn btn-sm btn-success">${ico('download')} Descargar</a>
</div>
</div>
` : `
<div style="background:#fef3c7;padding:1rem;border-radius:6px;border:1px solid #fcd34d;margin-bottom:1rem;">
<p>${ico('alert')} No hay evaluación inicial subida.</p>
</div>
`}
</div>
`;

html += `
<div style="margin-top:2rem;border-top:2px solid #e5e7eb;padding-top:1.5rem;">
<h4> Gestión de Inscripción/Actualización</h4>
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('info')} Nota:</strong> Al guardar con un número de registro, los <strong>documentos activos</strong> del proveedor se asociarán automáticamente a ese ciclo. Los documentos de ciclos anteriores quedan conservados en la pestaña <strong>${ico('archive')} Históricos</strong>.
</div>
${tienePermisoUI('gestion.inscribir') ? `
 <form id="formGestion" style="background:#f9fafb;padding:1.5rem;border-radius:8px;">
 <div class="form-group">
 <label for="numeroRegistro">${ico('file-text')} Fecha Movimiento</label>
<input type="text" id="numeroRegistro" value="${escapeHtml(proveedor.numero_registro || '')}" placeholder="Ej: Día Mes Año 01012000">
</div>
<div class="form-group">
<label for="observaciones"> Observaciones</label>
<textarea id="observaciones" rows="4" placeholder="Detalles sobre esta inscripción o actualización...">${escapeHtml(proveedor.notas_gestion || '')}</textarea>
</div>
<div class="form-group">
<label>Tipo de gestión</label>
<div style="display:flex;gap:1rem;margin-top:0.3rem;">
<label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;">
<input type="radio" name="tipoGestion" value="inscripcion" ${proveedor.tipo_gestion === 'inscripcion' || !proveedor.tipo_gestion ? 'checked' : ''}>
 Inscripción
</label>
<label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;">
<input type="radio" name="tipoGestion" value="actualizacion" ${proveedor.tipo_gestion === 'actualizacion' ? 'checked' : ''}>
${ico('refresh')} Actualización
</label>
</div>
</div>
<div class="form-group">
<label for="tipoProveedor"> Tipo de persona</label>
<select id="tipoProveedor" style="width:100%;padding:0.65rem 0.8rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="">— Sin definir —</option>
<option value="juridica" ${proveedor.tipo_proveedor === 'juridica' ? 'selected' : ''}>${ico('briefcase')} Persona Jurídica</option>
<option value="natural" ${proveedor.tipo_proveedor === 'natural' ? 'selected' : ''}>${ico('user')} Persona Natural</option>
</select>
<small style="color:#6b7280;font-size:0.8rem;">Define la documentación requerida del proveedor. Normalmente lo selecciona el propio proveedor en "Mis datos".</small>
</div>
 <button type= "submit " class= "btn " style= "background:#059669; " >${ICONOS.save} Guardar gestión </button >
 </form >` : '<div class="alert alert-info" style="margin-top:1rem;"> Tu perfil no tiene permiso de inscripción (solo consulta).</div>'}
</div>
`;
document.getElementById('modalContenidoDocs').innerHTML = html;
}

// ==========================================
//  RENDERIZAR DOCUMENTOS COMPLETO (para registrados)
// ==========================================
function renderDocsCompleto(p, docs, historicos) {
if (!p) {
document.getElementById('modalContenidoDocs').innerHTML = '<div class="alert alert-error">Error: No se pudo cargar la información del proveedor.</div>';
return;
}
//  FIX PUNTO 2: los proveedores RECHAZADOS/VENCIDOS ya NO son solo lectura.
// El administrador puede subir documentos en su nombre para iniciar la actualización.
// Solo los REGISTRADOS permanecen en modo solo lectura.
const soloLectura = p.etapa === 'registrado';
const esRechazado = p.etapa === 'rechazado';
const esVencimiento = p.notas_gestion && String(p.notas_gestion).toLowerCase().includes('vencimiento');
const numHistoricos = (historicos || []).length;

const map = {};
docs.forEach(d => { if (!map[d.tipo]) map[d.tipo] = []; map[d.tipo].push(d); });
let html = '';
//  R4 (D6): aviso de modo solo lectura para perfil revisor
if (esSoloLectorUI()) {
  html += `<div class="alert alert-info" style="margin-bottom:1rem;">${ico('info')} <strong>Modo solo lectura:</strong> tu perfil puede consultar y descargar documentos activos e históricos, pero no ejecutar acciones.</div>`;
}
//  FIX PUNTO 2: si el proveedor vencido/rechazado aún no define su tipo de persona,
// mostrar el bloque de definición (reutiliza renderDefinirTipoPersona y guardarTipoPersona).
if (!p.tipo_proveedor) {
html += renderDefinirTipoPersona(p);
}
html += `
<div class="card" style="background:#f9fafb;padding:1rem;margin-bottom:1rem;">
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin:0 0 2px;">
<strong>Email:</strong> <span id="emailActualProv">${escapeHtml(p.email || '—')}</span>
${tienePermisoUI('proveedores.gestionar') ? ` <button class= "btn btn-sm btn-secondary " onclick= "editarEmailProveedor(${p.id}, '${escapeAttr(p.email || '')}') " style= "padding:0.2rem 0.6rem;font-size:0.78rem; " >${ico('edit')} Cambiar </button >` : ''}</div>
<div id="contenedorEditarEmail" style="display:none;margin:0.3rem 0 0.4rem;"></div>
<strong>NIT/RUT:</strong> ${escapeHtml(p.rfc || '—')}<br>
<strong>Representante:</strong> ${escapeHtml(p.representante || '—')}<br>
<strong>Teléfono:</strong> ${escapeHtml(p.telefono || '—')}<br>
<strong>Dirección:</strong> ${escapeHtml(p.direccion || '—')}
${p.numero_registro ? `<br><strong>Fecha Movimiento:</strong> ${escapeHtml(p.numero_registro)}` : ''}
<br><strong>Tipo de persona:</strong> ${p.tipo_proveedor === 'natural' ? ' Persona Natural' : p.tipo_proveedor === 'juridica' ? ' Persona Jurídica' : ' Sin definir'}
${p.tipo_gestion ? `<br><strong>Tipo gestión:</strong> ${p.tipo_gestion === 'inscripcion' ? ' Inscripción' : ' Actualización'}` : ''}
${p.tipo_proveedor ? `<br><strong>Tipo de proveedor:</strong> ${escapeHtml(p.tipo_proveedor)}` : ''}
${p.notas_gestion ? `<br><strong>Nota:</strong> ${escapeHtml(p.notas_gestion)}` : ''}
${esRechazado ? `<br><span class="badge badge-rechazado" style="background:#dc2626;color:white;">${ico('x')} Rechazado</span>` : ''}
${p.etapa === 'registrado' ? `<br><span class="badge badge-aprobado" style="background:#059669;color:white;">${ico('check')} Registrado</span>` : ''}
</div>
${esRechazado ? `
<div style="margin-top:1rem;padding:1.5rem;background:#fee2e2;border:2px solid #dc2626;border-radius:8px;text-align:center;">
<p style="color:#991b1b;font-weight:600;margin-bottom:0.5rem;">${ico('alert')} Este proveedor fue rechazado${esVencimiento ? ' por vencimiento de documentos' : ''}.</p>
<p style="color:#7f1d1d;margin-bottom:0;">
${esVencimiento
? 'Todos sus documentos fueron movidos a histórico (ver pestaña  Históricos). Como administrador ya puedes subir documentos en nombre del proveedor para iniciar la actualización. El proveedor deberá seleccionar su tipo de persona y completar su documentación en el portal.'
: 'Sus documentos quedaron rechazados. Como administrador puedes subir documentos corregidos en nombre del proveedor si es necesario; el proveedor debe eliminar los rechazados activos antes de volver a cargar.'}
</p>
</div>
` : ''}
${soloLectura && !esRechazado ? `
<div style="margin-bottom:1rem;padding:1rem;background:#dbeafe;border:1px solid #2563eb;border-radius:8px;">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
<div>
<strong style="color:#1e40af;">${ico('refresh')} Actualización anual disponible</strong>
<p style="margin:0.3rem 0 0 0;color:#1e40af;font-size:0.9rem;">Puedes solicitar al proveedor que actualice sus documentos para el nuevo período. Sus documentos actuales se archivarán en el histórico.</p>
</div>
${tienePermisoUI('proveedores.gestionar') ? `
 <button class= "btn " style= "background:#2563eb;color:white;white-space:nowrap; "
data-id= "${p.id} "
data-nombre= "${escapeAttr(p.razon_social || p.nombre_empresa || 'Proveedor')} "
onclick= "abrirSolicitudActualizacion(this) " >
${ico('refresh')} Solicitar actualización
 </button >` : ''}
</div>
</div>
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('info')} Modo solo lectura:</strong> Este proveedor está registrado. Puedes visualizar, descargar y solicitar actualización de documentos.
</div>
` : ''}
${!soloLectura ? `
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>${ico('info')} Información:</strong> Como administrador, puedes subir documentos en nombre del proveedor para agilizar el proceso de registro.
</div>
` : ''}
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
<h4 style="margin:0;">Documentos activos</h4>
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
${numHistoricos > 0 ? `<small style="color:#6b7280;">${ico('archive')} ${numHistoricos} histórico(s) — ver pestaña "Históricos"</small>` : ''}
<button class="btn btn-success" onclick="descargarZIP(${p.id})" style="display:inline-flex;align-items:center;gap:0.5rem;">
${ICONOS.zip} Descargar activos en ZIP
</button>
</div>
</div>
<div class="doc-grid">
`;

requeridos.forEach((req, idx) => {
const sub = map[req.tipo] || [];
const ok = sub.filter(d => d.estado === 'aprobado').length >= req.cantidadMin;
const noAplica = sub.length > 0 && sub[0]?.no_aplica === 1;
//  Cupo múltiple (experiencia): permite agregar hasta cantidadMax
const permiteMultiples = req.cantidadMin > 1 || (req.cantidadMax && req.cantidadMax > 1);
const puedeSubir = !soloLectura && (permiteMultiples
? true
: (sub.length === 0 || (sub[0]?.estado === 'rechazado' && !noAplica)));

html += `<div class="doc-item doc-item-col">
<div class="doc-item-head">
<h4>${idx+1}. ${req.nombre}</h4>
<small style="color:#6b7280;">Requeridos: ${req.cantidadMin} · Subidos: ${sub.length}</small>
${ok ? '<span class="badge badge-aprobado" style="margin-left:0.5rem;">Completo</span>' : ''}
</div>`;

if (!sub.length) {
html += '<small style="color:#9ca3af;"> No ha subido</small>';
} else {
sub.forEach(d => {
const verificado = d.verificado === 1;
const mostrarCheck = !soloLectura && d.estado !== 'aprobado';
const esNoAplica = (d.no_aplica === 1 || d.archivo === 'no_aplica'); //  sin archivo físico
const checkDeshabilitado = d.estado === 'rechazado' || soloLectura || esNoAplica || !tienePermisoUI('docs.verificar');

const extraCheck = mostrarCheck ? `
<br><label style="display:inline-flex;align-items:center;gap:0.3rem;font-size:0.85rem;cursor:pointer;margin-top:0.2rem;">
<input type="checkbox" class="checkbox-verificado" data-docid="${d.id}"
${verificado ? 'checked' : ''} ${checkDeshabilitado ? 'disabled' : ''}>
<span style="color:${verificado ? '#059669' : '#6b7280'};">${verificado ? ' Verificado' : 'Marcar como verificado'}</span>
</label>
` : '';
html += `<div class="doc-row">
${infoDocRow(d, { extra: extraCheck })}
<div class="doc-row-actions">
${esNoAplica
? '<small style="color:#92400e;font-weight:600;"> Sin archivo (No aplica)</small>'
: `
<button class="btn btn-sm btn-secondary" data-url="/uploads/${escapeAttr(d.archivo)}" data-nombre="${escapeAttr(nombreFormato(d.tipo))}" onclick="verDocumentoBtn(this)">${ICONOS.eye} Ver</button>
<a href="/uploads/${escapeAttr(d.archivo)}?download=true" class="btn btn-sm btn-success">${ICONOS.download}</a>
`}
${!soloLectura ? `
${tienePermisoUI('docs.aprobar') ? ` <button class= "btn btn-sm " style= "background:#059669; " onclick= "cambiarEstado(${d.id},'aprobado') " >${ICONOS.check} Aprobar </button >` : ''}
${tienePermisoUI('docs.rechazar') ? ` <button class= "btn btn-sm btn-danger " onclick= "rechazar(${d.id}) " >${ICONOS.x} Rechazar </button >` : ''}
` : ''}
</div>
</div>`;
});
}

if (!soloLectura && req.opcional) {
//  FIX: solo contar archivos REALES; un marcador 'no_aplica' rechazado no debe bloquear el re-marcado
const tieneArchivosReales = sub.some(d => d.archivo && d.archivo !== 'no_aplica');
const checkboxDisabled = tieneArchivosReales && !noAplica;
html += `<div class="box-noaplica">
 <label style="display:flex;align-items:center;gap:0.5rem;cursor:${checkboxDisabled ? 'not-allowed' : 'pointer'};">
 <input type="checkbox" class="checkbox-no-aplica-admin"
data-docid="${sub[0]?.id || ''}" data-tipo="${req.tipo}" data-proveedorid="${p.id}"
${noAplica ? 'checked' : ''} ${checkboxDisabled ? 'disabled' : ''}>
<span style="font-weight:500;color:#92400e;opacity:${checkboxDisabled ? 0.6 : 1};">${ico('file-text')} Marcar como "No Aplica" para este proveedor</span>
</label>
<small style="color:#78350f;display:block;margin-top:0.3rem;">
${noAplica ? ' Documento marcado como "No aplica". La carga de archivos está desactivada.'
: (checkboxDisabled ? ' Ya hay archivos subidos. No puedes marcar "No aplica" si ya hay documentos cargados.'
: 'Si marcas esta opción, el documento se aprobará automáticamente como "No aplica"')}
</small>
</div>`;
}

if (!soloLectura && req.tipo === 'experiencia') {
const maxExp = req.cantidadMax || 3; //  jurídico=3, natural=2
const subidosValidos = sub.filter(d => d.estado !== 'rechazado' && d.no_aplica === 0).length;
const maxAlcanzado = subidosValidos >= maxExp;
html += `<div class="box-exito">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
 <span style="font-size:0.85rem;color:#065f46;">
${ico('file-text')} Certificados subidos: <strong>${subidosValidos}/${maxExp}</strong>
${maxAlcanzado ? '  Límite alcanzado' : ''}
</span>
${!maxAlcanzado && puedeSubir ? `
<form class="form-upload dropzone form-upload-admin" data-tipo="${req.tipo}" data-proveedorid="${p.id}">
<div class="dz-icon">${ICONOS.upload}</div>
<div class="dz-text"><strong>Subir como administrador</strong><small>Adjunta el PDF en nombre del proveedor · PDF · máx. 15 MB</small></div>
<input type="file" name="archivo" required accept=".pdf">
<button type="submit" class="btn btn-sm" style="background:#0284c7;">${ICONOS.upload} Subir PDF</button>
</form>
` : `
<span style="color:#6b7280;font-size:0.9rem;">${maxAlcanzado ? `${ico('check')} Máximo de ${maxExp} certificados alcanzado` : 'No disponible'}</span>
`}
</div>
</div>`;
}

if (!soloLectura && req.tipo !== 'experiencia' && puedeSubir && !noAplica) {
const label = sub.length === 0 ? ICONOS.upload + ' Admin subir PDF' : (req.cantidadMin > 1 ? ICONOS.plus + ` Agregar PDF (${sub.length}/${req.cantidadMin})` : ICONOS.upload + ' Reemplazar PDF');
html += `<form class="form-upload dropzone form-upload-admin" data-tipo="${req.tipo}" data-proveedorid="${p.id}">
<div class="dz-icon">${ICONOS.upload}</div>
<div class="dz-text"><strong>Subir como administrador</strong><small>Adjunta el PDF en nombre del proveedor · PDF · máx. 15 MB</small></div>
<input type="file" name="archivo" required accept=".pdf">
<button type="submit" class="btn btn-sm" style="background:#0284c7;">${label}</button>
</form>`;
} else if (!soloLectura && req.tipo !== 'experiencia' && noAplica) {
html += `<div class="box-noaplica">
 <small style="color:#92400e;">${ico('file-text')} Documento marcado como "No aplica". La carga de archivos está desactivada.</small>
 </div>`;
}
html += '</div>';
});
html += '</div>';

html += `
<div style="margin-top:2rem;border-top:2px solid #e5e7eb;padding-top:1.5rem;">
<h4>${ico('file-text')} Evaluación Inicial</h4>
${p.evaluacion_inicial ? `
<div style="background:#f9fafb;padding:1rem;border-radius:6px;margin-bottom:1rem;">
<p><strong>${ico('file')} Archivo:</strong> Evaluación Inicial.pdf</p>
<p><strong>${ico('file-text')} Estado:</strong> ${p.evaluacion_estado === 'aprobado' ? ' Aprobado' : p.evaluacion_estado === 'rechazado' ? ' Rechazado' : ' Pendiente'}</p>
<p><strong>${ico('calendar')} Fecha:</strong> ${p.evaluacion_fecha ? formatearFecha(p.evaluacion_fecha) : ''}</p>
<div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="verDocumento('/uploads/${p.evaluacion_inicial}','Evaluación Inicial')">${ICONOS.eye} Ver</button>
<a href="/api/admin/proveedor/${p.id}/evaluacion/download" class="btn btn-sm btn-success">${ico('download')} Descargar</a>
</div>
</div>
` : `
<div class="box-noaplica" style="margin-bottom:1rem;">
 <p>${ico('alert')} No hay evaluación inicial subida.</p>
 </div>
`}
</div>
`;
document.getElementById('modalContenidoDocs').innerHTML = html;
}

// ==========================================
//  PLANTILLAS
// ==========================================
function renderizarPlantillas() {
const cont = document.getElementById('contenedor-modulos');
if (!cont) return;
let html = `
<div class="card">
    <h3><svg class="ico ico-lg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> Plantillas para proveedores</h3>
    <p style="color:#6b6478;font-size:0.9rem;margin:0.5rem 0 1rem;">Sube los formatos institucionales que el proveedor debe descargar, diligenciar, firmar y devolver en PDF.</p>
    <div id="listaPlantillas" class="doc-grid"></div>
</div>
`;
cont.innerHTML = html;
cargarPlantillas();
}
async function cargarPlantillas() {
const cont = document.getElementById('listaPlantillas');
if (!cont) return;
// Espera ACOTADA a que existan los requerimientos (máx. 10 intentos)
if (!requeridos || requeridos.length === 0) {
cargarPlantillas._intentos = (cargarPlantillas._intentos || 0) + 1;
if (cargarPlantillas._intentos > 10) {
cont.innerHTML = '<p style="color:#991b1b;">No se pudieron cargar los tipos de documento. Recarga la página o revisa tu sesión.</p>';
return;
}
setTimeout(() => cargarPlantillas(), 300);
return;
}
cargarPlantillas._intentos = 0; //  resetea el contador al cargar bien

    const plantillasRequeridas = requeridos.filter(r => r.esPlantilla === true);
    if (plantillasRequeridas.length === 0) {
        cont.innerHTML = '<p style="color:#6b6478;">No hay plantillas configuradas.</p>';
        return;
    }

    try {
        const response = await fetchAPI('/api/admin/plantillas');
        if (!response.ok) throw new Error('Error al obtener plantillas');
        const plantillas = await response.json();
const map = {};
plantillas.forEach(p => map[p.tipo] = p);
cont.innerHTML = '';
//  F7: DocumentFragment = un solo reflow al final en vez de uno por plantilla
const fragPlantillas = document.createDocumentFragment();
plantillasRequeridas.forEach(req => {
            const p = map[req.tipo];
            const div = document.createElement('div');
            div.className = 'doc-item';
            div.style.cssText = 'flex-direction:column;align-items:stretch;';
            div.innerHTML = `
                <div style="margin-bottom:0.5rem;"><h4>${req.nombre}</h4></div>
                ${p ? `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:0.5rem;background:#f9fafb;border-radius:6px;margin-bottom:0.5rem;">
                    <small>${ico('check')} ${p.nombre_original}</small>
                    <a href="/plantillas/${p.archivo}" target="_blank" class="btn btn-sm btn-secondary">Ver</a>
                </div>
                ` : `
                <div class="alert" style="background:#fee2e2;color:#991b1b;padding:0.5rem;margin-bottom:0.5rem;">${ico('alert')} Sin plantilla</div>
                `}
                <form class="form-plantilla" data-tipo="${req.tipo}" style="display:flex;gap:0.5rem;align-items:center;">
                    <input type="file" name="archivo" required accept=".pdf,.doc,.docx,.xls,.xlsx">
                    <button type="submit" class="btn btn-sm">${p ? 'Reemplazar' : 'Subir'}</button>
        </form>
        `;
        fragPlantillas.appendChild(div);
        });
        cont.appendChild(fragPlantillas);
        // Adjunta handlers SOLO a los formularios recién renderizados
        cont.querySelectorAll('.form-plantilla').forEach(form => {
            form.addEventListener('submit', async e => {
                e.preventDefault();
                const fd = new FormData(e.target);
                fd.append('tipo', e.target.dataset.tipo);
                const res = await fetchAPI('/api/admin/plantilla', { method: 'POST', body: fd });
                if (res.ok) {
                    mostrarAlerta(' Plantilla cargada', 'success');
                    cargarPlantillas();
                    actualizarContadorPlantillas();
                } else {
                    const r = await res.json();
                    mostrarAlerta(r.error);
                }
            });
        });

        actualizarContadorPlantillas();
    } catch (err) {
        console.error('Error cargando plantillas:', err);
        cont.innerHTML = `<p style="color:#991b1b;">Error al cargar plantillas: ${err.message}</p>`;
    }
}

// ==========================================
//  HISTORIAL DE ACTUALIZACIONES
// ==========================================
let historialPaginaActual = 1;
let historialLimiteActual = 20;
let historialTotalPaginas = 1;
let historialTotalRegistros = 0;
let historialFiltros = { busqueda: '', año: '', rfc: '', estado: '' };

async function cargarHistorial(pagina = 1) {
try {
const contenedor = document.getElementById('contenedor-modulos');
const { busqueda, año, rfc, estado } = historialFiltros;
const limit = historialLimiteActual;

let url = `/api/admin/ciclos?page=${pagina}&limit=${limit}`;
if (busqueda) url += `&busqueda=${encodeURIComponent(busqueda)}`;
if (año) url += `&año=${encodeURIComponent(año)}`;
if (rfc) url += `&rfc=${encodeURIComponent(rfc)}`;
if (estado) url += `&estado=${encodeURIComponent(estado)}`;

const response = await fetchAPI(url);
const data = await response.json();
if (!response.ok) throw new Error(data.error || 'Error al cargar historial');

historialPaginaActual = data.page || 1;
historialTotalPaginas = data.totalPages || 1;
historialTotalRegistros = data.total || 0;
historialLimiteActual = data.limit || 20;

let html = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
<h3 style="margin:0;">${ico('file-text')} Historial de actualizaciones</h3>
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-success" onclick="exportarHistorial()">${ico('file-text')} Exportar</button>
</div>
</div>
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1.5rem;">
<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:1rem;margin-bottom:1rem;">
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('search')} Buscar</label>
<input type="text" id="historialBusqueda" placeholder="Nombre, email..."
value="${escapeHtml(busqueda)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Año</label>
<select id="historialAno" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="">Todos</option>
</select>
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('briefcase')} NIT / RUT</label>
<input type="text" id="historialRfc" placeholder="Ej: 900123456"
value="${escapeHtml(rfc)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;"> Estado</label>
<select id="historialEstado" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="">Todos</option>
<option value="activo" ${estado === 'activo' ? 'selected' : ''}>Activo</option>
<option value="cerrado" ${estado === 'cerrado' ? 'selected' : ''}>Cerrado</option>
<option value="rechazado" ${estado === 'rechazado' ? 'selected' : ''}>Rechazado</option>
</select>
</div>
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm" onclick="aplicarFiltrosHistorial()">${ico('search')} Filtrar</button>
<button class="btn btn-sm btn-secondary" onclick="limpiarFiltrosHistorial()">${ico('trash')} Limpiar</button>
</div>
<div id="paginacionHistorial" style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;flex-wrap:wrap;gap:0.5rem;">
<div style="display:flex;gap:0.5rem;align-items:center;">
<button id="btnHistorialAnterior" class="btn btn-sm btn-secondary" onclick="cambiarPaginaHistorial(-1)"> Anterior</button>
<span id="infoHistorialPagina">Página ${data.page} de ${data.totalPages} (${data.total} registros)</span>
<button id="btnHistorialSiguiente" class="btn btn-sm btn-secondary" onclick="cambiarPaginaHistorial(1)">Siguiente </button>
</div>
<div>
<label style="font-size:0.85rem;">Mostrar:</label>
<select id="historialLimite" onchange="cambiarLimiteHistorial()" style="padding:0.3rem;border-radius:4px;border:1px solid #d1d5db;">
<option value="10" ${limit === 10 ? 'selected' : ''}>10</option>
<option value="20" ${limit === 20 ? 'selected' : ''}>20</option>
<option value="50" ${limit === 50 ? 'selected' : ''}>50</option>
<option value="100" ${limit === 100 ? 'selected' : ''}>100</option>
</select>
</div>
</div>
</div>
<div id="listaHistorialCiclos"></div>
</div>
`;
contenedor.innerHTML = html;
await cargarAnosHistorial();
renderizarTablaHistorial(data.data || []);
actualizarBotonesHistorial();

const hb = document.getElementById('historialBusqueda');
const hr = document.getElementById('historialRfc');
if (hb) hb.addEventListener('keyup', (e) => { if (e.key === 'Enter') aplicarFiltrosHistorial(); });
if (hr) hr.addEventListener('keyup', (e) => { if (e.key === 'Enter') aplicarFiltrosHistorial(); });
} catch (err) {
console.error(' Error cargando historial:', err);
const contenedor = document.getElementById('contenedor-modulos');
contenedor.innerHTML = `<div class="alert alert-error">${ico('x')} Error al cargar historial: ${err.message}</div>`;
}
}

async function cargarAnosHistorial() {
try {
const response = await fetchAPI('/api/admin/ciclos/anos');
if (!response.ok) return;
const anos = await response.json();
const select = document.getElementById('historialAno');
if (!select) return;
const currentValue = historialFiltros.año;
select.innerHTML = '<option value="">Todos</option>';
anos.forEach(a => {
const opt = document.createElement('option');
opt.value = a; opt.textContent = a;
if (currentValue && String(a) === String(currentValue)) opt.selected = true;
select.appendChild(opt);
});
} catch (err) { console.error('Error cargando años:', err); }
}

function renderizarTablaHistorial(ciclos) {
const cont = document.getElementById('listaHistorialCiclos');
if (!cont) return;
if (!ciclos || ciclos.length === 0) {
cont.innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">No se encontraron ciclos con los filtros aplicados.</p>';
return;
}
let html = `
<div style="overflow-x:auto;">
<table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
<thead>
<tr style="background:#f3f4f6;border-bottom:2px solid #d1d5db;">
<th style="padding:0.7rem;text-align:left;">Proveedor</th>
<th style="padding:0.7rem;text-align:left;">Fecha Movimiento</th>
<th style="padding:0.7rem;text-align:center;">Fecha Inicio</th>
<th style="padding:0.7rem;text-align:center;">Fecha Fin</th>
<th style="padding:0.7rem;text-align:center;">Estado</th>
<th style="padding:0.7rem;text-align:center;">NIT / RUT</th>
<th style="padding:0.7rem;text-align:center;">Acciones</th>
</tr>
</thead>
<tbody>
`;
ciclos.forEach(c => {
const estadoColor = c.estado === 'activo' ? '#059669' : c.estado === 'cerrado' ? '#6b7280' : '#dc2626';
const estadoIcon = c.estado === 'activo' ? ico('check-circle', 'ico-exito') : c.estado === 'cerrado' ? ico('lock', 'ico-muted') : ico('x-circle', 'ico-peligro');
const fechaFin = c.fecha_fin ? formatearFecha(c.fecha_fin) : '—';
html += `
<tr style="border-bottom:1px solid #e5e7eb;">
<td style="padding:0.7rem;">
<strong>${escapeHtml(c.razon_social)}</strong><br>
<small style="color:#6b7280;">${escapeHtml(c.email)}</small>
</td>
<td style="padding:0.7rem;font-weight:500;">${escapeHtml(c.numero_registro)}</td>
<td style="padding:0.7rem;text-align:center;">${formatearFecha(c.fecha_inicio)}</td>
<td style="padding:0.7rem;text-align:center;">${fechaFin}</td>
<td style="padding:0.7rem;text-align:center;">
<span style="color:${estadoColor};font-weight:600;">${estadoIcon} ${c.estado}</span>
</td>
<td style="padding:0.7rem;text-align:center;font-family:monospace;font-weight:600;color:#1f1830;">
${escapeHtml(c.rfc || '—')}
</td>
<td style="padding:0.7rem;text-align:center;">
<button class="btn btn-sm btn-secondary" onclick="verCiclo(${c.id})">${ico('eye')} Ver docs</button>
<button class="btn btn-sm btn-success" onclick="descargarZIPCiclo(${c.id})">${ico('archive')} ZIP</button>
</td>
</tr>
`;
});
html += `</tbody></table></div>`;
cont.innerHTML = html;
}

function actualizarBotonesHistorial() {
const btnAnt = document.getElementById('btnHistorialAnterior');
const btnSig = document.getElementById('btnHistorialSiguiente');
const info = document.getElementById('infoHistorialPagina');
if (!btnAnt || !btnSig || !info) return;
const total = historialTotalRegistros;
if (total === 0) { info.textContent = 'No hay registros'; btnAnt.disabled = true; btnSig.disabled = true; return; }
info.textContent = `Página ${historialPaginaActual} de ${historialTotalPaginas} (${total} registros)`;
btnAnt.disabled = (historialPaginaActual <= 1);
btnSig.disabled = (historialPaginaActual >= historialTotalPaginas);
}
function cambiarPaginaHistorial(delta) {
const nueva = historialPaginaActual + delta;
if (nueva < 1 || nueva > historialTotalPaginas) return;
historialPaginaActual = nueva;
cargarHistorial(nueva);
}
function cambiarLimiteHistorial() {
const select = document.getElementById('historialLimite');
if (!select) return;
const nuevoLimite = parseInt(select.value);
if (nuevoLimite === historialLimiteActual) return;
historialLimiteActual = nuevoLimite;
historialPaginaActual = 1;
cargarHistorial(1);
}
function aplicarFiltrosHistorial() {
historialFiltros.busqueda = document.getElementById('historialBusqueda').value.trim();
historialFiltros.año = document.getElementById('historialAno').value;
historialFiltros.rfc = document.getElementById('historialRfc').value.trim();
historialFiltros.estado = document.getElementById('historialEstado').value;
historialPaginaActual = 1;
cargarHistorial(1);
}
function limpiarFiltrosHistorial() {
document.getElementById('historialBusqueda').value = '';
document.getElementById('historialAno').value = '';
document.getElementById('historialRfc').value = '';
document.getElementById('historialEstado').value = '';
historialFiltros = { busqueda: '', año: '', rfc: '', estado: '' };
historialPaginaActual = 1;
cargarHistorial(1);
}

// ==========================================
//  VER CICLO (modal con documentos)
// ==========================================
async function verCiclo(cicloId) {
try {
const response = await fetchAPI(`/api/admin/ciclos/${cicloId}/documentos`);
if (!response.ok) {
const err = await response.json();
throw new Error(err.error || 'Error al cargar documentos del ciclo');
}
const data = await response.json();
const { ciclo, documentos } = data;
const evaluacion = data.evaluacion || null;

const modal = document.createElement('div');
modal.className = 'modal-overlay active';
modal.id = 'modalCicloDocs';
modal.style.zIndex = '1000';
let docsHtml = '';
if (evaluacion && evaluacion.archivo) {
const evalBadge = evaluacion.es_historico === 1
? '<span class="badge badge-faltante">' + ico('archive') + ' Histórica</span>'
: (evaluacion.estado === 'aprobado' ? '<span class="badge badge-aprobado">' + ico('check') + ' Aprobada</span>'
: evaluacion.estado === 'rechazado' ? '<span class="badge badge-rechazado">' + ico('x') + ' Rechazada</span>'
: '<span class="badge badge-pendiente"> Pendiente</span>');
docsHtml += `
<div class="doc-item" style="flex-direction:column;align-items:stretch;background:#f5f3ff;border:1px solid #c4b5fd;">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
<span><strong>${ico('file-text')} Evaluación Inicial</strong> ${evalBadge}</span>
</div>
<div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="verDocumento('/uploads/${evaluacion.archivo}','Evaluación Inicial')">${ICONOS.eye} Ver</button>
<a href="/uploads/${evaluacion.archivo}?download=true" class="btn btn-sm btn-success">${ico('download')} Descargar</a>
</div>
${evaluacion.fecha ? `<small style="color:#6b7280;">${ico('calendar')} Fecha: ${formatearFecha(evaluacion.fecha)}</small>` : ''}
</div>
`;
}
if (documentos && documentos.length > 0) {
docsHtml += `
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
<h4 style="margin:0;">Documentos del ciclo ${escapeHtml(ciclo.numero_registro)}</h4>
<button class="btn btn-sm btn-success" onclick="descargarZIPCiclo(${ciclo.id})">${ico('archive')} Descargar todos en ZIP</button>
</div>
<div class="doc-grid">
`;
documentos.forEach(d => {
const estadoVencimiento = d.estado_vencimiento || 'vigente';
const vencimientoColor = estadoVencimiento === 'vencido' ? '#dc2626' : estadoVencimiento === 'proximo_a_vencer' ? '#d97706' : '#059669';
const vencimientoLabel = estadoVencimiento === 'vencido' ? ico('x-circle', 'ico-peligro') + ' Vencido' : estadoVencimiento === 'proximo_a_vencer' ? ico('clock', 'ico-advertencia') + ' Próximo a vencer' : ico('check-circle', 'ico-exito') + ' Vigente';
docsHtml += `
<div class="doc-item" style="flex-direction:column;align-items:stretch;">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
<span><strong>${escapeHtml(nombreFormato(d.tipo))}</strong></span>
<span>
<span class="badge badge-${d.estado || 'pendiente'}">${d.estado || 'pendiente'}</span>
${d.es_historico === 1 ? '<span class="badge badge-rechazado" style="margin-left:0.3rem;">histórico</span>' : ''}
${d.fecha_vencimiento ? `<span style="color:${vencimientoColor};font-size:0.8rem;margin-left:0.5rem;">${vencimientoLabel}</span>` : ''}
</span>
</div>
<div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
${(d.no_aplica === 1 || d.archivo === 'no_aplica')
? '<small style="color:#92400e;font-weight:600;"> Sin archivo (No aplica)</small>'
: `
<button class="btn btn-sm btn-secondary" data-url="/uploads/${escapeAttr(d.archivo)}" data-nombre="${escapeAttr(nombreFormato(d.tipo))}" onclick="verDocumentoBtn(this)">${ICONOS.eye} Ver</button>
<a href="/uploads/${escapeAttr(d.archivo)}?download=true" class="btn btn-sm btn-success">${ico('download')} Descargar</a>
`}
</div>
${d.fecha_vencimiento ? `<small style="color:#6b7280;">Vence: ${formatearFecha(d.fecha_vencimiento)}</small>` : ''}
</div>
`;
});
docsHtml += '</div>';
} else {
docsHtml += '<p style="color:#6b7280;">Este ciclo no tiene documentos asociados.</p>';
}

modal.innerHTML = `
<div class="modal" style="max-width:900px;max-height:90vh;overflow-y:auto;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
<h3 style="margin:0;"> Ciclo: ${escapeHtml(ciclo.numero_registro)}</h3>
<button class="btn btn-sm btn-secondary" onclick="cerrarModalCiclo()"> Cerrar</button>
</div>
<div style="background:#f9fafb;padding:1rem;border-radius:6px;margin-bottom:1rem;">
<p><strong>Proveedor:</strong> ${escapeHtml(ciclo.razon_social)}</p>
<p><strong>Email:</strong> ${escapeHtml(ciclo.email)}</p>
<p><strong>Fecha inicio:</strong> ${formatearFecha(ciclo.fecha_inicio)}</p>
<p><strong>Fecha fin:</strong> ${ciclo.fecha_fin ? formatearFecha(ciclo.fecha_fin) : '—'}</p>
<p><strong>Estado:</strong> <span style="color:${ciclo.estado === 'activo' ? '#059669' : ciclo.estado === 'cerrado' ? '#6b7280' : '#dc2626'};font-weight:600;">${ciclo.estado}</span></p>
</div>
${docsHtml}
</div>
`;
document.body.appendChild(modal);
modal.addEventListener('click', (e) => { if (e.target === modal) cerrarModalCiclo(); });
} catch (err) {
console.error(' Error viendo ciclo:', err);
mostrarAlerta(' Error al cargar los documentos del ciclo: ' + err.message);
}
}
function cerrarModalCiclo() {
const modal = document.getElementById('modalCicloDocs');
if (modal) modal.remove();
}

// ==========================================
//  DESCARGAR ZIP DE CICLO
// ==========================================
async function descargarZIPCiclo(cicloId) {
try {
mostrarAlerta(' Generando ZIP del ciclo...', 'info');
const response = await fetchAPI(`/api/admin/ciclos/${cicloId}/zip`);
if (!response.ok) {
const err = await response.json();
throw new Error(err.error || 'Error al generar ZIP');
}
const blob = await response.blob();
const contentDisposition = response.headers.get('Content-Disposition');
let filename = `ciclo_${cicloId}.zip`;
if (contentDisposition) {
const match = contentDisposition.match(/filename="(.+)"/);
if (match) filename = decodeURIComponent(match[1]);
}
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url; a.download = filename;
document.body.appendChild(a); a.click(); document.body.removeChild(a);
window.URL.revokeObjectURL(url);
mostrarAlerta(' ZIP descargado correctamente', 'success');
} catch (err) {
console.error(' Error descargando ZIP del ciclo:', err);
mostrarAlerta(' Error al descargar: ' + err.message);
}
}

// ==========================================
//  EXPORTAR HISTORIAL (CSV)
// ==========================================
async function exportarHistorial() {
try {
const { busqueda, año, rfc, estado } = historialFiltros;
let url = `/api/admin/ciclos?page=1&limit=10000`;
if (busqueda) url += `&busqueda=${encodeURIComponent(busqueda)}`;
if (año) url += `&año=${encodeURIComponent(año)}`;
//if (numero_registro) url += `&numero_registro=${encodeURIComponent(numero_registro)}`;
if (rfc) url += `&rfc=${encodeURIComponent(rfc)}`;
if (estado) url += `&estado=${encodeURIComponent(estado)}`;

const response = await fetchAPI(url);
const data = await response.json();
if (!response.ok) throw new Error(data.error || 'Error al exportar');
const ciclos = data.data || [];
if (ciclos.length === 0) { mostrarAlerta('No hay datos para exportar con los filtros actuales', 'info'); return; }

const headers = ['Proveedor', 'Email', 'Fecha Movimiento', 'Fecha Inicio', 'Fecha Fin', 'Estado', 'Documentos Totales', 'Documentos Aprobados'];
const rows = ciclos.map(c => [
c.razon_social || '', c.email || '', c.numero_registro || '',
c.fecha_inicio || '', c.fecha_fin || '', c.estado || '',
c.total_documentos || 0, c.documentos_aprobados || 0
]);
const csv = '\uFEFF' + [headers.join(';'), ...rows.map(r => r.map(celdaCSV).join(';'))].join('\n');
const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
const urlBlob = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = urlBlob; a.download = `historial_ciclos_${fechaArchivo()}.csv`;
document.body.appendChild(a); a.click(); document.body.removeChild(a);
window.URL.revokeObjectURL(urlBlob);
mostrarAlerta(`${ico('check')} Historial exportado (${ciclos.length} ciclos)`, 'success');
} catch (err) {
console.error(' Error exportando historial:', err);
mostrarAlerta(' Error al exportar: ' + err.message);
}
}

// ==========================================
//  CONFIGURACIÓN DEL SISTEMA (FECHA FIJA)
// ==========================================
async function cargarConfiguracion() {
const contenedor = document.getElementById('contenedor-modulos');
let html = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
<h3 style="margin:0;">${ico('settings')} Configuración del sistema</h3>
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="recargarConfiguracion()">${ico('refresh')} Recargar</button>
</div>
</div>
<div id="configuracionContenido">
<div style="text-align:center;padding:2rem;">
<div style="font-size:2rem;margin-bottom:0.5rem;">${ico('clock')}</div>
<p>Cargando configuración...</p>
</div>
</div>
</div>
`;
contenedor.innerHTML = html;
await recargarConfiguracion();
}
async function recargarConfiguracion() {
try {
const response = await fetchAPI('/api/admin/configuracion');
if (!response.ok) {
const err = await response.json();
throw new Error(err.error || 'Error al cargar configuración');
}
const config = await response.json();
renderizarFormularioConfiguracion(config);
cargarBackups();
} catch (err) {
console.error(' Error cargando configuración:', err);
const cont = document.getElementById('configuracionContenido');
if (cont) cont.innerHTML = `<div class="alert alert-error">${ico('x')} Error al cargar configuración: ${err.message}</div>`;
}
}

// ==========================================
//  RENDER DEL FORMULARIO DE CONFIGURACIÓN
// ==========================================
function renderizarFormularioConfiguracion(config) {
    const cont = document.getElementById('configuracionContenido');
    if (!cont) return;
    let fechaActual = config?.valor || '';
    if (!fechaActual) {
        const fecha = new Date();
        fecha.setFullYear(fecha.getFullYear() + 1);
        fecha.setHours(23, 59, 59, 0);
        fechaActual = fecha.toISOString().slice(0, 16);
    } else {
        fechaActual = fechaActual.replace(' ', 'T').slice(0, 16);
    }
    const fechaMostrada = config?.valor ? formatearFecha(config.valor) : 'No configurada';
    const fechaActualizacion = config?.actualizado_en ? formatearFecha(config.actualizado_en) : 'Nunca';
    cont.innerHTML = `
    <div style="margin-top:1.5rem;padding-top:1.5rem;border-top:2px solid #e5e7eb;">
        <h4 style="color:#dc2626;margin-bottom:0.5rem;"> Acciones urgentes</h4>
        <p style="color:#6b7280;font-size:0.9rem;margin-bottom:1rem;">
            Esta acción moverá <strong>TODOS los documentos activos</strong> de <strong>TODOS los proveedores</strong> a histórico y los cambiará a estado RECHAZADO, sin importar su fecha de vencimiento.
        </p>
        <button class="btn btn-danger" onclick="forzarVencimientosAhora()" style="background:#dc2626;color:white;font-weight:bold;padding:0.8rem 2rem;">
             Forzar vencimiento de todos los documentos
        </button>
        <small style="color:#6b7280;display:block;margin-top:0.5rem;">
            ${ico('alert')} Esta acción es irreversible. Se recomienda hacer una copia de seguridad antes.
        </small>
    </div>
    <div style="background:#f0fdf4;padding:1.5rem;border-radius:8px;margin-bottom:1.5rem;border-left:4px solid #059669;">
        <h4 style="color:#065f46;margin-bottom:0.5rem;">${ico('file-text')} Configuración actual</h4>
        <p><strong>${ico('calendar')} Fecha fija de vencimiento:</strong> <span style="font-size:1.2rem;font-weight:700;color:#059669;">${fechaMostrada}</span></p>
        <p><strong>${ico('clock')} Última actualización:</strong> ${fechaActualizacion}</p>
        <p><strong> Descripción:</strong> Fecha y hora a partir de la cual los documentos aprobados se considerarán vencidos.</p>
    </div>
    <div style="background:#f9fafb;padding:1.5rem;border-radius:8px;margin-bottom:1.5rem;">
        <h4 style="margin-bottom:0.5rem;">${ico('edit')} Modificar fecha fija de vencimiento</h4>
        <p style="color:#6b7280;font-size:0.9rem;margin-bottom:1rem;">
            Establece la fecha y hora exacta en que todos los documentos aprobados pasarán a vencidos.
            Esta fecha se aplicará a los documentos que se aprueben a partir de ahora.
        </p>
        <div style="display:flex;gap:1rem;align-items:flex-end;flex-wrap:wrap;">
            <div style="flex:1;min-width:200px;">
                <label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Fecha y hora de vencimiento</label>
                <input type="datetime-local" id="fechaVencimientoInput" value="${fechaActual}"
                    style="width:100%;padding:0.7rem;border:1px solid #d1d5db;border-radius:6px;font-size:1rem;">
            </div>
            <button class="btn" onclick="guardarConfiguracion()" style="background:#059669;">${ico('save')} Guardar</button>
        </div>
        <small style="color:#6b7280;display:block;margin-top:0.5rem;">
            ${ico('alert')} Este cambio afectará solo a los documentos que se aprueben a partir de ahora.
        </small>
    </div>
    <div style="background:#fffbeb;padding:1.5rem;border-radius:8px;border:2px solid #f59e0b;">
        <h4 style="color:#92400e;margin-bottom:0.5rem;">${ico('refresh')} Recalcular fechas de vencimiento existentes</h4>
        <p style="color:#78350f;font-size:0.9rem;margin-bottom:1rem;">
            Aplica la fecha fija configurada a todos los documentos <strong>aprobados y activos</strong> (no históricos).
            Esto asignará la misma fecha y hora a todos los documentos aprobados.
        </p>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
            <button class="btn btn-warning" onclick="recalcularVencimientos()" style="background:#d97706;color:white;">
                ${ico('refresh')} Aplicar a todos (fecha fija)
            </button>
            <small style="color:#6b7280;display:block;margin-top:0.5rem;">
                ${ico('alert')} Esta acción puede afectar a muchos documentos. Se recomienda hacer una copia de seguridad antes.
            </small>
        </div>
    </div>
    <div style="background:#f0f9ff;padding:1.5rem;border-radius:8px;margin-top:1.5rem;border:2px solid #0284c7;">
        <h4 style="color:#075985;margin-bottom:0.5rem;">${ico('save')} Backups de BD y documentos</h4>
        <p style="color:#6b7280;font-size:0.9rem;margin-bottom:1rem;">
            Copia automática cada 12 h (2 AM / 2 PM): base de datos completa + mirror de PDFs cifrados y plantillas.
            Crea, verifica, descarga (copia externa) o restaura sin usar consola.
        </p>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem;">
            <button class="btn" onclick="crearBackupAhora()" style="background:#0284c7;">${ico('plus')} Crear backup ahora</button>
            <button class="btn btn-secondary" onclick="cargarBackups()">${ico('refresh')} Actualizar lista</button>
        </div>
<div id="listaBackups"><p style="color:#6b7280;">Cargando…</p></div> </div>`;
aplicarGatingBotones(); //  R4: backups/acciones urgentes según permiso
}

// ==========================================
//  VENCIMIENTOS — LANZAMIENTO + POLLING DEL JOB (anti-congelamiento)
// ==========================================
async function lanzarJobVencimientos(url, etiqueta) {
    try {
        mostrarAlerta(`${ico('clock')} ${etiqueta}: iniciando en segundo plano...`, 'info');
        const res = await fetchAPI(url, { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (res.status === 409) { mostrarAlerta(' ' + (data.error || 'Ya hay un procesamiento en curso.'), 'warning'); return; }
        if (!res.ok) { mostrarAlerta(' ' + (data.error || 'Error al iniciar el proceso.'), 'error'); return; }
        await pollJobVencimientos(etiqueta);
    } catch (err) {
        console.error('Error lanzando job de vencimientos:', err);
        mostrarAlerta(' Error de conexión', 'error');
    }
}
async function pollJobVencimientos(etiqueta) {
    return new Promise(resolve => {
        const iv = setInterval(async () => {
            try {
                const r = await fetchAPI('/api/admin/vencimientos-job');
                const j = await r.json();
                const pct = j.total ? Math.round((j.procesados / j.total) * 100) : 0;
                console.log(`${ico('clock')} ${etiqueta}: ${j.procesados}/${j.total} (${pct}%) · movidos=${j.movidos} notificados=${j.notificados} errores=${j.errores}`);
                if (!j.enCurso) {
                    clearInterval(iv);
                    mostrarAlerta(`${ico('check')} ${etiqueta} completado: ${j.movidos} movidos, ${j.notificados} notificados, ${j.errores} errores`, 'success');
                    recargarConfiguracion();
                    recargarVistaActual();
                    resolve();
                }
            } catch (e) { /* se reintenta en el siguiente tick */ }
        }, 2500);
    });
}
async function ejecutarVencimientosAhora() {
    if (!await confirmarSwal({ titulo: ' Ejecutar vencimientos ahora', texto: 'Se moverán todos los documentos vencidos a histórico.', icono: 'question', peligro: false, textoConfirmar: 'Sí, ejecutar' })) return;
    await lanzarJobVencimientos('/api/admin/ejecutar-vencimientos', 'Procesamiento de vencimientos');
}
async function forzarVencimientosAhora() {
    if (!await confirmarSwal({ titulo: ' Reiniciar proceso', texto: 'Se eliminará la evaluación actual y los documentos volverán a pendiente.', icono: 'question', peligro: false, textoConfirmar: 'Sí, reiniciar' })) return;
    await lanzarJobVencimientos('/api/admin/forzar-vencimientos', 'Vencimiento forzado');
}

async function guardarConfiguracion() {
const input = document.getElementById('fechaVencimientoInput');
if (!input) return;
const fecha = input.value;
if (!fecha) { mostrarAlerta(' Debes seleccionar una fecha y hora', 'error'); return; }
const fechaSeleccionada = new Date(fecha);
const hoy = new Date();
if (fechaSeleccionada < hoy) {
mostrarAlerta(' La fecha de vencimiento no puede ser anterior a la fecha actual', 'warning');
if (!await confirmarSwal({ titulo: ' Fecha en el pasado', texto: 'La fecha elegida ya pasó. ¿Usarla de todos modos?', icono: 'question', textoConfirmar: 'Sí, usar' })) return;
}
const btn = document.querySelector('#configuracionContenido .btn');
const textoOriginal = btn.textContent;
btn.disabled = true; btn.textContent = ' Guardando...';
try {
const response = await fetchAPI('/api/admin/configuracion', {
method: 'PUT',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ valor: fecha })
});
const data = await response.json();
if (response.ok) { mostrarAlerta(`${ico('check')} ${data.mensaje}`, 'success'); await recargarConfiguracion(); }
else { mostrarAlerta(`${ico('x')} ${data.error || 'Error al guardar'}`, 'error'); }
} catch (err) {
console.error(' Error guardando configuración:', err);
mostrarAlerta(' Error de conexión', 'error');
} finally { btn.disabled = false; btn.textContent = textoOriginal; }
}

async function recalcularVencimientos() {
if (!await confirmarSwal({ titulo: ' Recalcular vencimientos', texto: 'Se aplicará la fecha fija configurada a TODOS los documentos aprobados y activos (no históricos).', textoConfirmar: 'Sí, recalcular' })) return;const btn = document.querySelector('#configuracionContenido .btn-warning');
if (!btn) return;
const textoOriginal = btn.textContent;
btn.disabled = true; btn.textContent = ' Procesando...';
try {
const response = await fetchAPI('/api/admin/recalcular-vencimientos', { method: 'POST' });
const data = await response.json();
if (response.ok) { mostrarAlerta(`${ico('check')} ${data.mensaje}`, 'success'); await recargarConfiguracion(); }
else { mostrarAlerta(`${ico('x')} ${data.error || 'Error al recalcular'}`, 'error'); }
} catch (err) {
console.error(' Error recalculando:', err);
mostrarAlerta(' Error de conexión', 'error');
} finally { btn.disabled = false; btn.textContent = textoOriginal; }
}

// ==========================================
//  BACKUPS (UI en Configuración)
// ==========================================
async function cargarBackups() {
const cont = document.getElementById('listaBackups');
if (!cont) return;
try {
const res = await fetchAPI('/api/admin/backups');
const data = await res.json();
const backups = data.backups || [];
if (!backups.length) { cont.innerHTML = '<p style="color:#6b7280;">Aún no hay backups en el volumen.</p>'; return; }
cont.innerHTML = `<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
<thead><tr style="background:#e0f2fe;border-bottom:2px solid #7dd3fc;">
<th style="padding:0.6rem;text-align:left;">Archivo</th>
<th style="padding:0.6rem;text-align:center;">Tamaño</th>
<th style="padding:0.6rem;text-align:center;">Acciones</th>
</tr></thead><tbody>` +
backups.map(b => `
<tr style="border-bottom:1px solid #e5e7eb;">
<td style="padding:0.6rem;"><strong>${escapeHtml(b.nombre)}</strong></td>
<td style="padding:0.6rem;text-align:center;">${(b.bytes / 1024 / 1024).toFixed(2)} MB</td>
<td style="padding:0.6rem;text-align:center;white-space:nowrap;">
<button class="btn btn-sm btn-secondary" onclick="verificarBackup('${escapeAttr(b.nombre)}')">${ico('search')} Verificar</button>
<a class="btn btn-sm btn-success" href="/api/admin/backups/${encodeURIComponent(b.nombre)}">${ico('download')} Descargar</a>
<button class="btn btn-sm btn-warning" onclick="restaurarBackup('${escapeAttr(b.nombre)}')"> Restaurar</button>
</td>
</tr>`).join('') + `</tbody></table></div>`;
} catch (err) {
console.error('Error cargando backups:', err);
cont.innerHTML = '<p style="color:#dc2626;">Error al cargar la lista de backups.</p>';
}
}
async function crearBackupAhora() {
if (!await confirmarSwal({ titulo: 'Crear backup manual', texto: 'Se respaldará la base de datos y los archivos ahora.', icono: 'question', peligro: false, textoConfirmar: 'Sí, crear backup' })) return;
mostrarAlerta(' Creando backup…', 'info');
try {
const res = await fetchAPI('/api/admin/backups/crear', { method: 'POST' });
const r = await res.json();
if (res.ok) { mostrarAlerta(' ' + (r.mensaje || 'Backup creado'), 'success'); await cargarBackups(); }
else mostrarAlerta(' ' + (r.error || 'Error al crear el backup'), 'error');
} catch (err) { mostrarAlerta(' Error de conexión', 'error'); }
}
async function verificarBackup(nombre) {
mostrarAlerta(' Verificando integridad de ' + nombre + '…', 'info');
try {
const res = await fetchAPI('/api/admin/backups/' + encodeURIComponent(nombre) + '/verificar');
const r = await res.json();
if (res.ok && r.integro) {
mostrarAlerta(`${ico('check')} ${nombre} ÍNTEGRO · usuarios: ${r.conteos.usuarios ?? '-'} · proveedores: ${r.conteos.proveedores ?? '-'} · documentos: ${r.conteos.documentos ?? '-'}`, 'success');
} else {
mostrarAlerta(' ' + (r.mensaje || 'Backup dañado'), 'error');
}
} catch (err) { mostrarAlerta(' Error al verificar: ' + err.message, 'error'); }
}
async function restaurarBackup(nombre) {
if (!await confirmarSwal({ titulo: `${ico('alert')} Restaurar "${nombre}"`, texto: 'Los datos ACTUALES se reemplazarán por los del backup. Se creará un snapshot de seguridad (pre_restore_*) antes de tocar nada.', textoConfirmar: 'Sí, restaurar' })) return;
if (!await confirmarSwal({ titulo: 'ÚLTIMA ADVERTENCIA', texto: 'El servicio se reiniciará tras restaurar.', textoConfirmar: 'Sí, continuar' })) return;
mostrarAlerta(' Restaurando… el servicio se reiniciará en unos segundos.', 'info');
try {
const res = await fetchAPI('/api/admin/backups/' + encodeURIComponent(nombre) + '/restaurar', { method: 'POST' });
const r = await res.json();
if (res.ok) { mostrarAlerta(' ' + (r.mensaje || 'Restauración completada.'), 'success'); setTimeout(() => location.reload(), 8000); }
else mostrarAlerta(' ' + (r.error || 'Error al restaurar'), 'error');
} catch (err) { setTimeout(() => location.reload(), 8000); }
}

// ==========================================
//  ELIMINAR DOCUMENTO (admin)
// ==========================================
async function eliminarDocumentoAdmin(docId, proveedorId) {
if (!docId) { mostrarAlerta(' ID de documento no válido', 'error'); return; }
if (!proveedorId) {
if (proveedorActualId) proveedorId = proveedorActualId;
else { mostrarAlerta(' No se pudo identificar al proveedor', 'error'); return; }
}
if (!await confirmarSwal({ titulo: '¿Eliminar este documento?', texto: 'El documento se eliminará de forma permanente.', textoConfirmar: 'Sí, eliminar' })) return;
try {
const res = await fetchAPI(`/api/admin/documento/${docId}`, { method: 'DELETE' });
if (res.ok) {
mostrarAlerta(' Documento eliminado', 'success');
await Promise.all([recargarVistaProveedor(), cargarProveedoresPorModulo(moduloActual, paginaActual)]);
} else {
const r = await res.json();
mostrarAlerta(`${ico('x')} ${r.error || 'Error al eliminar'}`);
}
} catch (err) {
console.error('Error eliminando documento:', err);
mostrarAlerta('Error al eliminar el documento');
}
}

// ==========================================
//  EVENTOS DE SUBIDA (admin)
// ==========================================
document.addEventListener('submit', async function(e) {
if (e.target.classList.contains('form-upload-admin')) {
if (adminFormSubmitted) return;
adminFormSubmitted = true;
e.preventDefault();
const form = e.target;
const fd = new FormData(form);
const tipo = form.dataset.tipo;
const proveedorId = form.dataset.proveedorid;

const checkboxNoAplica = form.closest('.doc-item').querySelector('.checkbox-no-aplica-admin');
if (checkboxNoAplica && checkboxNoAplica.checked) {
try {
const docId = checkboxNoAplica.dataset.docid;
const url = docId && docId !== ''
? `/api/admin/proveedor/${proveedorId}/documento/${docId}/no-aplica`
: `/api/admin/proveedor/${proveedorId}/documento/0/no-aplica`;
await fetchAPI(url, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ no_aplica: false, tipo: tipo })
});
} catch (err) {
console.error('Error desmarcando No Aplica:', err);
mostrarAlerta(' Error al desmarcar "No Aplica". Intenta de nuevo.', 'error');
adminFormSubmitted = false;
return;
}
}
fd.append('tipo', tipo);
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/documento`, { method: 'POST', body: fd });
const r = await res.json();
if (res.ok) {
mostrarAlerta(`${ico('check')} ${r.mensaje}`, 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else {
mostrarAlerta(`${ico('x')} ${r.error || 'Error desconocido'}`);
}
} catch (err) {
console.error('Error subiendo documento:', err);
mostrarAlerta(' Error al subir el documento: ' + err.message);
} finally {
setTimeout(() => { adminFormSubmitted = false; }, 500);
}
}
if (e.target.id && e.target.id.trim() === 'formEvaluacion') {
e.preventDefault();
const fd = new FormData(e.target);
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/evaluacion`, { method: 'POST', body: fd });
const r = await res.json();
if (res.ok) {
mostrarAlerta(' Evaluación subida correctamente', 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { mostrarAlerta(`${ico('x')} ${r.error}`); }
} catch (err) {
console.error('Error subiendo evaluación:', err);
mostrarAlerta('Error al subir evaluación');
}
}
if (e.target.id && e.target.id.trim() === 'formGestion') {
e.preventDefault();
const proveedorId = proveedorActualId;
const numero_registro = document.getElementById('numeroRegistro').value.trim();
const tipo_gestion = document.querySelector('input[name="tipoGestion"]:checked')?.value || 'inscripcion';
const notas_gestion = document.getElementById('observaciones').value.trim();
const tipo_proveedor = document.getElementById('tipoProveedor').value.trim();
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/gestion`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ numero_registro, tipo_gestion, notas_gestion, tipo_proveedor })
});
const r = await res.json();
if (res.ok) {
mostrarAlerta(' Gestión guardada correctamente', 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else {
mostrarAlerta(`${ico('x')} ${r.error}`);
if (r.ciclo_duplicado) {
const campo = document.getElementById('numeroRegistro');
if (campo) {
campo.focus();
campo.style.borderColor = '#dc2626';
campo.style.boxShadow = '0 0 0 3px rgba(220,38,38,.15)';
}
}
}
} catch (err) {
console.error('Error guardando gestión:', err);
mostrarAlerta(' Error al guardar la gestión');
}
}
});

// ==========================================
//  EVENTOS DE VERIFICACIÓN (checkbox)
// ==========================================
document.addEventListener('change', async function(e) {
if (e.target.classList.contains('checkbox-verificado')) {
const checkbox = e.target;
const docId = checkbox.dataset.docid;
const verificado = checkbox.checked;
checkbox.disabled = true;
try {
const res = await fetchAPI(`/api/admin/documento/${docId}/verificar`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ verificado })
});
if (res.ok) {
mostrarAlerta(` Documento ${verificado ? 'verificado' : 'desmarcado'} correctamente`, 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else {
const r = await res.json();
mostrarAlerta(`${ico('x')} ${r.error || 'Error al actualizar'}`);
checkbox.checked = !verificado;
}
} catch (err) {
console.error('Error:', err);
mostrarAlerta(' Error de conexión al actualizar verificación');
checkbox.checked = !verificado;
} finally { checkbox.disabled = false; }
}
if (e.target.classList.contains('checkbox-no-aplica-admin')) {
if (noAplicaChanged) return;
noAplicaChanged = true;
const checkbox = e.target;
const docId = checkbox.dataset.docid;
const tipo = checkbox.dataset.tipo;
const proveedorId = checkbox.dataset.proveedorid;
const noAplica = checkbox.checked;
try {
let url = docId && docId !== ''
? `/api/admin/proveedor/${proveedorId}/documento/${docId}/no-aplica`
: `/api/admin/proveedor/${proveedorId}/documento/0/no-aplica`;
const res = await fetchAPI(url, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ no_aplica: noAplica, tipo: tipo })
});
const r = await res.json();
if (res.ok) {
mostrarAlerta(noAplica ? ' Documento marcado como "No Aplica"' : ' Documento ahora requiere carga', 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else {
mostrarAlerta(`${ico('x')} ${r.error}`);
checkbox.checked = !noAplica;
}
} catch (err) {
console.error('Error:', err);
mostrarAlerta('Error al actualizar');
checkbox.checked = !noAplica;
} finally { setTimeout(() => { noAplicaChanged = false; }, 500); }
}
});

// ==========================================
//  FUNCIONES PARA EVALUACIÓN
// ==========================================
async function cambiarEstadoEvaluacion(proveedorId, estado) {
if (estado === 'rechazado') {
const motivo = await promptSwal({ titulo: 'Motivo del rechazo', texto: 'El proveedor recibirá este motivo por correo.', placeholder: 'Ej: La evaluación no cumple los requisitos…', obligatorio: true });
if (motivo === null) return;
await enviarEstadoEvaluacion(proveedorId, estado, motivo.trim());
} else {
if (!await confirmarSwal({ titulo: '¿Aprobar la evaluación inicial?', texto: 'El proveedor pasará a la etapa de Inscripción.', icono: 'question', peligro: false, textoConfirmar: 'Sí, aprobar' })) return;
await enviarEstadoEvaluacion(proveedorId, estado, '');
}
}
async function eliminarEvaluacion(proveedorId) {
if (!proveedorId) { mostrarAlerta(' ID de proveedor no válido', 'error'); return; }
if (!await confirmarSwal({ titulo: ' Eliminar Evaluación Inicial', texto: 'Esta acción no se puede deshacer.', textoConfirmar: 'Sí, eliminar' })) return;
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/evaluacion`, { method: 'DELETE' });
const r = await res.json();
if (res.ok) {
mostrarAlerta(' Evaluación inicial eliminada correctamente', 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { mostrarAlerta(`${ico('x')} ${r.error || 'Error al eliminar'}`, 'error'); }
} catch (err) {
console.error('Error eliminando evaluación:', err);
mostrarAlerta(' Error de conexión', 'error');
}
}
async function enviarEstadoEvaluacion(proveedorId, estado, comentario) {
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/evaluacion/estado`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ estado, comentario })
});
const r = await res.json();
if (res.ok) {
mostrarAlerta(`${ico('check')} Evaluación ${estado}`, 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { mostrarAlerta(`${ico('x')} ${r.error}`); }
} catch (err) {
console.error('Error cambiando estado evaluación:', err);
mostrarAlerta('Error al cambiar estado');
}
}
async function rechazarEvaluacion(proveedorId) {
if (!await confirmarSwal({ titulo: ' ADVERTENCIA', texto: 'Al rechazar la evaluación inicial, TODOS los documentos activos serán rechazados. El proveedor volverá a verificación (si es actualización) o pasará a rechazado (si es inscripción).', textoConfirmar: 'Sí, rechazar todo' })) return;
cambiarEstadoEvaluacion(proveedorId, 'rechazado');
}

// ==========================================
//  APROBAR / RECHAZAR DOCUMENTO
// ==========================================
async function cambiarEstado(docId, estado, comentario = null) {
if (estado === 'aprobado') {
const checkbox = document.querySelector(`.checkbox-verificado[data-docid="${docId}"]`);
if (checkbox && !checkbox.checked) {
mostrarAlerta(' Primero debes marcar el documento como "Verificado" antes de aprobarlo.', 'error');
return;
}
}
const res = await fetchAPI(`/api/admin/documento/${docId}/estado`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ estado, comentario })
});
if (res.ok) {
mostrarAlerta(`Documento ${estado}`, 'success');
await recargarVistaProveedor();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
await actualizarEstadisticasGlobales();
} else {
const r = await res.json();
mostrarAlerta(r.error || 'Error al cambiar estado');
}
}
//  C2: motivos institucionales predefinidos (estandariza rechazos del equipo)
const MOTIVOS_RECHAZO = [
  'Documento ilegible o borroso',
  'Falta firma o huella',
  'Documento vencido',
  'Formato incorrecto (no es la plantilla institucional)',
  'Documento no corresponde al tipo solicitado',
  'Información incompleta o inconsistente'
];
async function rechazar(docId) {
  // Paso 1: select de motivos predefinidos
  const opciones = { '': '— Selecciona un motivo —' };
  MOTIVOS_RECHAZO.forEach((m, i) => { opciones[String(i)] = m; });
  opciones['otro'] = ' Otro (escribir)…';
  const r1 = await Swal.fire({
    title: 'Motivo del rechazo',
    text: 'El proveedor lo verá en su portal y por correo.',
    icon: 'warning',
    input: 'select',
    inputOptions: opciones,
    showCancelButton: true,
    confirmButtonText: 'Continuar',
    cancelButtonText: 'Cancelar',
    confirmButtonColor: '#dc2626',
    cancelButtonColor: '#6b7280',
    reverseButtons: true,
    inputValidator: (v) => (v === '' || v === undefined || v === null) ? 'Debes seleccionar un motivo.' : null
  });
  if (!r1.isConfirmed) return;
  // Paso 2: si eligió "Otro", texto libre obligatorio (reusa promptSwal)
  let motivo;
  if (r1.value === 'otro') {
    const r2 = await promptSwal({
      titulo: 'Escribe el motivo',
      texto: 'Sé específico: el proveedor lo verá en su portal y por correo.',
      placeholder: 'Describe el motivo del rechazo…',
      obligatorio: true
    });
    if (r2 === null) return;
    motivo = r2.trim();
  } else {
    motivo = MOTIVOS_RECHAZO[parseInt(r1.value, 10)];
  }
  cambiarEstado(docId, 'rechazado', motivo);
}

// ==========================================
//  RECARGAR VISTA DEL PROVEEDOR (modal)
// ==========================================
async function recargarVistaProveedor() {
if (!proveedorActualId) { console.warn(' proveedorActualId no definido, no se puede recargar'); return; }
try {
const response = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}`);
if (!response.ok) {
const errorData = await response.json().catch(() => ({}));
mostrarAlerta(`${ico('x')} Error al recargar: ${errorData.error || 'Error desconocido'}`);
return;
}
const data = await response.json();
if (!data.proveedor) {
mostrarAlerta(' No se encontró información del proveedor. Puede que haya sido eliminado.');
cerrarModal();
return;
}
historicosCache = data.documentos_historicos || [];
documentosActivosCache = data.documentos || []; //  C1
//  Mantener los requerimientos del tipo de persona del proveedor
try {
const tipoProv = data.proveedor.tipo_proveedor === 'natural' ? 'natural' : 'juridica';
const rr = await fetchAPI(`/api/proveedor/requerimientos?tipo=${tipoProv}`);
if (rr.ok) {
const listaTipo = await rr.json();
if (listaTipo.length) requeridos = listaTipo;
}
} catch (e) { console.warn(' No se pudieron cargar requerimientos por tipo:', e); }
//  F2: invalidar flags lazy tras recarga; si hay una sub-pestaña dinámica
// VISIBLE en este momento, se refresca solo esa (no las cuatro).
resetSubTabFlags(proveedorActualId);
const badgeHistRecarga = document.getElementById('countHistoricos');
if (badgeHistRecarga) {
if (historicosCache.length) { badgeHistRecarga.textContent = historicosCache.length; badgeHistRecarga.style.display = 'inline-block'; }
else badgeHistRecarga.style.display = 'none';
}
const stabActiva = document.querySelector('[data-stab].active')?.dataset.stab;
if (stabActiva === 'historicos') { renderHistoricosProveedor(data.proveedor, historicosCache); marcarSubTab('historicos'); }
else if (stabActiva === 'notas') { cargarNotas(); marcarSubTab('notas'); }
else if (stabActiva === 'hist') { cargarHistorialProveedor(); marcarSubTab('hist'); }
else if (stabActiva === 'rec') { cargarRecordatoriosEnviados(); marcarSubTab('rec'); }
document.getElementById('modalTitulo').textContent = proveedorActualNombre;
const contenedorDinamico = document.getElementById('modalContenidoDinamico');
const subTabsContainer = document.getElementById('subTabsContainer');

if (moduloActual === 'registrados') {
subTabsContainer.style.display = 'block';
contenedorDinamico.innerHTML = '';
renderDocsCompleto(data.proveedor, data.documentos, historicosCache);
} else if (moduloActual === 'verificacion') {
subTabsContainer.style.display = 'block';
contenedorDinamico.innerHTML = '';
renderVerificacionCompleta(data.proveedor, data.documentos);
} else if (moduloActual === 'aprobacion') {
subTabsContainer.style.display = 'block';
contenedorDinamico.innerHTML = '';
renderAprobacionCompleta(data.proveedor, data.documentos);
} else if (moduloActual === 'inscripcion') {
subTabsContainer.style.display = 'block';
contenedorDinamico.innerHTML = '';
renderGestion(data.proveedor, data.documentos);
}
} catch (err) {
console.error('Error recargando vista:', err);
mostrarAlerta('Error al recargar la vista');
}
}

// ==========================================
//  C1: REVISIÓN ENFOCADA (un documento a la vez, PDF siempre visible)
// ==========================================
//  Construye la cola: pendientes reales + No aplica + opcionales sin documento
function construirColaRevision(modo) {
  const docs = documentosActivosCache || [];
const cola = docs
.filter(d => d.estado === 'pendiente' && (
modo === 'verificacion'
? (d.no_aplica === 1 || (d.no_aplica === 0 && d.verificado === 0 && d.archivo && d.archivo !== 'no_aplica'))
//  FIX: en Aprobación también entran los marcadores "No aplica" verificados,
// porque la lista normal los muestra con Aprobar y el medidor aprobados/total
// exige estado 'aprobado' para completar el cupo del tipo.
: (d.verificado === 1 && (d.no_aplica === 1 || (d.archivo && d.archivo !== 'no_aplica')))
))
.map(d => ({ ...d, esNoAplica: d.no_aplica === 1 }));
  // Requisitos opcionales sin ningún registro → permitir marcar No aplica desde el modo enfocado
  if (modo === 'verificacion') {
    (requeridos || []).forEach(r => {
      if (!r.opcional) return;
      if (!docs.some(d => d.tipo === r.tipo)) {
        cola.push({ id: 0, tipo: r.tipo, nombre: r.nombre, sinDocumento: true, estado: 'pendiente', verificado: 0, no_aplica: 0 });
      }
    });
  }
  return cola;
}
function iniciarRevisionEnfocada(modo) {
  const cola = construirColaRevision(modo);
  if (!cola.length) {
    mostrarAlerta(modo === 'verificacion'
      ? ' No hay documentos pendientes por verificar ni opcionales por definir en este proveedor.'
      : ' No hay documentos verificados pendientes de aprobación.', 'info');
    return;
  }
  revisionEnfocada = { activa: true, modo, cola, indice: 0 };
  montarOverlayRevision();
  pintarRevisionActual();
}
function montarOverlayRevision() {
  let ov = document.getElementById('modalRevisionEnfocada');
  if (ov) ov.remove();
  ov = document.createElement('div');
  ov.className = 'modal-overlay active';
  ov.id = 'modalRevisionEnfocada';
  ov.style.zIndex = '9600';
  ov.innerHTML = `
  <div class="modal" style="max-width:96%;width:1250px;height:94vh;padding:0.8rem;display:flex;flex-direction:column;gap:0.6rem;">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.8rem;flex-wrap:wrap;">
      <h3 style="margin:0;font-size:1.05rem;" id="revTitulo">Documento</h3>
      <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
        <span id="revContador" class="badge-count"></span>
        <button class="btn btn-sm btn-secondary" onclick="cerrarRevisionEnfocada()"> Cerrar</button>
      </div>
    </div>
    <div id="revMeta" style="font-size:0.85rem;color:#6b7280;"></div>
    <div style="flex:1;min-height:0;background:#525659;border-radius:8px;overflow:hidden;position:relative;">
      <iframe id="revIframe" style="width:100%;height:100%;border:none;display:block;"></iframe>
      <div id="revPlaceholder" style="display:none;position:absolute;inset:0;background:#f9fafb;color:#374151;align-items:center;justify-content:center;flex-direction:column;gap:0.6rem;text-align:center;padding:2rem;font-size:0.95rem;"></div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.6rem;flex-wrap:wrap;">
      <div style="display:flex;gap:0.5rem;">
        <button class="btn btn-sm btn-secondary" onclick="navegarRevision(-1)">← Anterior</button>
        <button class="btn btn-sm btn-secondary" onclick="navegarRevision(1)">Saltar →</button>
      </div>
      <div id="revAcciones" style="display:flex;gap:0.5rem;flex-wrap:wrap;"></div>
    </div>
    <small style="color:#9ca3af;">Atajos: ← anterior · → saltar · V verificar/aprobar · R rechazar · Esc cerrar</small>
  </div>`;
  document.body.appendChild(ov);
}
function pintarRevisionActual() {
  const r = revisionEnfocada;
  if (!r.activa) return;
  if (!r.cola.length || r.indice >= r.cola.length) { finalizarRevisionEnfocada(true); return; }
  const doc = r.cola[r.indice];
  const titulo = document.getElementById('revTitulo');
  const contador = document.getElementById('revContador');
  const meta = document.getElementById('revMeta');
  const iframe = document.getElementById('revIframe');
  const placeholder = document.getElementById('revPlaceholder');
  const acciones = document.getElementById('revAcciones');
  const tieneArchivo = !doc.sinDocumento && doc.archivo && doc.archivo !== 'no_aplica';
  if (titulo) titulo.textContent = `${proveedorActualNombre} — ${nombreFormato(doc.tipo)}`;
  if (contador) contador.textContent = `Elemento ${r.indice + 1} de ${r.cola.length}`;
  if (meta) {
    meta.innerHTML = doc.esNoAplica
      ? `${ico('file-text')} <strong>NO APLICA</strong> · ${escapeHtml((doc.comentario || 'Marcado sin archivo').replace('No aplica - ', ''))}`
      : doc.sinDocumento
        ? ` <strong>Sin documento</strong> · requisito opcional aún sin cargar`
        : `Estado: <strong>${doc.estado}</strong> · ${doc.verificado === 1 ? ' Verificado' : ' Sin verificar'} · Subido: ${formatearFecha(doc.subido_en)}`;
  }
  if (tieneArchivo) {
    if (iframe) { iframe.style.display = 'block'; iframe.src = `/uploads/${doc.archivo}`; }
    if (placeholder) placeholder.style.display = 'none';
  } else {
    if (iframe) { iframe.style.display = 'none'; iframe.src = 'about:blank'; }
    if (placeholder) {
      placeholder.style.display = 'flex';
      placeholder.innerHTML = doc.esNoAplica
        ? `<div style="font-size:2.2rem;">${ico('file-text')}</div><strong>Documento marcado como NO APLICA</strong><small style="color:#6b7280;">Confirma el marcado o desmárcalo para exigir la carga del PDF.</small>`
        : `<div style="font-size:2.2rem;"></div><strong>Requisito opcional sin documento</strong><small style="color:#6b7280;">Puedes marcarlo como NO APLICA o dejarlo pendiente de carga.</small>`;
    }
  }
if (acciones) {
if (doc.esNoAplica && r.modo === 'verificacion') {
acciones.innerHTML = `
<button class="btn btn-sm btn-secondary" onclick="accionRevision('desmarcar_noaplica')"> Desmarcar No aplica</button>
<button class="btn btn-sm btn-success" onclick="accionRevision('principal')">${ico('check')} Confirmar No aplica y seguir</button>`;
} else if (doc.esNoAplica && r.modo === 'aprobacion') {
//  FIX: en Aprobación el marcador No aplica se aprueba/rechaza como en la lista normal
acciones.innerHTML = `
<button class="btn btn-sm btn-danger" onclick="accionRevision('rechazar')">${ico('x')} Rechazar</button>
<button class="btn btn-sm btn-success" onclick="accionRevision('principal')">${ico('check')} Aprobar y siguiente</button>`;
} else if (doc.sinDocumento) {
      acciones.innerHTML = `
        <button class="btn btn-sm" style="background:#0284c7;" onclick="accionRevision('marcar_noaplica')">${ico('file-text')} Marcar No aplica</button>
        <button class="btn btn-sm btn-secondary" onclick="navegarRevision(1)"> Dejar pendiente y seguir</button>`;
    } else {
      acciones.innerHTML = `
        <button class="btn btn-sm btn-danger" onclick="accionRevision('rechazar')">${ico('x')} Rechazar</button>
        <button class="btn btn-sm btn-success" onclick="accionRevision('principal')">${r.modo === 'verificacion' ? ' Verificar y siguiente' : ' Aprobar y siguiente'}</button>`;
    }
  }
}
function navegarRevision(delta) {
  const r = revisionEnfocada;
  if (!r.activa) return;
  const nuevo = r.indice + delta;
  if (nuevo < 0) return;
  if (nuevo >= r.cola.length) { finalizarRevisionEnfocada(false); return; }
  r.indice = nuevo;
  pintarRevisionActual();
}
async function accionRevision(accion) {
  const r = revisionEnfocada;
  if (!r.activa) return;
  const doc = r.cola[r.indice];
  if (!doc) return;
  try {
//  NO APLICA en VERIFICACIÓN: confirmar el marcado no toca servidor, solo avanza
if (accion === 'principal' && doc.esNoAplica && r.modo === 'verificacion') {
r.cola.splice(r.indice, 1);
if (r.indice >= r.cola.length) r.indice = Math.max(0, r.cola.length - 1);
pintarRevisionActual();
return;
}
//  FIX: NO APLICA en APROBACIÓN: se aprueba por servidor (igual que el botón Aprobar de la lista)
if (accion === 'principal' && doc.esNoAplica && r.modo === 'aprobacion') {
const res = await fetchAPI(`/api/admin/documento/${doc.id}/estado`, {
method: 'POST', headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ estado: 'aprobado' })
});
if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al aprobar'), 'error'); return; }
mostrarAlerta(' No aplica aprobado', 'success');
r.cola.splice(r.indice, 1);
if (r.indice >= r.cola.length) r.indice = Math.max(0, r.cola.length - 1);
pintarRevisionActual();
return;
}
    //  Desmarcar No aplica → el documento vuelve a requerir carga
    if (accion === 'desmarcar_noaplica') {
      const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/documento/${doc.id}/no-aplica`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ no_aplica: false, tipo: doc.tipo })
      });
      if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al desmarcar'), 'error'); return; }
      mostrarAlerta(' No aplica desmarcado: el documento vuelve a requerir carga', 'success');
      await refrescarColaRevision();
      return;
    }
    //  Marcar No aplica sobre un requisito opcional sin documento
    if (accion === 'marcar_noaplica') {
      const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/documento/0/no-aplica`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ no_aplica: true, tipo: doc.tipo })
      });
      if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al marcar'), 'error'); return; }
      mostrarAlerta(' Documento marcado como No aplica', 'success');
      await refrescarColaRevision();
      return;
    }
    if (accion === 'rechazar') {
      if (doc.sinDocumento) { //  FIX: los marcadores No aplica SÍ pueden rechazarse (como en la lista normal)
        mostrarAlerta(' Este elemento no tiene archivo para rechazar. Usa Desmarcar o Marcar No aplica.', 'warning');
        return;
      }
      const motivo = await promptSwal({ titulo: 'Motivo del rechazo', texto: 'El proveedor verá este motivo en su portal y por correo.', placeholder: 'Ej: Documento ilegible…', obligatorio: false });
      if (motivo === null) return;
      const res = await fetchAPI(`/api/admin/documento/${doc.id}/estado`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ estado: 'rechazado', comentario: motivo }) });
      if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al rechazar'), 'error'); return; }
      mostrarAlerta(' Documento rechazado', 'success');
    } else if (r.modo === 'verificacion') {
      const res = await fetchAPI(`/api/admin/documento/${doc.id}/verificar`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ verificado: true }) });
      if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al verificar'), 'error'); return; }
      mostrarAlerta(' Documento verificado', 'success');
    } else {
      const res = await fetchAPI(`/api/admin/documento/${doc.id}/estado`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ estado: 'aprobado' }) });
      if (!res.ok) { const e = await res.json(); mostrarAlerta(' ' + (e.error || 'Error al aprobar'), 'error'); return; }
      mostrarAlerta(' Documento aprobado', 'success');
    }
    r.cola.splice(r.indice, 1);
    if (r.indice >= r.cola.length) r.indice = Math.max(0, r.cola.length - 1);
    pintarRevisionActual();
  } catch (err) {
    console.error('Error en revisión enfocada:', err);
    mostrarAlerta(' Error de conexión', 'error');
  }
}
//  Reconstruye la cola desde la caché fresca tras marcar/desmarcar No aplica
async function refrescarColaRevision() {
  const modo = revisionEnfocada.modo;
  const idx = revisionEnfocada.indice;
  await recargarVistaProveedor();
  const cola = construirColaRevision(modo);
  if (!cola.length) {
    cerrarRevisionEnfocada();
    mostrarAlerta(' Revisión enfocada completada: no quedan elementos en la cola.', 'success');
    return;
  }
  revisionEnfocada.cola = cola;
  revisionEnfocada.indice = Math.min(idx, cola.length - 1);
  pintarRevisionActual();
}
function finalizarRevisionEnfocada(completada) {
  const ov = document.getElementById('modalRevisionEnfocada');
  if (ov) ov.remove();
  revisionEnfocada.activa = false;
  mostrarAlerta(completada ? ' Revisión enfocada completada: no quedan documentos en la cola.' : ' Sesión de revisión finalizada.', completada ? 'success' : 'info');
  recargarVistaProveedor();
  cargarProveedoresPorModulo(moduloActual, paginaActual);
  actualizarEstadisticasGlobales();
}
function cerrarRevisionEnfocada() {
  const iframe = document.getElementById('revIframe');
  if (iframe) iframe.src = 'about:blank';
  finalizarRevisionEnfocada(false);
}
// ==========================================
//  VISOR DE DOCUMENTOS
// ==========================================
function verDocumento(url, nombre) {
document.getElementById('modalVisor').style.zIndex = '9000';
document.getElementById('visorTitulo').textContent = nombre;
document.getElementById('visorDescargar').href = url + '?download=true';
document.getElementById('visorDescargar').setAttribute('download', /\.pdf$/i.test(nombre) ? nombre : nombre + '.pdf');
document.getElementById('visorNuevaPestana').href = url;
const iframe = document.getElementById('visorIframe');
const cargando = document.getElementById('visorCargando');
iframe.style.display = 'none';
cargando.style.display = 'block';
iframe.src = url;
iframe.onload = () => { cargando.style.display = 'none'; iframe.style.display = 'block'; };
setTimeout(() => { iframe.onload = () => { cargando.style.display = 'none'; iframe.style.display = 'block'; }; }, 8000);
document.getElementById('modalVisor').classList.add('active');
}
function cerrarVisor() {
document.getElementById('visorIframe').src = 'about:blank';
document.getElementById('modalVisor').classList.remove('active');
document.getElementById('modalVisor').classList.remove('visor-fullscreen'); //  E4: cerrar restaura el tamaño
}
// ==========================================
//  E4 (REDEFINIDO): EXPANDIR VISOR A PANTALLA COMPLETA
// Decisión de diseño: el zoom y la rotación REALES los aporta el visor
// nativo del navegador dentro del iframe (PDFium). Lo que el nativo NO
// puede hacer es agrandar el modal que lo contiene. Este toggle lleva
// el modal a ~100vw/100vh para que el PDF trabaje con toda el área.
// ==========================================
function toggleVisorPantallaCompleta() {
const m = document.getElementById('modalVisor');
if (!m) return;
m.classList.toggle('visor-fullscreen');
}

// ==========================================
//  NOTAS (para sub-tabs)
// ==========================================
async function cargarNotas() {
if (!proveedorActualId) return;
const notas = await (await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/notas`)).json();
const cont = document.getElementById('listaNotas');
if (!notas.length) { cont.innerHTML = '<small style="color:#9ca3af;">Sin notas.</small>'; return; }
cont.innerHTML = '';
//  F7: DocumentFragment = un solo reflow al final en vez de uno por nota
const fragNotas = document.createDocumentFragment();
notas.forEach(n => {
const div = document.createElement('div');
div.className = 'nota-item';
const header = document.createElement('div');
header.className = 'nota-header';
const strong = document.createElement('strong');
strong.textContent = ` ${n.titulo}`;
header.appendChild(strong);
const small = document.createElement('small');
small.textContent = `${ico('clock')} ${formatearFecha(n.creado_en)} ·  ${n.admin_nombre}`;
header.appendChild(small);
div.appendChild(header);
const body = document.createElement('div');
body.className = 'nota-body';
body.textContent = n.nota;
div.appendChild(body);
fragNotas.appendChild(div);
});
cont.appendChild(fragNotas);
}
async function guardarNota() {
const titulo = document.getElementById('tituloNota').value.trim();
const nota = document.getElementById('detalleNota').value.trim();
if (!nota) { mostrarAlerta('Escribe el detalle'); return; }
const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/nota`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ titulo: titulo || 'Nota', nota })
});
if (res.ok) {
mostrarAlerta(' Nota guardada', 'success');
document.getElementById('tituloNota').value = '';
document.getElementById('detalleNota').value = '';
await cargarNotas();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { const r = await res.json(); mostrarAlerta(r.error); }
}

// ==========================================
//  HISTORIAL (para sub-tabs)
// ==========================================
async function cargarHistorialProveedor() {
if (!proveedorActualId) return;
const hist = await (await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/historial`)).json();
const cont = document.getElementById('modalHistorial');
if (!hist.length) { cont.innerHTML = '<div class="historial-vacio"> Sin actividad.</div>'; return; }
cont.innerHTML = '<h4 style="margin-bottom:0.8rem;">Historial completo</h4>' + hist.map(h => {
const iconos = {
registro: ico('award'), documento_subido: ico('upload'), documento_reemplazado: ico('refresh'),
documento_eliminado: ico('trash'), documento_aprobado: ico('check'), documento_rechazado: ico('x'),
datos_actualizados: ico('edit'), recordatorio_enviado: ico('send'), nota_agregada: ico('message'),
documento_no_aplica: ico('clipboard'), documento_requiere_carga: ico('file'), gestion_actualizada: ico('clipboard'),
cambio_etapa: ico('refresh'), evaluacion_subida: ico('file'), evaluacion_estado_cambiado: ico('clipboard'),
solicitud_actualizacion: ico('refresh'), vencimiento_automatico: ico('clock'), vencimiento_forzado: ico('zap'),
reinicio_automatico: ico('refresh'),tipo_persona_definido: ico('file-text')
};
const clases = {
documento_subido: 'subida', documento_reemplazado: 'subida',
documento_aprobado: 'aprobado', documento_rechazado: 'rechazado',
documento_eliminado: 'eliminado', datos_actualizados: 'datos',
recordatorio_enviado: 'recordatorio', nota_agregada: 'recordatorio',
registro: 'registro', documento_no_aplica: 'aprobado', documento_requiere_carga: 'datos',
gestion_actualizada: 'datos', cambio_etapa: 'datos',
evaluacion_subida: 'subida', evaluacion_estado_cambiado: 'datos',
solicitud_actualizacion: 'recordatorio', vencimiento_automatico: 'rechazado',
vencimiento_forzado: 'rechazado', reinicio_automatico: 'subida',tipo_persona_definido: 'datos'
};
return `
<div class="historial-item">
<div class="historial-icono ${clases[h.accion] || 'datos'}">${iconos[h.accion] || ico('pin')}</div>
<div class="historial-contenido">
<div class="detalle">${h.detalle}</div>
<div class="meta"><span>${ico('clock')} ${formatearFecha(h.creado_en)}</span><span class="usuario"> ${escapeHtml(h.usuario_nombre)}</span></div>
</div>
</div>
`;
}).join('');
}

// ==========================================
//  RECORDATORIOS (para sub-tabs)
// ==========================================
async function cargarRecordatoriosEnviados() {
if (!proveedorActualId) return;
const hist = await (await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/historial`)).json();
const recs = hist.filter(h => h.accion === 'recordatorio_enviado');
const cont = document.getElementById('listaRecordatoriosEnviados');
if (!recs.length) { cont.innerHTML = '<small style="color:#9ca3af;">Sin recordatorios.</small>'; return; }
cont.innerHTML = recs.map(r => `
<div class="historial-item">
<div class="historial-icono recordatorio">${ico('send')}</div>
<div class="historial-contenido">
<div class="detalle">${r.detalle.replace('Recordatorio enviado: ', '')}</div>
<div class="meta"><span>${ico('clock')} ${formatearFecha(r.creado_en)}</span></div>
</div>
</div>
`).join('');
}
async function enviarRecordatorio() {
const msg = document.getElementById('mensajeRecordatorio').value.trim();
if (!msg) { mostrarAlerta('Escribe un mensaje'); return; }
const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}/recordatorio`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mensaje: msg })
});
if (res.ok) {
mostrarAlerta(' Recordatorio enviado', 'success');
document.getElementById('mensajeRecordatorio').value = '';
await cargarRecordatoriosEnviados();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { const r = await res.json(); mostrarAlerta(r.error); }
}

// ==========================================
//  C3: RECORDATORIO MASIVO A INACTIVOS
// ==========================================
async function recordarInactivos() {
if (!await confirmarSwal({ titulo: ' Recordar a proveedores inactivos', texto: 'Se enviará un recordatorio por correo y en el portal a todos los proveedores con más de 7 días sin subir documentos (máx. 1 por día por proveedor).', peligro: false, textoConfirmar: 'Sí, enviar' })) return;
try {
const res = await fetchAPI('/api/admin/recordatorio-inactivos', { method: 'POST' });
const r = await res.json();
if (res.ok) mostrarAlerta(`${ico('check')} Recordatorios enviados: ${r.enviados}${r.omitidos ? ` · omitidos (ya recordados hoy): ${r.omitidos}` : ''}`, 'success');
else mostrarAlerta(' ' + (r.error || 'Error al enviar'), 'error');
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} catch (err) {
console.error('Error recordatorio masivo:', err);
mostrarAlerta(' Error de conexión', 'error');
}
}

// ==========================================
//  ELIMINAR PROVEEDOR
// ==========================================
function mostrarConfirmacionEliminar() {
document.getElementById('nombreProveedorEliminar').textContent = proveedorActualNombre;
document.getElementById('textoConfirmacion').value = '';
document.getElementById('passwordConfirmacion').value = '';
document.getElementById('alertaEliminar').innerHTML = '';
document.getElementById('modalConfirmarEliminar').classList.add('active');
}
function cerrarConfirmacionEliminar() {
document.getElementById('modalConfirmarEliminar').classList.remove('active');
}
async function ejecutarEliminacion() {
const texto = document.getElementById('textoConfirmacion').value.trim();
const password = document.getElementById('passwordConfirmacion').value;
const alertaEl = document.getElementById('alertaEliminar');
if (texto !== 'ELIMINAR') {
alertaEl.innerHTML = '<div class="alert alert-error">Debes escribir exactamente "ELIMINAR" para confirmar</div>';
return;
}
if (!password) {
alertaEl.innerHTML = '<div class="alert alert-error">Debes ingresar tu contraseña de administrador</div>';
return;
}
if (!await confirmarSwal({ titulo: ' ÚLTIMA ADVERTENCIA', texto: `¿Estás 100% seguro de eliminar a "${proveedorActualNombre}"? Esta acción es PERMANENTE y NO se puede deshacer.`, textoConfirmar: 'Sí, eliminar definitivamente' })) return;
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorActualId}`, {
method: 'DELETE',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ password })
});
const r = await res.json();
if (res.ok) {
alertaEl.innerHTML = `<div class="alert alert-success">${ico('check')} ${r.mensaje}</div>`;
setTimeout(() => {
cerrarConfirmacionEliminar();
cerrarModal();
cargarProveedoresPorModulo(moduloActual, 1);
mostrarAlerta('Proveedor eliminado correctamente', 'success');
}, 1500);
} else {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} ${r.error}</div>`;
}
} catch (err) {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${err.message}</div>`;
}
}
function cerrarModal() {
document.getElementById('modal').classList.remove('active');
requeridos = requeridosDefault.slice(); //  restaurar lista base
proveedorActualId = null;
proveedorActualNombre = '';
historicosCache = [];
const countBadge = document.getElementById('countHistoricos');
if (countBadge) countBadge.style.display = 'none';
}

// ==========================================
//  DESCARGAR ZIP
// ==========================================
async function descargarZIP(proveedorId) {
try {
mostrarAlerta(' Generando archivo ZIP... Esto puede tomar unos segundos.', 'info');
const response = await fetchAPI(`/api/admin/proveedor/${proveedorId}/documentos/zip`);
if (!response.ok) {
const errorData = await response.json().catch(() => ({}));
throw new Error(errorData.error || 'Error al generar el ZIP');
}
const blob = await response.blob();
const contentDisposition = response.headers.get('Content-Disposition');
let filename = `proveedor_${proveedorId}_documentos.zip`;
if (contentDisposition) {
const match = contentDisposition.match(/filename="(.+)"/);
if (match) filename = decodeURIComponent(match[1]);
}
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url; a.download = filename;
document.body.appendChild(a); a.click(); document.body.removeChild(a);
window.URL.revokeObjectURL(url);
mostrarAlerta(' ZIP descargado correctamente', 'success');
} catch (err) {
console.error(' Error descargando ZIP:', err);
mostrarAlerta(' Error al descargar: ' + err.message);
}
}
async function reiniciarProceso(proveedorId) {
if (!await confirmarSwal({ titulo: ' Reiniciar proceso', texto: 'Se eliminará la evaluación actual y los documentos volverán a pendiente.', icono: 'question', peligro: false, textoConfirmar: 'Sí, reiniciar' })) return;
try {
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/reiniciar-proceso`, { method: 'POST' });
const data = await res.json();
if (res.ok) {
mostrarAlerta(' Proceso reiniciado. El proveedor vuelve a verificación.', 'success');
cerrarModal();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
} else { mostrarAlerta(' ' + (data.error || 'Error al reiniciar el proceso')); }
} catch (err) {
console.error('Error reiniciando:', err);
mostrarAlerta(' Error de conexión al reiniciar el proceso');
}
}

//  A1: abre el modal de actualización leyendo los datos desde data-attributes
// (evita inyectar el nombre del proveedor dentro del onclick → previene XSS).
function abrirSolicitudActualizacion(btn) {
  mostrarModalSolicitarActualizacion(parseInt(btn.dataset.id, 10), btn.dataset.nombre);
}

// ==========================================
//  SOLICITAR ACTUALIZACIÓN ANUAL (modal solo con mensaje)
// ==========================================
function mostrarModalSolicitarActualizacion(proveedorId, nombreProveedor) {
const previo = document.getElementById('modalSolicitarActualizacion');
if (previo) previo.remove();
const overlay = document.createElement('div');
overlay.className = 'modal-overlay active';
overlay.id = 'modalSolicitarActualizacion';
overlay.style.zIndex = '9500';
overlay.innerHTML = `
<div class="modal" style="max-width:540px;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
<h3 style="margin:0;">${ico('refresh')} Solicitar actualización de documentos</h3>
<button class="btn btn-sm btn-secondary" onclick="cerrarModalSolicitarActualizacion()"> Cerrar</button>
</div>
<p style="color:#374151;margin-bottom:0.8rem;">
Vas a solicitar la actualización anual a <strong>${escapeHtml(nombreProveedor)}</strong>.
</p>
<div class="alert alert-info" style="margin-bottom:1rem;">
<strong>Esto hará que:</strong><br>
• Los documentos actuales se archiven en el histórico<br>
• El proveedor vuelva a la etapa de Verificación<br>
• Se le envíe un correo y un recordatorio<br>
• <strong>El proveedor deberá definir su tipo de persona (Natural/Jurídica) al ingresar al portal</strong>
</div>
<div class="form-group">
<label> Mensaje para el proveedor (opcional)</label>
<textarea id="mensajeActualizacion" rows="3" placeholder="Ej: Por favor actualiza tus documentos para el nuevo período..."></textarea>
</div>
<div style="display:flex;gap:0.5rem;margin-top:1rem;">
<button class="btn btn-secondary" onclick="cerrarModalSolicitarActualizacion()" style="flex:1;">Cancelar</button>
<button class="btn" onclick="confirmarSolicitarActualizacion(${proveedorId})" style="flex:1;background:#2563eb;">${ico('refresh')} Confirmar solicitud</button>
</div>
</div>
`;
document.body.appendChild(overlay);
overlay.addEventListener('click', (e) => { if (e.target === overlay) cerrarModalSolicitarActualizacion(); });
}
function cerrarModalSolicitarActualizacion() {
const modal = document.getElementById('modalSolicitarActualizacion');
if (modal) modal.remove();
}
async function confirmarSolicitarActualizacion(proveedorId) {
const mensaje = document.getElementById('mensajeActualizacion')?.value?.trim() || '';
try {
mostrarAlerta(' Enviando solicitud de actualización...', 'info');
const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/solicitar-actualizacion`, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mensaje })
});
const data = await res.json();
if (res.ok) {
mostrarAlerta(' ' + data.mensaje, 'success', 6000);
cerrarModalSolicitarActualizacion();
cerrarModal();
await cargarProveedoresPorModulo(moduloActual, paginaActual);
await actualizarEstadisticasGlobales();
} else {
mostrarAlerta(' ' + (data.error || 'Error al solicitar la actualización'));
}
} catch (err) {
console.error('Error solicitando actualización:', err);
mostrarAlerta(' Error de conexión al solicitar la actualización');
}
}

// ==========================================
//  EXPORTAR CSV
// ==========================================
async function exportarCSV() {
try {
const busqueda = document.getElementById('buscador')?.value?.trim() || '';
const estado = filtroEstadoActual || 'todos';
let url = `/api/admin/proveedores/export?estado=${estado}&modulo=${moduloActual}`;
if (busqueda) url += `&busqueda=${encodeURIComponent(busqueda)}`;
const response = await fetchAPI(url);
if (!response.ok) {
const err = await response.json();
throw new Error(err.error || 'Error al exportar');
}
const result = await response.json();
const proveedores = result.data || [];
if (!proveedores.length) { mostrarAlerta('No hay proveedores para exportar con los filtros actuales', 'info'); return; }

const headers = ['Razón Social', 'NIT/RUT', 'Correo', 'Teléfono', 'Representante Legal', 'Dirección', 'Estado', 'Fecha Aprobación', 'Fecha Movimiento', 'Tipo Gestión', 'Tipo Proveedor', 'Nota'];
const filas = proveedores.map(p => [
p.razon_social || p.nombre_empresa || '', p.rfc || '', p.email || '', p.telefono || '',
p.representante || '', (p.direccion || '').replace(/[\n\r]+/g, ' '),
estadoLegible(p),
p.fecha_aprobacion ? formatearFecha(p.fecha_aprobacion) : 'Pendiente',
p.numero_registro || '', p.tipo_gestion || '', p.tipo_proveedor || '', p.notas_gestion || ''
]);
const csv = '\uFEFF' + [headers.join(';'), ...filas.map(f => f.map(celdaCSV).join(';'))].join('\n');
const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
descargarBlob(blob, `proveedores_${fechaArchivo()}.csv`);
mostrarAlerta(` CSV exportado (${proveedores.length} proveedores)`, 'success');
} catch (err) {
console.error('Error exportando CSV:', err);
mostrarAlerta(' Error al exportar: ' + err.message);
}
}

// ==========================================
//  EXPORTAR EXCEL
// ==========================================
async function exportarExcel() {
try {
const busqueda = document.getElementById('buscador')?.value?.trim() || '';
const estado = filtroEstadoActual || 'todos';
let url = `/api/admin/proveedores/export?estado=${estado}&modulo=${moduloActual}`;
if (busqueda) url += `&busqueda=${encodeURIComponent(busqueda)}`;
const response = await fetchAPI(url);
if (!response.ok) {
const err = await response.json();
throw new Error(err.error || 'Error al exportar');
}
const result = await response.json();
const proveedores = result.data || [];
if (!proveedores.length) { mostrarAlerta('No hay proveedores para exportar con los filtros actuales', 'info'); return; }

const res = await fetchAPI('/api/admin/exportar-excel', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ proveedores })
});
if (!res.ok) {
const err = await res.json();
throw new Error(err.error || 'Error al generar Excel');
}
const blob = await res.blob();
descargarBlob(blob, `proveedores_${fechaArchivo()}.xlsx`);
mostrarAlerta(` Excel exportado (${proveedores.length} proveedores)`, 'success');
} catch (err) {
console.error('Error exportando Excel:', err);
mostrarAlerta(' Error al exportar: ' + err.message);
}
}

function toggleExportDropdown() {
const d = document.getElementById('exportDropdown');
if (d) d.style.display = d.style.display === 'block' ? 'none' : 'block';
}

// ==========================================
//  G11: TELÉFONO COLOMBIA (máscara 3-3-4 + validación en vivo)
// ==========================================
//  F8: TEL_CO_RE / normalizarDigitosCO / formatearTelefonoCO / validarTelefonoCO → /js/utils.js
function conectarMascaraTelefono(input) {
if (!input) return;
let hint = document.getElementById(input.id + '_hint') || input.closest('.form-group')?.querySelector('.tel-hint-g11');
if (!hint) {
hint = document.createElement('small');
hint.className = 'tel-hint-g11';
hint.id = 'telCrearHint';
hint.style.cssText = 'display:block;margin-top:0.3rem;font-size:0.78rem;color:#6b7280;';
const grp = input.closest('.form-group');
if (grp) grp.appendChild(hint);
}
const pintar = () => {
const r = validarTelefonoCO(input.value);
hint.textContent = input.value ? r.mensaje : 'Ej: 310 123 4567 · 601 123 4567';
hint.style.color = !input.value ? '#6b7280' : (r.valido ? '#059669' : '#dc2626');
input.dataset.telOk = r.valido ? '1' : '0';
};
input.addEventListener('input', () => {
input.value = formatearTelefonoCO(input.value);
pintar();
});
input.addEventListener('blur', pintar);
pintar();
}
conectarMascaraTelefono(document.querySelector('#formCrearProveedor input[name="telefono"]'));
// ==========================================
//  G7: TIPO DE DOCUMENTO (cliente) — espejo exacto del server
// ==========================================
//  F8: TIPOS_DOCUMENTO_CO / normalizarNumeroDocumento / validarDocumentoCO → /js/utils.js
function labelTipoDoc(p) {
const map = { nit: 'NIT', cc: 'C.C.', ce: 'C.E.', pas: 'Pasaporte' };
return map[(p && p.tipo_documento) || 'nit'] || 'NIT';
}
(function conectarValidacionDocCrear() {
const form = document.getElementById('formCrearProveedor');
if (!form) return;
const sel = form.querySelector('select[name="tipo_documento"]');
const inp = form.querySelector('input[name="rfc"]');
const hint = document.getElementById('hintDocCrear');
if (!sel || !inp) return;
const pintar = () => {
const r = validarDocumentoCO(sel.value, inp.value);
if (hint) {
hint.textContent = r.valido
? (inp.value ? ' Formato ' + sel.value.toUpperCase() + ' válido' : 'NIT: 7–15 dígitos · CC: 6–12 · CE: 6–15 · Pasaporte: 6–15 alfanuméricos')
: ' ' + r.mensaje;
hint.style.color = r.valido ? '#059669' : '#dc2626';
}
inp.dataset.docOk = r.valido ? '1' : '0';
};
sel.addEventListener('change', pintar);
inp.addEventListener('input', pintar);
window.pintarDocAdmin = pintar; //  repintado externo (guía G7-b)
pintar();
})();
//  G7-b: guía contextual en creación (jurídica→NIT empresa; natural→C.C.)
function sincronizarTipoDocCrear(valor) {
const sel = document.querySelector('#formCrearProveedor select[name="tipo_documento"]');
const hint = document.getElementById('hintDocCrear');
if (valor === 'juridica') {
if (sel) sel.value = 'nit';
if (hint) { hint.textContent = ' Persona jurídica: usa el NIT de la empresa (asignado por la DIAN). No es la cédula del representante.'; hint.style.color = '#1e40af'; }
} else if (valor === 'natural') {
if (sel) sel.value = 'cc';
if (hint) { hint.textContent = ' Persona natural: su NIT es su misma cédula. Recomendado: C.C. (equivalentes anti-duplicados).'; hint.style.color = '#1e40af'; }
} else if (hint) {
hint.textContent = 'NIT: 7–15 dígitos · CC: 6–12 · CE: 6–15 · Pasaporte: 6–15 alfanuméricos';
hint.style.color = '#6b7280';
}
if (window.pintarDocAdmin) window.pintarDocAdmin();
if (hint && (valor === 'juridica' || valor === 'natural')) {
// reaplica la guía tras el repintado de validación
hint.textContent = valor === 'juridica'
? ' Persona jurídica: usa el NIT de la empresa (asignado por la DIAN). No es la cédula del representante.'
: ' Persona natural: su NIT es su misma cédula. Recomendado: C.C. (equivalentes anti-duplicados).';
hint.style.color = '#1e40af';
}
}
//  G7-fix: eliminados el listener duplicado y la SEGUNDA definición de
// sincronizarTipoDocCrear (la última declaración pisaba a la primera y dejaba
// muerto el auto-switch a C.C. en naturales). El select ya invoca la función
// vía onchange inline; queda UNA sola definición activa (la que sí conmuta).
// ==========================================
//  CREAR PROVEEDOR
// ==========================================
function mostrarModalCrearProveedor() {
document.getElementById('formCrearProveedor').reset();
document.getElementById('alertaCrearProveedor').innerHTML = '';
document.getElementById('modalCrearProveedor').classList.add('active');
}
function cerrarModalCrearProveedor() {
document.getElementById('modalCrearProveedor').classList.remove('active');
}
document.getElementById('formCrearProveedor').addEventListener('submit', async e => {
e.preventDefault();
const alertaEl = document.getElementById('alertaCrearProveedor');
const formData = new FormData(e.target);
const data = Object.fromEntries(formData);
//  G11: bloqueo local si el teléfono es inválido (el server también valida)
const telInput = e.target.querySelector('input[name="telefono"]');
if (telInput && telInput.dataset.telOk === '0') {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} Teléfono inválido: ${escapeHtml(validarTelefonoCO(telInput.value).mensaje)}</div>`;
telInput.focus();
return;
}
//  G7: bloqueo local si el documento es inválido (el server también valida)
const docInput = e.target.querySelector('input[name="rfc"]');
if (docInput && docInput.value.trim() && docInput.dataset.docOk === '0') {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} Documento inválido: revisa el formato del tipo seleccionado.</div>`;
docInput.focus();
return;
}
try {
const res = await fetchAPI('/api/admin/proveedor', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(data)
});
const r = await res.json();
if (res.ok) {
alertaEl.innerHTML = `<div class="alert alert-success">${ico('check')} ${r.mensaje}</div>`;
setTimeout(async () => {
cerrarModalCrearProveedor();
await cargarProveedoresPorModulo(moduloActual, 1);
if (r.proveedorId) {
await verProveedor(r.proveedorId, moduloActual);
mostrarAlerta('Proveedor creado. Revisa y gestiona sus documentos.', 'success');
}
}, 1500);
} else {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} ${r.error}</div>`;
}
} catch (err) {
alertaEl.innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${err.message}</div>`;
}
});

// ==========================================
//  LOGOUT
// ==========================================
async function logout() {
await fetchAPI('/api/logout', { method: 'POST' });
window.location.href = 'index.html';
}

// ==========================================
//  EVENT LISTENERS DE SUB-TABS
// ==========================================
document.addEventListener('click', function(e) {
const tab = e.target.closest('[data-stab]');
if (tab) {
document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
tab.classList.add('active');
const tgt = tab.dataset.stab;
['docs','historicos','notas','hist','rec','eliminar'].forEach(t =>
document.getElementById(`subTab${t.charAt(0).toUpperCase() + t.slice(1)}`).classList.toggle('hidden', t !== tgt)
);
//  F2: cada sub-pestaña carga SOLO la primera vez por proveedor abierto.
// Las mutaciones que refrescan explícitamente (guardarNota, enviarRecordatorio,
// recargas por socket) resetean los flags, así el caché nunca queda viejo.
if (tgt === 'historicos' && !subTabYaCargada('historicos')) {
renderHistoricosProveedor({ id: proveedorActualId }, historicosCache);
marcarSubTab('historicos');
}
if (tgt === 'notas' && !subTabYaCargada('notas')) { cargarNotas(); marcarSubTab('notas'); }
if (tgt === 'hist' && !subTabYaCargada('hist')) { cargarHistorialProveedor(); marcarSubTab('hist'); }
if (tgt === 'rec' && !subTabYaCargada('rec')) { cargarRecordatoriosEnviados(); marcarSubTab('rec'); }
}
});

// ==========================================
//  C1: ATAJOS DE TECLADO DE LA REVISIÓN ENFOCADA
// ==========================================
document.addEventListener('keydown', function(e) {
  const r = revisionEnfocada;
  if (!r || !r.activa) return;
  const tag = (e.target.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
  if (e.key === 'ArrowLeft') { e.preventDefault(); navegarRevision(-1); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); navegarRevision(1); }
  else if (e.key.toLowerCase() === 'v') { e.preventDefault(); accionRevision('principal'); }
  else if (e.key.toLowerCase() === 'r') { e.preventDefault(); accionRevision('rechazar'); }
  else if (e.key === 'Escape') { cerrarRevisionEnfocada(); }
});

// ==========================================
//  CERRAR MODALES CLICK FUERA
// ==========================================
document.getElementById('modal').addEventListener('click', e => { if (e.target.id === 'modal') cerrarModal(); });
document.getElementById('modalVisor').addEventListener('click', e => { if (e.target.id === 'modalVisor') cerrarVisor(); });
document.getElementById('modalConfirmarEliminar').addEventListener('click', e => { if (e.target.id === 'modalConfirmarEliminar') cerrarConfirmacionEliminar(); });
document.getElementById('modalCrearProveedor').addEventListener('click', e => { if (e.target.id === 'modalCrearProveedor') cerrarModalCrearProveedor(); });

// ==========================================
//  EDITAR CORREO DE PROVEEDOR (admin) — AGENDA #2
// ==========================================
function editarEmailProveedor(proveedorId, emailActual) {
    const cont = document.getElementById('contenedorEditarEmail');
    if (!cont) return;
    cont.style.display = 'block';
    cont.innerHTML = `
    <div style="background:#eff6ff;padding:0.7rem;border-radius:8px;border:1px solid #bfdbfe;">
        <label style="font-weight:600;color:#1e40af;display:block;margin-bottom:0.3rem;">${ico('mail')} Nuevo correo electrónico</label>
        <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
            <input type="email" id="nuevoEmailProveedor" value="${escapeAttr(emailActual)}" placeholder="nuevo@correo.com" style="flex:1;min-width:200px;padding:0.45rem;border:1px solid #bfdbfe;border-radius:6px;">
            <button class="btn btn-sm" style="background:#2563eb;" onclick="guardarEmailProveedor(${proveedorId})">${ico('save')} Guardar</button>
            <button class="btn btn-sm btn-secondary" onclick="document.getElementById('contenedorEditarEmail').style.display='none'"> Cancelar</button>
        </div>
        <small style="color:#1e40af;font-size:0.78rem;display:block;margin-top:0.3rem;">El proveedor conservará historial, documentos y contraseña; solo cambia su correo de acceso.</small>
    </div>`;
    const inp = document.getElementById('nuevoEmailProveedor');
    if (inp) inp.focus();
}
async function guardarEmailProveedor(proveedorId) {
    const input = document.getElementById('nuevoEmailProveedor');
    if (!input) return;
    const emailNuevo = input.value.trim();
    if (!emailNuevo) { mostrarAlerta(' Escribe un correo', 'error'); return; }
    try {
        mostrarAlerta(' Actualizando correo...', 'info');
        const res = await fetchAPI(`/api/admin/proveedor/${proveedorId}/email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailNuevo })
        });
        const r = await res.json();
        if (res.ok) {
            mostrarAlerta(' ' + r.mensaje, 'success');
            const span = document.getElementById('emailActualProv');
            if (span) span.textContent = emailNuevo;
            document.getElementById('contenedorEditarEmail').style.display = 'none';
            await cargarProveedoresPorModulo(moduloActual, paginaActual);
        } else {
            mostrarAlerta(' ' + (r.error || 'Error'), 'error');
        }
    } catch (err) {
        mostrarAlerta(' Error de conexión', 'error');
    }
}

// ==========================================
//  C6: BÚSQUEDA GLOBAL Ctrl+K (paleta SweetAlert2)
// ==========================================
let ctrlKState = { abierta: false, items: [], sel: 0 };
function accionesCtrlK() {
return [
{ tipo: 'accion', nombre: 'Ir a: Registrados', run: () => { moduloActual = 'registrados'; filtroEstadoActual = 'todos'; paginaActual = 1; marcarModuloAdmin('registrados'); cargarModulo('registrados'); } },
{ tipo: 'accion', nombre: 'Ir a: Verificación', run: () => { moduloActual = 'verificacion'; filtroEstadoActual = 'todos'; paginaActual = 1; marcarModuloAdmin('verificacion'); cargarModulo('verificacion'); } },
{ tipo: 'accion', nombre: 'Ir a: Aprobación', run: () => { moduloActual = 'aprobacion'; filtroEstadoActual = 'todos'; paginaActual = 1; marcarModuloAdmin('aprobacion'); cargarModulo('aprobacion'); } },
{ tipo: 'accion', nombre: 'Ir a: Inscripción', run: () => { moduloActual = 'inscripcion'; filtroEstadoActual = 'todos'; paginaActual = 1; marcarModuloAdmin('inscripcion'); cargarModulo('inscripcion'); } },
{ tipo: 'accion', nombre: 'Ir a: Rechazados', run: () => { filtroEstadoActual = 'rechazado'; moduloActual = 'registrados'; paginaActual = 1; marcarModuloAdmin('rechazados'); cargarModulo('registrados'); } },
{ tipo: 'accion', nombre: 'Ir a: Historial', run: () => { cargarHistorial(1); } },
{ tipo: 'accion', nombre: 'Ir a: Configuración', run: () => { cargarConfiguracion(); } },
{ tipo: 'accion', nombre: 'Ir a: Plantillas', run: () => { renderizarPlantillas(); } },
{ tipo: 'accion', nombre: ' Crear proveedor', run: () => mostrarModalCrearProveedor() },
{ tipo: 'accion', nombre: ' Crear backup ahora', run: () => crearBackupAhora() },
{ tipo: 'accion', nombre: 'Ir a: Métricas', run: () => { moduloActual = 'metricas'; cargarMetricas(); } },
{ tipo: 'accion', nombre: 'Ir a: Auditoría', run: () => { moduloActual = 'auditoria'; cargarAuditoria(); } },
{ tipo: 'accion', nombre: 'Ir a: Equipo', run: () => { moduloActual = 'equipo'; cargarModulo('equipo'); } }
];
}
function abrirCtrlK() {
if (ctrlKState.abierta) { cerrarCtrlK(); return; }
Swal.fire({
title: ' Búsqueda global',
html: `
<input type="text" id="ctrlKInput" class="swal2-input" placeholder="Buscar proveedor por nombre, NIT o email… o escribe una acción" style="width:100%;margin:0 0 0.6rem 0;">
<div id="ctrlKResults" style="max-height:320px;overflow-y:auto;text-align:left;"></div>
`,
showConfirmButton: false,
showCloseButton: true,
allowOutsideClick: true,
allowEscapeKey: true,
customClass: { popup: 'ctrlk-popup' },
didOpen: () => {
ctrlKState = { abierta: true, items: [], sel: 0 };
const inp = document.getElementById('ctrlKInput');
if (inp) {
inp.addEventListener('input', e => buscarCtrlK(e.target.value));
//  C6-fix A: Enter/flechas DIRECTO en el input.
// SweetAlert2 detiene la propagación de keydown hacia document por defecto,
// por eso el listener global nunca recibía Enter/flechas desde el popup.
inp.addEventListener('keydown', e => {
if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); console.log('[C6] Enter en input → sel=', ctrlKState.sel, 'items=', ctrlKState.items.length); ejecutarCtrlK(ctrlKState.sel); }
else if (e.key === 'ArrowDown') { e.preventDefault(); e.stopPropagation(); ctrlKState.sel = Math.min(ctrlKState.sel + 1, ctrlKState.items.length - 1); renderCtrlK(); }
else if (e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); ctrlKState.sel = Math.max(ctrlKState.sel - 1, 0); renderCtrlK(); }
});
//  C6-fix B: click por DELEGACIÓN en el contenedor de resultados.
// El listener vive en #ctrlKResults (no en cada ítem), así sobrevive
// a cada re-render de la lista de resultados.
const contResults = document.getElementById('ctrlKResults');
if (contResults) contResults.addEventListener('click', ev => {
const item = ev.target.closest ? ev.target.closest('.ctrlk-item') : null;
if (!item) return;
ev.preventDefault();
ev.stopPropagation();
console.log('[C6] Click en item → i=', item.dataset.i);
ejecutarCtrlK(parseInt(item.dataset.i, 10));
});
inp.focus();
}
renderCtrlK();
},
didClose: () => { ctrlKState.abierta = false; }
});
}
function cerrarCtrlK() {
  //  FIX: Swal.isOpen() no existe en SweetAlert2. 
  // Usamos Swal.isVisible() o Swal.getPopup() para verificar si hay un modal activo.
  if (typeof Swal !== 'undefined' && Swal.isVisible && Swal.isVisible()) {
    Swal.close();
  } else if (typeof Swal !== 'undefined' && Swal.getPopup && Swal.getPopup()) {
    Swal.close();
  }
  ctrlKState.abierta = false;
}
async function buscarCtrlK(q) {
const qy = (q || '').trim().toLowerCase();
const results = [];
if (qy.length >= 2) {
accionesCtrlK().forEach(a => { if (a.nombre.toLowerCase().includes(qy)) results.push(a); });
try {
const res = await fetchAPI(`/api/admin/proveedores?page=1&limit=8&busqueda=${encodeURIComponent(q || '')}`);
if (res.ok) { const data = await res.json(); (data.data || []).forEach(p => results.push({ tipo: 'proveedor', p })); }
} catch (e) { /* silencioso */ }
}
ctrlKState.items = results;
ctrlKState.sel = 0;
renderCtrlK();
}
function renderCtrlK() {
const cont = document.getElementById('ctrlKResults');
if (!cont) return;
if (!ctrlKState.items.length) {
cont.innerHTML = '<p style="color:#6b7280;font-size:0.85rem;padding:0.6rem;text-align:center;">Escribe al menos 2 caracteres…</p>';
return;
}
cont.innerHTML = ctrlKState.items.map((it, i) => {
const sel = i === ctrlKState.sel ? 'background:var(--color-primario-claro);' : '';
if (it.tipo === 'accion') {
return `<div class="ctrlk-item" data-i="${i}" style="${sel}display:flex;gap:0.6rem;align-items:center;padding:0.55rem 0.8rem;border-radius:6px;cursor:pointer;"><span></span><span style="font-size:0.9rem;">${escapeHtml(it.nombre)}</span></div>`;
}
const p = it.p;
return `<div class="ctrlk-item" data-i="${i}" style="${sel}display:flex;gap:0.6rem;align-items:center;padding:0.55rem 0.8rem;border-radius:6px;cursor:pointer;"><span>${p.tipo_proveedor === 'natural' ? '' : ''}</span><span style="flex:1;font-size:0.9rem;"><strong>${escapeHtml(p.razon_social || p.nombre_empresa || '')}</strong> <small style="color:#6b7280;">· ${escapeHtml(p.rfc || '')} · ${escapeHtml(p.email || '')}</small></span><span class="badge-count">${escapeHtml(p.etapa || '')}</span></div>`;
}).join('');
//  C6-fix: los clicks se manejan por delegación en didOpen (parche 1).
// Ya NO se adjuntan listeners por elemento: se perdían en cada re-render.
}
function ejecutarCtrlK(i) {
console.log('[C6] ejecutarCtrlK i=', i, 'items=', ctrlKState.items.length);
const it = ctrlKState.items[i];
if (!it) { console.warn('[C6] Sin item en el índice', i); return; }
try {
//  Acciones: cerrar primero está bien (no abren modal encima)
if (it.tipo === 'accion') {
cerrarCtrlK();
console.log('[C6] Ejecutando acción:', it.nombre);
it.run();
return;
}
const p = it.p;
if (!p || !p.id) { console.warn('[C6] Item sin proveedor/id:', it); return; }
const mod = (p.etapa === 'verificacion' || p.etapa === 'aprobacion' || p.etapa === 'inscripcion') ? p.etapa : 'registrados';
console.log('[C6] Navegando a proveedor', p.id, '(etapa', p.etapa, ') → módulo', mod);
// 1) Cambiar módulo y cargar lista
moduloActual = mod;
filtroEstadoActual = (p.etapa === 'rechazado') ? 'rechazado' : 'todos';
paginaActual = 1;
marcarModuloAdmin(p.etapa === 'rechazado' ? 'rechazados' : mod);
cargarModulo(mod);
// 2)  FIX: cerrar Swal PRIMERO y abrir el modal DESPUÉS de su cleanup
//    (restoreFocus + retiro del backdrop z-index 99999). Antes el
//    Swal.close() síncrono pisaba la apertura del modal del proveedor.
cerrarCtrlK();
setTimeout(() => {
try {
verProveedor(p.id, mod);
console.log('[C6] Modal abierto para proveedor', p.id);
} catch (err2) {
console.error('[C6] Error abriendo modal:', err2);
mostrarAlerta(' Error al abrir el proveedor: ' + err2.message, 'error');
}
}, 300);
} catch (err) {
console.error('[C6] Error en ejecutarCtrlK:', err);
mostrarAlerta(' Error al navegar: ' + err.message, 'error');
cerrarCtrlK();
}
}
// Listener global de teclado (Ctrl+K abre/cierra; flechas y Enter navegan)
document.addEventListener('keydown', function(e) {
if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ctrlKState.abierta ? cerrarCtrlK() : abrirCtrlK(); return; }
if (!ctrlKState.abierta) return;
if (e.key === 'Escape') { cerrarCtrlK(); return; }
if (e.key === 'ArrowDown') { e.preventDefault(); ctrlKState.sel = Math.min(ctrlKState.sel + 1, ctrlKState.items.length - 1); renderCtrlK(); return; }
if (e.key === 'ArrowUp') { e.preventDefault(); ctrlKState.sel = Math.max(ctrlKState.sel - 1, 0); renderCtrlK(); return; }
if (e.key === 'Enter') { e.preventDefault(); ejecutarCtrlK(ctrlKState.sel); return; }
});

// ==========================================
//  R1: MÓDULO AUDITORÍA (3 sub-tabs)
// ==========================================
let auditoriaTab = 'actividad';
let auditoriaFiltros = { busqueda: '', fecha_desde: '', fecha_hasta: '', accion: '', usuario: '', exitoso: '' };
let auditoriaLogsPagina = 1;
let auditoriaLogsTotalPaginas = 1;

async function cargarAuditoria() {
const contenedor = document.getElementById('contenedor-modulos');
if (!contenedor) return;
contenedor.innerHTML = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
<h3 style="margin:0;">${ico('chart')} Auditoría del sistema</h3>
</div>
<div style="display:flex;gap:0.5rem;margin-bottom:1.5rem;border-bottom:2px solid var(--color-borde);flex-wrap:wrap;">
<button class="tab active" data-atab="actividad" onclick="cambiarTabAuditoria('actividad', this)">${ico('file-text')} Actividad por usuario</button>
<button class="tab" data-atab="historial" onclick="cambiarTabAuditoria('historial', this)">${ico('file-text')} Historial detalle</button>
<button class="tab" data-atab="logs" onclick="cambiarTabAuditoria('logs', this)"> Logs de seguridad</button>
</div>
<div id="auditoriaContenido"><p style="color:#6b7280;text-align:center;padding:2rem;">${ico('clock')} Cargando…</p></div>
</div>`;
renderTabAuditoria();
}

function cambiarTabAuditoria(tab, btn) {
auditoriaTab = tab;
document.querySelectorAll('[data-atab]').forEach(t => t.classList.remove('active'));
if (btn) btn.classList.add('active');
renderTabAuditoria();
}

async function renderTabAuditoria() {
const cont = document.getElementById('auditoriaContenido');
if (!cont) return;
if (auditoriaTab === 'actividad') await renderAuditoriaActividad(cont);
else if (auditoriaTab === 'historial') await renderAuditoriaHistorial(cont);
else if (auditoriaTab === 'logs') await renderAuditoriaLogs(cont);
}

// ---- Sub-tab 1: Actividad agregada por usuario ----
async function renderAuditoriaActividad(cont) {
const f = auditoriaFiltros;
cont.innerHTML = `
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1rem;">
<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:1rem;margin-bottom:0.8rem;align-items:end;">
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('search')} Buscar usuario</label>
<input type="text" id="audBusqueda" placeholder="Email del operador…" value="${escapeHtml(f.busqueda)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Desde</label>
<input type="date" id="audFechaDesde" value="${escapeHtml(f.fecha_desde)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Hasta</label>
<input type="date" id="audFechaHasta" value="${escapeHtml(f.fecha_hasta)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm" onclick="aplicarFiltrosAuditoria()" style="background:#8600dd;">${ico('search')} Filtrar</button>
<button class="btn btn-sm btn-secondary" onclick="limpiarFiltrosAuditoria()">${ico('trash')} Limpiar</button>
</div>
</div>
</div>
<div id="audActividadTabla"><p style="color:#6b7280;text-align:center;padding:1rem;">${ico('clock')} Cargando actividad…</p></div>`;
try {
let url = '/api/admin/actividad?_=1';
if (f.busqueda) url += `&busqueda=${encodeURIComponent(f.busqueda)}`;
if (f.fecha_desde) url += `&fecha_desde=${encodeURIComponent(f.fecha_desde)}`;
if (f.fecha_hasta) url += `&fecha_hasta=${encodeURIComponent(f.fecha_hasta)}`;
const res = await fetchAPI(url);
if (!res.ok) throw new Error((await res.json()).error || 'Error');
const data = await res.json();
const usuarios = data.data || [];
if (!usuarios.length) {
document.getElementById('audActividadTabla').innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">No hay actividad registrada con los filtros aplicados.</p>';
return;
}
document.getElementById('audActividadTabla').innerHTML = `
<div style="margin-bottom:0.8rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
<strong>${ico('chart')} Total global: ${data.total_global} acciones · ${usuarios.length} operador(es)</strong>
</div>
<div style="overflow-x:auto;">
<table style="width:100%;border-collapse:collapse;font-size:0.88rem;">
<thead>
<tr style="background:#f3f4f6;border-bottom:2px solid #d1d5db;">
<th style="padding:0.6rem;text-align:left;">Operador</th>
<th style="padding:0.6rem;text-align:center;">Total</th>
<th style="padding:0.6rem;text-align:center;">${ico('check')} Verif.</th>
<th style="padding:0.6rem;text-align:center;"> Aprob.</th>
<th style="padding:0.6rem;text-align:center;"> Rech.</th>
<th style="padding:0.6rem;text-align:center;">${ico('upload')} Subidas</th>
<th style="padding:0.6rem;text-align:center;"> Notas</th>
<th style="padding:0.6rem;text-align:center;">${ico('send')} Record.</th>
<th style="padding:0.6rem;text-align:center;">${ico('file-text')} Gest.</th>
<th style="padding:0.6rem;text-align:center;">${ico('refresh')} Etapas</th>
<th style="padding:0.6rem;text-align:center;">Última actividad</th>
</tr>
</thead>
<tbody>
${usuarios.map(u => `
<tr style="border-bottom:1px solid #e5e7eb;">
<td style="padding:0.55rem;font-weight:600;">${escapeHtml(u.usuario_nombre)}</td>
<td style="padding:0.55rem;text-align:center;"><strong>${u.total_acciones}</strong></td>
<td style="padding:0.55rem;text-align:center;">${u.verificaciones || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.aprobaciones || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.rechazos || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.subidas || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.notas || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.recordatorios || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.gestiones || 0}</td>
<td style="padding:0.55rem;text-align:center;">${u.cambios_etapa || 0}</td>
<td style="padding:0.55rem;text-align:center;font-size:0.8rem;">${formatearFecha(u.ultima_actividad)}</td>
</tr>`).join('')}
</tbody>
</table>
</div>`;
} catch (e) {
document.getElementById('audActividadTabla').innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${e.message}</div>`;
}
}

// ---- Sub-tab 2: Historial detalle (reutiliza /api/admin/audit-log) ----
async function renderAuditoriaHistorial(cont) {
const f = auditoriaFiltros;
cont.innerHTML = `
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1rem;">
<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:0.8rem;margin-bottom:0.8rem;align-items:end;">
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('search')} Buscar</label>
<input type="text" id="audHistBusqueda" placeholder="Detalle, usuario…" value="${escapeHtml(f.busqueda)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;"> Operador</label>
<input type="text" id="audHistUsuario" placeholder="Email…" value="${escapeHtml(f.usuario)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Desde</label>
<input type="date" id="audHistDesde" value="${escapeHtml(f.fecha_desde)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Hasta</label>
<input type="date" id="audHistHasta" value="${escapeHtml(f.fecha_hasta)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm" onclick="aplicarFiltrosAuditoria()" style="background:#8600dd;">${ico('search')} Filtrar</button>
<button class="btn btn-sm btn-secondary" onclick="limpiarFiltrosAuditoria()">${ico('trash')}</button>
</div>
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm btn-success" onclick="exportarHistorialAuditoria()">${ico('file-text')} Exportar CSV</button>
</div>
</div>
<div id="audHistTabla"><p style="color:#6b7280;text-align:center;padding:1rem;">${ico('clock')} Cargando historial…</p></div>`;
await cargarHistorialAuditoria(1);
}

async function cargarHistorialAuditoria(pagina) {
const f = auditoriaFiltros;
let url = `/api/admin/audit-log?page=${pagina}&limit=50`;
if (f.busqueda) url += `&busqueda=${encodeURIComponent(f.busqueda)}`;
if (f.usuario) url += `&usuario=${encodeURIComponent(f.usuario)}`;
if (f.accion) url += `&accion=${encodeURIComponent(f.accion)}`;
if (f.fecha_desde) url += `&fecha_desde=${encodeURIComponent(f.fecha_desde)}`;
if (f.fecha_hasta) url += `&fecha_hasta=${encodeURIComponent(f.fecha_hasta)}`;
try {
const res = await fetchAPI(url);
if (!res.ok) throw new Error((await res.json()).error || 'Error');
const data = await res.json();
const registros = data.data || [];
const cont = document.getElementById('audHistTabla');
if (!cont) return;
if (!registros.length) {
cont.innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">No hay registros con los filtros aplicados.</p>';
return;
}
const iconosAccion = {
registro: ico('award'), documento_subido: ico('upload'), documento_reemplazado: ico('refresh'),
documento_eliminado: ico('trash'), documento_aprobado: ico('check'), documento_rechazado: ico('x'),
documento_verificado: ico('search'), datos_actualizados: ico('edit'), recordatorio_enviado: ico('send'),
nota_agregada: ico('message'), documento_no_aplica: ico('clipboard'), gestion_actualizada: ico('clipboard'),
cambio_etapa: ico('refresh'), evaluacion_subida: ico('file'), evaluacion_estado_cambiado: ico('clipboard'),
solicitud_actualizacion: ico('refresh'), vencimiento_automatico: ico('clock'), vencimiento_forzado: ico('zap'),
proceso_reiniciado: ico('refresh'), tipo_persona_definido: ico('file-text'), email_cambiado: ico('mail'),
evaluacion_eliminada: ico('trash'), login_exitoso: ico('lock'), login_fallido_admin: ico('alert')
};
cont.innerHTML = `
<div style="margin-bottom:0.5rem;font-size:0.85rem;color:#6b7280;">
Página ${data.page} de ${data.totalPages} (${data.total} registros)
</div>
<div style="overflow-x:auto;">
<table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
<thead>
<tr style="background:#f3f4f6;border-bottom:2px solid #d1d5db;">
<th style="padding:0.5rem;text-align:left;">Fecha</th>
<th style="padding:0.5rem;text-align:left;">Operador</th>
<th style="padding:0.5rem;text-align:left;">Acción</th>
<th style="padding:0.5rem;text-align:left;">Detalle</th>
<th style="padding:0.5rem;text-align:left;">Proveedor</th>
<th style="padding:0.5rem;text-align:center;">IP</th>
</tr>
</thead>
<tbody>
${registros.map(r => `
<tr style="border-bottom:1px solid #e5e7eb;">
<td style="padding:0.45rem;font-size:0.8rem;white-space:nowrap;">${formatearFecha(r.creado_en)}</td>
<td style="padding:0.45rem;font-weight:600;">${escapeHtml(r.usuario_nombre || 'Sistema')}</td>
<td style="padding:0.45rem;">${iconosAccion[r.accion] || ico('pin')} ${escapeHtml(r.accion)}</td>
<td style="padding:0.45rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(r.detalle || '')}</td>
<td style="padding:0.45rem;">${escapeHtml(r.razon_social || r.proveedor_email || '—')}</td>
<td style="padding:0.45rem;text-align:center;font-family:monospace;font-size:0.75rem;">${escapeHtml(r.ip_origen || '—')}</td>
</tr>`).join('')}
</tbody>
</table>
</div>
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:0.8rem;gap:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="cargarHistorialAuditoria(${data.page - 1})" ${data.page <= 1 ? 'disabled' : ''}> Anterior</button>
<span style="font-size:0.85rem;color:#6b7280;">Página ${data.page} de ${data.totalPages}</span>
<button class="btn btn-sm btn-secondary" onclick="cargarHistorialAuditoria(${data.page + 1})" ${data.page >= data.totalPages ? 'disabled' : ''}>Siguiente </button>
</div>`;
} catch (e) {
const cont = document.getElementById('audHistTabla');
if (cont) cont.innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${e.message}</div>`;
}
}

async function exportarHistorialAuditoria() {
const f = auditoriaFiltros;
let url = '/api/admin/audit-log/export?';
if (f.busqueda) url += `&busqueda=${encodeURIComponent(f.busqueda)}`;
if (f.usuario) url += `&usuario=${encodeURIComponent(f.usuario)}`;
if (f.accion) url += `&accion=${encodeURIComponent(f.accion)}`;
if (f.fecha_desde) url += `&fecha_desde=${encodeURIComponent(f.fecha_desde)}`;
if (f.fecha_hasta) url += `&fecha_hasta=${encodeURIComponent(f.fecha_hasta)}`;
try {
mostrarAlerta(' Generando CSV…', 'info');
const res = await fetchAPI(url);
if (!res.ok) throw new Error((await res.json()).error || 'Error');
const blob = await res.blob();
descargarBlob(blob, `auditoria_historial_${fechaArchivo()}.csv`);
mostrarAlerta(' Historial exportado', 'success');
} catch (e) {
mostrarAlerta(' Error exportando: ' + e.message, 'error');
}
}

// ---- Sub-tab 3: Logs de seguridad ----
async function renderAuditoriaLogs(cont) {
const f = auditoriaFiltros;
cont.innerHTML = `
<div style="background:#f9fafb;padding:1rem;border-radius:8px;margin-bottom:1rem;">
<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:0.8rem;margin-bottom:0.8rem;align-items:end;">
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('search')} Buscar</label>
<input type="text" id="audLogBusqueda" placeholder="Email, detalle…" value="${escapeHtml(f.busqueda)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;"> Resultado</label>
<select id="audLogExitoso" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
<option value="">Todos</option>
<option value="1" ${f.exitoso === '1' ? 'selected' : ''}>${ico('check')} Exitoso</option>
<option value="0" ${f.exitoso === '0' ? 'selected' : ''}>${ico('x')} Fallido</option>
</select>
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Desde</label>
<input type="date" id="audLogDesde" value="${escapeHtml(f.fecha_desde)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div>
<label style="display:block;font-size:0.85rem;color:#6b7280;margin-bottom:0.3rem;">${ico('calendar')} Hasta</label>
<input type="date" id="audLogHasta" value="${escapeHtml(f.fecha_hasta)}" style="width:100%;padding:0.5rem;border:1px solid #d1d5db;border-radius:6px;">
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm" onclick="aplicarFiltrosAuditoria()" style="background:#8600dd;">${ico('search')} Filtrar</button>
<button class="btn btn-sm btn-secondary" onclick="limpiarFiltrosAuditoria()">${ico('trash')}</button>
</div>
</div>
<div style="display:flex;gap:0.5rem;">
<button class="btn btn-sm btn-success" onclick="exportarLogsAuditoria()">${ico('file-text')} Exportar CSV</button>
</div>
</div>
<div id="audLogsTabla"><p style="color:#6b7280;text-align:center;padding:1rem;">${ico('clock')} Cargando logs…</p></div>`;
await cargarLogsAuditoria(1);
}

async function cargarLogsAuditoria(pagina) {
const f = auditoriaFiltros;
let url = `/api/admin/logs-seguridad?page=${pagina}&limit=50`;
if (f.busqueda) url += `&busqueda=${encodeURIComponent(f.busqueda)}`;
if (f.exitoso !== '') url += `&exitoso=${encodeURIComponent(f.exitoso)}`;
if (f.fecha_desde) url += `&fecha_desde=${encodeURIComponent(f.fecha_desde)}`;
if (f.fecha_hasta) url += `&fecha_hasta=${encodeURIComponent(f.fecha_hasta)}`;
try {
const res = await fetchAPI(url);
if (!res.ok) throw new Error((await res.json()).error || 'Error');
const data = await res.json();
const registros = data.data || [];
const cont = document.getElementById('audLogsTabla');
if (!cont) return;
if (!registros.length) {
cont.innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">No hay logs con los filtros aplicados.</p>';
return;
}
cont.innerHTML = `
<div style="margin-bottom:0.5rem;font-size:0.85rem;color:#6b7280;">
Página ${data.page} de ${data.totalPages} (${data.total} registros)
</div>
<div style="overflow-x:auto;">
<table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
<thead>
<tr style="background:#f3f4f6;border-bottom:2px solid #d1d5db;">
<th style="padding:0.5rem;text-align:left;">Fecha</th>
<th style="padding:0.5rem;text-align:left;">Email</th>
<th style="padding:0.5rem;text-align:left;">Acción</th>
<th style="padding:0.5rem;text-align:center;">Resultado</th>
<th style="padding:0.5rem;text-align:left;">Detalle</th>
<th style="padding:0.5rem;text-align:center;">IP</th>
</tr>
</thead>
<tbody>
${registros.map(r => `
<tr style="border-bottom:1px solid #e5e7eb;${r.exitoso === 0 ? 'background:#fef2f2;' : ''}">
<td style="padding:0.45rem;font-size:0.8rem;white-space:nowrap;">${formatearFecha(r.creado_en)}</td>
<td style="padding:0.45rem;font-weight:600;">${escapeHtml(r.email || '—')}</td>
<td style="padding:0.45rem;">${escapeHtml(r.accion)}</td>
<td style="padding:0.45rem;text-align:center;">${r.exitoso ? '<span class="badge badge-aprobado">' + ico('check') + ' Exitoso</span>' : '<span class="badge badge-rechazado">' + ico('x') + ' Fallido</span>'}</td>
<td style="padding:0.45rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(r.detalle || '')}</td>
<td style="padding:0.45rem;text-align:center;font-family:monospace;font-size:0.75rem;">${escapeHtml(r.ip_origen || '—')}</td>
</tr>`).join('')}
</tbody>
</table>
</div>
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:0.8rem;gap:0.5rem;flex-wrap:wrap;">
<button class="btn btn-sm btn-secondary" onclick="cargarLogsAuditoria(${data.page - 1})" ${data.page <= 1 ? 'disabled' : ''}> Anterior</button>
<span style="font-size:0.85rem;color:#6b7280;">Página ${data.page} de ${data.totalPages}</span>
<button class="btn btn-sm btn-secondary" onclick="cargarLogsAuditoria(${data.page + 1})" ${data.page >= data.totalPages ? 'disabled' : ''}>Siguiente </button>
</div>`;
} catch (e) {
const cont = document.getElementById('audLogsTabla');
if (cont) cont.innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${e.message}</div>`;
}
}

async function exportarLogsAuditoria() {
const f = auditoriaFiltros;
let url = '/api/admin/logs-seguridad/export?';
if (f.busqueda) url += `&busqueda=${encodeURIComponent(f.busqueda)}`;
if (f.exitoso !== '') url += `&exitoso=${encodeURIComponent(f.exitoso)}`;
if (f.fecha_desde) url += `&fecha_desde=${encodeURIComponent(f.fecha_desde)}`;
if (f.fecha_hasta) url += `&fecha_hasta=${encodeURIComponent(f.fecha_hasta)}`;
try {
mostrarAlerta(' Generando CSV…', 'info');
const res = await fetchAPI(url);
if (!res.ok) throw new Error((await res.json()).error || 'Error');
const blob = await res.blob();
descargarBlob(blob, `logs_seguridad_${fechaArchivo()}.csv`);
mostrarAlerta(' Logs exportados', 'success');
} catch (e) {
mostrarAlerta(' Error exportando: ' + e.message, 'error');
}
}

// ---- Filtros compartidos de Auditoría ----
function aplicarFiltrosAuditoria() {
const get = (id) => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
if (auditoriaTab === 'actividad') {
auditoriaFiltros.busqueda = get('audBusqueda');
auditoriaFiltros.fecha_desde = get('audFechaDesde');
auditoriaFiltros.fecha_hasta = get('audFechaHasta');
renderAuditoriaActividad(document.getElementById('auditoriaContenido'));
} else if (auditoriaTab === 'historial') {
auditoriaFiltros.busqueda = get('audHistBusqueda');
auditoriaFiltros.usuario = get('audHistUsuario');
auditoriaFiltros.fecha_desde = get('audHistDesde');
auditoriaFiltros.fecha_hasta = get('audHistHasta');
cargarHistorialAuditoria(1);
} else if (auditoriaTab === 'logs') {
auditoriaFiltros.busqueda = get('audLogBusqueda');
auditoriaFiltros.exitoso = get('audLogExitoso');
auditoriaFiltros.fecha_desde = get('audLogDesde');
auditoriaFiltros.fecha_hasta = get('audLogHasta');
cargarLogsAuditoria(1);
}
}

function limpiarFiltrosAuditoria() {
auditoriaFiltros = { busqueda: '', fecha_desde: '', fecha_hasta: '', accion: '', usuario: '', exitoso: '' };
renderTabAuditoria();
}


// ==========================================
//  R4: GATING RBAC DE UI (sidebar, KPIs, subtabs, botones)
// ==========================================
function renderAccesoDenegado() {
  const contenedor = document.getElementById('contenedor-modulos');
  if (!contenedor) return;
  contenedor.innerHTML = `<div class="card"><div class="alert alert-error"> Acceso denegado: tu perfil no tiene permiso para este módulo.</div></div>`;
}
function aplicarGatingRBAC() {
  // 1) Item Equipo (superadmin) — se inyecta si el markup no lo trae (sin tocar admin.html)
  if (!document.querySelector('.ad-item[data-mod="equipo"]')) {
    const ref = document.querySelector('.ad-item[data-mod="auditoria"]');
    if (ref && ref.parentNode) {
      const btn = document.createElement('button');
      btn.className = 'ad-item';
      btn.dataset.mod = 'equipo';
      btn.setAttribute('onclick', 'cambiarModuloSidebar(this)');
      btn.innerHTML = '<svg class="ico" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><span class="txt">Equipo</span>';
      ref.parentNode.insertBefore(btn, ref.nextSibling);
    }
  }
  // 2) Sidebar por módulo
  const reglasSidebar = {
    verificacion: 'docs.verificar', aprobacion: 'docs.aprobar',
    inscripcion: 'gestion.inscribir', metricas: 'metricas.ver',
    auditoria: 'auditoria.ver', configuracion: 'config.gestionar',
    historial: 'docs.ver', plantillas: 'docs.ver'
  };
  document.querySelectorAll('.ad-item[data-mod]').forEach(btn => {
    const mod = btn.dataset.mod;
    if (mod === 'equipo') { btn.style.display = esSuperadminUI ? '' : 'none'; return; }
    const clave = reglasSidebar[mod];
    if (clave) btn.style.display = tienePermisoUI(clave) ? '' : 'none';
  });
  // 3) KPIs que navegan a módulos gateados
  const kpiReglas = { verificacion: 'docs.verificar', aprobacion: 'docs.aprobar', inscripcion: 'gestion.inscribir' };
  document.querySelectorAll('.kpi-tab[data-modulo]').forEach(k => {
    const clave = kpiReglas[k.dataset.modulo];
    if (clave) k.style.display = tienePermisoUI(clave) ? '' : 'none';
  });
  // 4) Subtabs de notas/recordatorios/eliminar (D7: revisor no)
  const subTabReglas = { notas: 'notas.enviar', rec: 'notas.enviar', eliminar: 'proveedores.gestionar' };
  document.querySelectorAll('[data-stab]').forEach(t => {
    const clave = subTabReglas[t.dataset.stab];
    if (clave) t.style.display = tienePermisoUI(clave) ? '' : 'none';
  });
  aplicarGatingBotones();
}
function aplicarGatingBotones() {
  const reglas = [
    ['[onclick*="mostrarModalCrearProveedor"]', 'proveedores.crear'],
    ['[onclick*="toggleExportDropdown"]', 'exportar.datos'],
    ['[onclick*="exportarHabeasData"]', 'exportar.datos'],
    ['[onclick*="recordarInactivos"]', 'notas.enviar'],
    ['[onclick*="crearBackupAhora"]', 'backups.gestionar'],
    ['[onclick*="forzarVencimientosAhora"]', 'config.gestionar'],
    ['[onclick*="recalcularVencimientos"]', 'config.gestionar']
  ];
  reglas.forEach(([sel, clave]) => {
    document.querySelectorAll(sel).forEach(el => {
      el.style.display = tienePermisoUI(clave) ? '' : 'none';
    });
  });
}
// ==========================================
//  R4: MÓDULO EQUIPO (solo superadmin) — matriz de 15 switches + invitación
// ==========================================
let equipoCache = [];
//  R4-fix: catálogo LEGIBLE de la matriz de permisos (D2).
// La clave técnica (data-clave / value) NO cambia: es el contrato con el server.
// Solo cambia lo que ve el superadmin: grupo + nombre + ayuda.
const PERMISOS_UI = [
  { grupo: 'Documentos', clave: 'docs.ver', nombre: 'Ver documentos y expedientes', ayuda: 'Abrir, ver, descargar ZIP e históricos' },
  { grupo: 'Documentos', clave: 'docs.verificar', nombre: 'Verificar documentos', ayuda: 'Marcar como verificado (etapa Verificación)' },
  { grupo: 'Documentos', clave: 'docs.aprobar', nombre: 'Aprobar documentos', ayuda: 'Aprobar documentos verificados (etapa Aprobación)' },
  { grupo: 'Documentos', clave: 'docs.rechazar', nombre: 'Rechazar documentos', ayuda: 'Rechazar con motivo (Verificación y Aprobación)' },
  { grupo: 'Documentos', clave: 'evaluacion.gestionar', nombre: 'Gestionar evaluación inicial', ayuda: 'Subir, aprobar, rechazar o eliminar la evaluación' },
  { grupo: 'Proveedores', clave: 'proveedores.crear', nombre: 'Crear proveedores', ayuda: 'Registrar proveedores desde el panel' },
  { grupo: 'Proveedores', clave: 'proveedores.gestionar', nombre: 'Gestionar ficha de proveedor', ayuda: 'Editar email, tipo de persona, eliminar, pedir actualización' },
  { grupo: 'Proveedores', clave: 'gestion.inscribir', nombre: 'Inscribir y registrar', ayuda: 'Guardar Fecha Movimiento y cerrar ciclo' },
  { grupo: 'Comunicación', clave: 'notas.enviar', nombre: 'Enviar notas y recordatorios', ayuda: 'Escribir notas y recordatorios al proveedor' },
  { grupo: 'Sistema', clave: 'plantillas.gestionar', nombre: 'Gestionar plantillas', ayuda: 'Subir y reemplazar formatos institucionales' },
  { grupo: 'Sistema', clave: 'config.gestionar', nombre: 'Gestionar configuración', ayuda: 'Fecha fija de vencimiento y acciones urgentes' },
  { grupo: 'Sistema', clave: 'backups.gestionar', nombre: 'Gestionar backups', ayuda: 'Crear, verificar, descargar y restaurar' },
  { grupo: 'Sistema', clave: 'exportar.datos', nombre: 'Exportar datos', ayuda: 'CSV, Excel y Habeas Data' },
  { grupo: 'Control', clave: 'auditoria.ver', nombre: 'Ver auditoría', ayuda: 'Actividad por usuario y logs de seguridad' },
  { grupo: 'Control', clave: 'metricas.ver', nombre: 'Ver métricas', ayuda: 'Productividad de los últimos 7 días' }
];
// Matriz de switches de un usuario, agrupada y alineada (checkbox en columna fija)
function renderMatrizPermisos(u, lista) {
//  R4-fix: descarta entradas sin clave (evita matriz vacía o filas "undefined")
const listaSegura = (Array.isArray(lista) ? lista : []).filter(p => p && p.clave && p.nombre);
if (!listaSegura.length) return '<div class="eq-matriz"><small style="color:#6b7280;">Sin catálogo de permisos disponible.</small></div>';
const grupos = [...new Set(listaSegura.map(p => p.grupo))];
return `<div class="eq-matriz">` + grupos.map(gr => `<div class="eq-grupo"><div class="eq-grupo-titulo">${escapeHtml(gr)}</div> ${listaSegura.filter(p => p.grupo === gr).map(p =>`<label class="eq-check" title="${escapeAttr(p.ayuda)}">
          <input type="checkbox" class="chk-permiso" data-uid="${u.id}" data-clave="${p.clave}" ${(u.permisos || []).includes(p.clave) ? 'checked' : ''}>
          <span class="eq-nombre">${escapeHtml(p.nombre)}</span>
          <span class="eq-ayuda">${escapeHtml(p.ayuda)}</span>
        </label>`).join('')}
    </div>`).join('') + `</div>`;
}
// Checklist del modal de invitación (mismos nombres, mismas claves)
function renderChecklistInvitacion() {
  const grupos = [...new Set(PERMISOS_UI.map(p => p.grupo))];
  return `<div class="eq-matriz">` + grupos.map(gr => `
    <div class="eq-grupo">
      <div class="eq-grupo-titulo">${escapeHtml(gr)}</div>
      ${PERMISOS_UI.filter(p => p.grupo === gr).map(p => `
        <label class="eq-check" title="${escapeAttr(p.ayuda)}">
          <input type="checkbox" class="chk-inv" value="${p.clave}">
          <span class="eq-nombre">${escapeHtml(p.nombre)}</span>
          <span class="eq-ayuda">${escapeHtml(p.ayuda)}</span>
        </label>`).join('')}
    </div>`).join('') + `</div>`;
}
async function cargarEquipo() {
  const contenedor = document.getElementById('contenedor-modulos');
  if (!contenedor) return;
  contenedor.innerHTML = `
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
      <h3 style="margin:0;">${ico('users')} Equipo y permisos</h3>
      <button class="btn btn-sm" style="background:#059669;" onclick="mostrarModalInvitar()">${ico('plus')} Invitar miembro</button>
    </div>
    <div class="alert alert-info" style="margin-bottom:1rem;">Los cambios de permisos o desactivación <strong>cierran la sesión activa</strong> del miembro afectado (debe volver a ingresar). Las 4 claves reservadas (usuarios.gestionar, sesiones.limpiar, rate_limits.limpiar, seguridad.diagnosticar) no se asignan: son del superadmin.</div>
    <div id="equipoContenido"><p style="color:#6b7280;text-align:center;padding:2rem;">${ico('clock')} Cargando equipo…</p></div>
  </div>`;
  try {
    const res = await fetchAPI('/api/admin/usuarios');
    if (!res.ok) throw new Error((await res.json()).error || 'Error');
    const data = await res.json();
equipoCache = data.data || [];
//  R4-fix: el server puede omitir `catalogo` o devolverlo como array de claves (strings).
// Lo normalizamos al catálogo UI (mismas claves que PERMISOS_CONMUTABLES del server).
// Si no viene, usamos PERMISOS_UI completo (contraseña de claves idéntica).
const catalogoServidor = Array.isArray(data.catalogo) ? data.catalogo : [];
const clavesServidor = catalogoServidor.map(c => (typeof c === 'string' ? c : (c && c.clave))).filter(Boolean);
const catalogo = clavesServidor.length
  ? PERMISOS_UI.filter(p => clavesServidor.includes(p.clave))
  : PERMISOS_UI;
    const cont = document.getElementById('equipoContenido');
    if (!equipoCache.length) { cont.innerHTML = '<p style="color:#6b7280;text-align:center;padding:2rem;">Sin miembros registrados.</p>'; return; }
    cont.innerHTML = equipoCache.map(u => `
      <div class="card" style="background:#f9fafb;margin-bottom:1rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.6rem;margin-bottom:0.8rem;">
          <div>
            <strong>${escapeHtml(u.email)}</strong>
            ${u.es_superadmin ? '<span class="badge badge-aprobado" style="margin-left:0.4rem;">SUPERADMIN</span>' : ''}
            ${u.activo ? '<span class="badge badge-aprobado" style="margin-left:0.4rem;">ACTIVO</span>' : '<span class="badge badge-rechazado" style="margin-left:0.4rem;">INACTIVO</span>'}
            ${u.debe_cambiar_password ? '<span class="badge badge-pendiente" style="margin-left:0.4rem;">DEBE CAMBIAR CLAVE</span>' : ''}
          </div>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
${u.es_superadmin ? '' : `
 <button class="btn btn-sm btn-secondary" onclick="togglePermisosMiembro(${u.id}, this)">${ico('eye')} Ver permisos</button>
 <button class="btn btn-sm btn-secondary" onclick="guardarPermisosUsuario(${u.id})">${ico('save')} Guardar permisos</button>
${u.activo
? `<button class="btn btn-sm btn-danger" onclick="toggleActivoUsuario(${u.id}, 0, '${escapeAttr(u.email)}')">${ico('ban')} Desactivar</button>`
: `<button class="btn btn-sm btn-success" onclick="toggleActivoUsuario(${u.id}, 1, '${escapeAttr(u.email)}')">${ico('check')} Activar</button>`}
${!esYoMiembro(u) ? `<button class="btn btn-sm btn-warning" onclick="toggleSuperadminMiembro(${u.id}, true, '${escapeAttr(u.email)}')"> Hacer superadmin</button>` : ''}
`}
${u.es_superadmin && !esYoMiembro(u) ? `<button class="btn btn-sm btn-warning" onclick="toggleSuperadminMiembro(${u.id}, false, '${escapeAttr(u.email)}')">${ico('download')} Quitar superadmin</button>` : ''}
<button class="btn btn-sm btn-secondary" onclick="cambiarEmailMiembro(${u.id}, '${escapeAttr(u.email)}')">${ico('edit')} Cambiar email</button>
${u.email === (document.getElementById('userEmail')?.textContent || '').trim() ? '' : `<button class="btn btn-sm btn-negro" onclick="eliminarMiembroEquipo(${u.id}, '${escapeAttr(u.email)}')">${ico('trash')} Eliminar</button>`}
          </div>
        </div>
        ${u.es_superadmin ? '<small style="color:#6b7280;">El superadmin tiene bypass total: no requiere switches.</small>' : `
        <div id="eqPermisos-${u.id}" style="display:none;margin-top:0.4rem;">
          ${renderMatrizPermisos(u, catalogo)}
        </div>`}
      </div>`).join('');
  } catch (e) {
    const cont = document.getElementById('equipoContenido');
    if (cont) cont.innerHTML = `<div class="alert alert-error">${ico('x')} Error: ${e.message}</div>`;
  }
}
//  R4-fix: mostrar/ocultar la matriz de permisos de un miembro (ahorra espacio vertical)
function togglePermisosMiembro(uid, btn) {
  const caja = document.getElementById('eqPermisos-' + uid);
  if (!caja) return;
  const abierto = caja.style.display !== 'none';
  caja.style.display = abierto ? 'none' : 'block';
  if (btn) btn.textContent = abierto ? ' Ver permisos' : ' Ocultar permisos';
}
//  R4-fix: eliminar miembro del equipo (baja definitiva con confirmación Swal).
// El server aplica los candados D8 (no auto-eliminación, último superadmin intocable).
async function eliminarMiembroEquipo(uid, email) {
  const ok = await confirmarSwal({
    titulo: ' Eliminar miembro del equipo',
    texto: `Se eliminará permanentemente la cuenta ${email} y se cerrarán sus sesiones activas. Esta acción NO se puede deshacer.`,
    textoConfirmar: 'Sí, eliminar'
  });
  if (!ok) return;
  try {
    const res = await fetchAPI(`/api/admin/usuarios/${uid}`, { method: 'DELETE' });
    const r = await res.json().catch(() => ({}));
    if (!res.ok) { mostrarAlerta(' ' + (r.error || 'Error al eliminar'), 'error'); return; }
    mostrarAlerta(' ' + (r.mensaje || 'Miembro eliminado'), 'success');
    await cargarEquipo();
  } catch (e) {
    mostrarAlerta(' Error de conexión', 'error');
  }
}
//  R4.1: ¿el miembro es yo mismo? (oculta promover/degradar propios — D8)
function esYoMiembro(u) {
  return u.email === (document.getElementById('userEmail')?.textContent || '').trim();
}
//  R4.1: cambiar correo de un miembro (conserva superadmin, permisos e historial)
async function cambiarEmailMiembro(uid, emailActual) {
  const r = await Swal.fire({
    title: ' Cambiar correo del miembro',
    html: `<p style="margin:0 0 .6rem 0;color:#6b7280;">Actual: <strong>${escapeHtml(emailActual)}</strong></p>`,
    input: 'email',
    inputValue: emailActual,
    showCancelButton: true,
    confirmButtonText: ' Guardar',
    cancelButtonText: 'Cancelar',
    confirmButtonColor: '#8600dd',
    cancelButtonColor: '#6b7280',
    inputValidator: (v) => (!v || !v.trim()) ? 'Escribe un correo válido.' : null
  });
  if (!r.isConfirmed) return;
  try {
    const res = await fetchAPI(`/api/admin/usuarios/${uid}/email`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: r.value.trim() })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Error');
    mostrarAlerta(' ' + d.mensaje, 'success');
    await cargarEquipo();
  } catch (e) { mostrarAlerta(' ' + e.message, 'error'); }
}
//  R4.1: promover/degradar superadmin (D8: sin auto-cambio; último activo intocable)
async function toggleSuperadminMiembro(uid, promover, email) {
  const ok = await confirmarSwal({
    titulo: promover ? ' Hacer superadmin' : ' Quitar superadmin',
    texto: promover
      ? `${email} tendrá bypass total: equipo, permisos y todos los módulos.`
      : `${email} pasará a admin regular: solo lo que permitan sus permisos.`,
    peligro: !promover,
    textoConfirmar: promover ? 'Sí, promover' : 'Sí, quitar'
  });
  if (!ok) return;
  try {
    const res = await fetchAPI(`/api/admin/usuarios/${uid}/superadmin`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ es_superadmin: promover ? 1 : 0 })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Error');
    mostrarAlerta(' ' + d.mensaje, 'success');
    await cargarEquipo();
  } catch (e) { mostrarAlerta(' ' + e.message, 'error'); }
}
async function guardarPermisosUsuario(uid) {
  const claves = [];
  document.querySelectorAll(`.chk-permiso[data-uid="${uid}"]:checked`).forEach(c => claves.push(c.dataset.clave));
  if (!await confirmarSwal({ titulo: ' Cambiar permisos', texto: 'Se cerrará la sesión activa del miembro afectado.', peligro: false, textoConfirmar: 'Sí, guardar' })) return;
  try {
    const res = await fetchAPI(`/api/admin/usuarios/${uid}/permisos`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ permisos: claves })
    });
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || 'Error');
    mostrarAlerta(' ' + r.mensaje, 'success');
    await cargarEquipo();
  } catch (e) { mostrarAlerta(' ' + e.message, 'error'); }
}
async function toggleActivoUsuario(uid, activo, email) {
  const texto = activo ? `Activar a ${email}` : `Desactivar a ${email}. Sus sesiones activas se cerrarán.`;
  if (!await confirmarSwal({ titulo: activo ? ' Activar miembro' : ' Desactivar miembro', texto, peligro: !activo, textoConfirmar: 'Sí, continuar' })) return;
  try {
    const res = await fetchAPI(`/api/admin/usuarios/${uid}/activo`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activo })
    });
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || 'Error');
    mostrarAlerta(' ' + r.mensaje, 'success');
    await cargarEquipo();
  } catch (e) { mostrarAlerta(' ' + e.message, 'error'); }
}
function mostrarModalInvitar() {
  const previo = document.getElementById('modalInvitarStaff');
  if (previo) previo.remove();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay active';
  overlay.id = 'modalInvitarStaff';
  overlay.style.zIndex = '9500';
  overlay.innerHTML = `
  <div class="modal" style="max-width:560px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
      <h3 style="margin:0;">${ico('plus')} Invitar miembro al equipo</h3>
      <button class="btn btn-sm btn-secondary" onclick="cerrarModalInvitar()"> Cerrar</button>
    </div>
    <div class="form-group"><label>${ico('mail')} Email corporativo *</label><input type="email" id="invEmail" placeholder="nombre@unab.edu.co"></div>
    <div class="form-group"><label> Nombre o área (opcional)</label><input type="text" id="invNombre" placeholder="Ej: Nayardy — Verificación"></div>
    <div class="form-group"><label>${ico('key')} Permisos iniciales</label>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.3rem 1rem;max-height:180px;overflow-y:auto;border:1px solid #e5e7eb;border-radius:6px;padding:0.6rem;">
        ${renderChecklistInvitacion()}
      </div>
      <small style="color:#6b7280;">Recibirá un correo con enlace de activación válido por 7 días (un solo uso).</small>
    </div>
    <div id="invAlerta"></div>
    <div style="display:flex;gap:0.5rem;">
      <button class="btn btn-secondary" style="flex:1;" onclick="cerrarModalInvitar()">Cancelar</button>
      <button class="btn" style="flex:1;background:#059669;" onclick="enviarInvitacionStaff()">${ico('send')} Enviar invitación</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) cerrarModalInvitar(); });
}
function cerrarModalInvitar() {
  const m = document.getElementById('modalInvitarStaff');
  if (m) m.remove();
}
async function enviarInvitacionStaff() {
  const email = document.getElementById('invEmail').value.trim();
  const nombre = document.getElementById('invNombre').value.trim();
  const permisos = [];
  document.querySelectorAll('.chk-inv:checked').forEach(c => permisos.push(c.value));
  const alerta = document.getElementById('invAlerta');
  if (!email) { alerta.innerHTML = '<div class="alert alert-error">Escribe un email válido.</div>'; return; }
  try {
    const res = await fetchAPI('/api/admin/usuarios', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, nombre_empresa: nombre, permisos })
    });
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || 'Error');
    cerrarModalInvitar();
    mostrarAlerta(' ' + r.mensaje, 'success', 6000);
    await cargarEquipo();
  } catch (e) { alerta.innerHTML = `<div class="alert alert-error">${ico('x')} ${e.message}</div>`; }
}
// ==========================================
//  INICIAR APLICACIÓN
// ==========================================
console.log(' Panel de Administración con nuevo flujo cargado');
console.log(' fetchAPI helper activo (credentials: include)');
init();
