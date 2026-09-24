function fetchAPI(url, options = {}) {
return fetch(url, { ...options, credentials: 'include' });
}
function mostrarAlerta(msg, tipo = 'error') {
const html = `<div class="alert alert-${tipo}">${msg}</div>`;
const a = document.getElementById('Al1Lg6');
const b = document.getElementById('Ar8Rg3');
if (a) a.innerHTML = html;
if (b) b.innerHTML = html;
setTimeout(() => { if (a) a.innerHTML = ''; if (b) b.innerHTML = ''; }, 5000);
}
function mostrarAlertaPassword(msg, tipo = 'error') {
const el = document.getElementById('Ap7Pw5');
if (!el) return;
el.innerHTML = `<div class="alert alert-${tipo}">${msg}</div>`;
setTimeout(() => { el.innerHTML = ''; }, 5000);
}
function validarPasswordCliente(password) {
if (!password || typeof password !== 'string') {
return { valido: false, mensaje: 'La contraseña debe ser un texto válido' };
}
const trimmed = password.trim();
if (trimmed.length < 8) return { valido: false, mensaje: 'La contraseña debe tener al menos 8 caracteres' };
if (!/[A-Z]/.test(trimmed)) return { valido: false, mensaje: 'Debe contener al menos una letra mayúscula (A-Z)' };
if (!/[a-z]/.test(trimmed)) return { valido: false, mensaje: 'Debe contener al menos una letra minúscula (a-z)' };
if (!/[0-9]/.test(trimmed)) return { valido: false, mensaje: 'Debe contener al menos un número (0-9)' };
if (!/[!@#$%^&*(),.?":{}|<>]/.test(trimmed)) return { valido: false, mensaje: 'Debe contener al menos un carácter especial (!@#$%^&*...)' };
return { valido: true, mensaje: 'Contraseña válida' };
}

document.querySelectorAll('.toggle-password').forEach(btn => {
btn.addEventListener('click', () => {
const target = document.querySelector(btn.dataset.target);
if (!target) return;
const esPassword = target.type === 'password';
target.type = esPassword ? 'text' : 'password';
btn.innerHTML = esPassword ? ico('eye-off') : ico('eye');
});
});
// ==========================================
//  G2: MEDIDOR DE FORTALEZA DE CONTRASEÑA (solo aviso)
// Espejo exacto de validarPasswordCliente / security.js: 8+ caracteres,
// mayúscula, minúscula, número y especial. NUNCA bloquea el envío:
// el server sigue siendo la autoridad de la política.
// ==========================================

const lpContainer = (document.getElementById('Qk3Rv8') || document.getElementById('container'))
const registerBtn = document.getElementById('Hn7Lp2');
const loginBtn = document.getElementById('Jm4Xs9');
const mRegisterBtn = document.getElementById('Wq6Yt1');
const mLoginBtn = document.getElementById('Zf8Bu3');
if (registerBtn) registerBtn.addEventListener('click', () => lpContainer.classList.add('active'));
if (mRegisterBtn) mRegisterBtn.addEventListener('click', (e) => { e.preventDefault(); lpContainer.classList.add('active'); });
if (loginBtn) loginBtn.addEventListener('click', () => lpContainer.classList.remove('active'));
if (mLoginBtn) mLoginBtn.addEventListener('click', (e) => { e.preventDefault(); lpContainer.classList.remove('active'); });
document.getElementById('Fl2Hc4').addEventListener('submit', async e => {
e.preventDefault();
const btn = e.target.querySelector('button[type="submit"]');
const textoOriginal = btn.textContent;
btn.disabled = true;
btn.textContent = ' Iniciando sesión...';
try {
const data = Object.fromEntries(new FormData(e.target));
const res = await fetchAPI('/api/login', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(data)
});
const r = await res.json();
if (!res.ok) {
if (res.status === 429 && r.minutos_restantes) {
mostrarAlerta(` ${r.error || 'Demasiados intentos.'} Espera ${r.minutos_restantes} minutos.`);
} else {
mostrarAlerta(r.error || 'Error al iniciar sesión');
}
btn.disabled = false;
btn.textContent = textoOriginal;
return;
}
if (r.debe_cambiar_password) {
mostrarAlerta(' Inicio exitoso. Cambia tu contraseña.', 'success');
setTimeout(() => { document.getElementById('Mp3Md8').classList.add('active'); }, 500);
} else {
mostrarAlerta(' Inicio exitoso. Redirigiendo...', 'success');
setTimeout(() => { window.location.href = r.rol === 'admin' ? 'admin.html' : 'proveedor.html'; }, 800);
}
} catch (err) {
console.error(' Error de conexión:', err);
mostrarAlerta('Error de conexión: ' + err.message);
btn.disabled = false;
btn.textContent = textoOriginal;
}
});
document.getElementById('Fr5Gd7').addEventListener('submit', async (e) => {
e.preventDefault();
const formData = new FormData(e.target);
const habeasDataCheckbox = document.querySelector('input[name="habeas_data"]');
const habeasData = habeasDataCheckbox ? habeasDataCheckbox.checked : false;
if (!habeasData) {
mostrarAlerta(' Debes aceptar la Política de Tratamiento de Datos Personales para registrarte');
return;
}
const password = formData.get('password');
const validacion = validarPasswordCliente(password);
if (!validacion.valido) {
mostrarAlerta(' ' + validacion.mensaje);
return;
}
const data = {
nombre_empresa: formData.get('nombre_empresa'),
email: formData.get('email'),
password: password,
habeas_data: 'true',
website: formData.get('website') || '',
_ts: formData.get('_ts') || ''
};
const btn = e.target.querySelector('button[type="submit"]');
const textoOriginal = btn.textContent;
btn.disabled = true;
btn.textContent = ' Creando cuenta...';
try {
const res = await fetchAPI('/api/registro', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(data)
});
const r = await res.json();
if (res.ok) {
mostrarAlerta(' Cuenta creada exitosamente. Ya puedes iniciar sesión.', 'success');
e.target.reset();
setTimeout(() => {
const c = (document.getElementById('Qk3Rv8') || document.getElementById('container'))
if (c) c.classList.remove('active');
}, 1200);
} else {
mostrarAlerta(' ' + (r.error || 'Error al registrarse'));
}
} catch (err) {
console.error(' Error:', err);
mostrarAlerta(' Error de conexión: ' + err.message);
} finally {
btn.disabled = false;
btn.textContent = textoOriginal;
}
});
document.getElementById('Fc9Ke6').addEventListener('submit', async e => {
e.preventDefault();
const data = Object.fromEntries(new FormData(e.target));
if (data.password_nueva !== data.password_confirmar) {
return mostrarAlertaPassword('Las contraseñas nuevas no coinciden');
}
const validacion = validarPasswordCliente(data.password_nueva);
if (!validacion.valido) {
return mostrarAlertaPassword(' ' + validacion.mensaje);
}
const btn = e.target.querySelector('button[type="submit"]');
const textoOriginal = btn.textContent;
btn.disabled = true;
btn.textContent = ' Cambiando...';
try {
const res = await fetchAPI('/api/cambiar-password', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({
password_actual: data.password_actual,
password_nueva: data.password_nueva
})
});
const r = await res.json();
if (!res.ok) {
mostrarAlertaPassword(r.error || 'Error al cambiar contraseña');
btn.disabled = false;
btn.textContent = textoOriginal;
return;
}
mostrarAlertaPassword(' Contraseña cambiada. Redirigiendo...', 'success');
setTimeout(async () => {
try {
const meRes = await fetchAPI('/api/me');
const me = await meRes.json();
if (me.usuario) {
window.location.href = me.usuario.rol === 'admin' ? 'admin.html' : 'proveedor.html';
} else {
window.location.href = '/';
}
} catch (err) {
window.location.href = '/';
}
}, 1500);
} catch (err) {
console.error(' Error:', err);
mostrarAlertaPassword('Error de conexión: ' + err.message);
btn.disabled = false;
btn.textContent = textoOriginal;
}
});
document.getElementById('Mp3Md8').addEventListener('click', e => {
if (e.target.id === 'Mp3Md8') {
document.getElementById('Mp3Md8').classList.remove('active');
}
});

try { const _t = document.getElementById('Ts6Tm1'); if (_t) _t.value = Date.now(); } catch (e) {}
// ==========================================
//  G2: MEDIDOR DE FORTALEZA (index) — solo aviso, nunca bloquea.
//  Anti-colisión: todo vive DENTRO del IIFE (nombres internos), así no
// choca con bloques G2 antiguos ni sufre TDZ. Guards totales por elemento.
// ==========================================
(function initMedidorG2Index() {
const REGLAS = {
len: v => v.length >= 8,
may: v => /[A-ZÁÉÍÓÚÑ]/.test(v),
min: v => /[a-záéíóúñ]/.test(v),
num: v => /\d/.test(v),
esp: v => /[^A-Za-z0-9\s]/.test(v)
};
const ETIQ = { 0: '—', 1: 'Muy débil', 2: 'Débil', 3: 'Aceptable', 4: 'Buena', 5: 'Fuerte' };
function fortaleza(v) {
return Object.keys(REGLAS).filter(k => REGLAS[k](v || '')).length;
}
function conectar(selInput, idMeter, idHint) {
const inp = document.querySelector(selInput);
const meter = document.getElementById(idMeter);
const hint = document.getElementById(idHint);
if (!inp || !meter) return; //  sin markup = sin medidor, sin error
const pintar = () => {
const v = inp.value || '';
const score = fortaleza(v);
meter.setAttribute('data-score', String(v ? score : 0));
if (hint) hint.textContent = v ? ('Seguridad: ' + ETIQ[score]) : '';
};
inp.addEventListener('input', pintar);
inp.addEventListener('blur', pintar);
pintar();
}
conectar('#Rp7Pw2', 'Mr5Xq3', 'Hr9Ys2'); //  registro público
conectar('#Cn2Nw7', 'Mp3Mt1', 'Mp3Ht1'); //  modal cambio obligatorio
})();
console.log(' Portal de Proveedores cargado (v4.7)');
// ==========================================
// CSP L3: fallback de imágenes por delegación (captura), sin onerror inline
// ==========================================
document.addEventListener('error', function (e) {
  const el = e.target;
  if (!el || el.tagName !== 'IMG') return;
  if (el.dataset.imgHideOnError === '1') {
    el.style.display = 'none';
    const next = el.nextElementSibling;
    if (next) next.style.display = 'inline-block';
  }
  if (el.dataset.imgSelfHide === '1') {
    if (el.dataset.imgSelfHideArmed === '1') el.style.display = 'none';
    else el.dataset.imgSelfHideArmed = '1';
  }
}, true);
