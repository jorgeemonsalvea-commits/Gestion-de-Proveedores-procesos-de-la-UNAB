function fetchAPI(url, options = {}) {
      return fetch(url, { ...options, credentials: 'include' });
    }

    function mostrarAlerta(msg, tipo = 'error') {
      const el = document.getElementById('alerta');
      el.innerHTML = `<div class="alert alert-${tipo}">${msg}</div>`;
      if (tipo !== 'success') setTimeout(() => { el.innerHTML = ''; }, 6000);
    }

    // Validación de contraseña alineada con security.js del backend
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

    // Toggle mostrar/ocultar contraseña
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
//  G2: MEDIDOR DE FORTALEZA (solo aviso; el server valida siempre)
// ==========================================
const PASS_REGLAS = {
len: v => v.length >= 8,
may: v => /[A-ZÁÉÍÓÚÑ]/.test(v),
min: v => /[a-záéíóúñ]/.test(v),
num: v => /\d/.test(v),
esp: v => /[^A-Za-z0-9\s]/.test(v)
};
const PASS_ETIQUETAS = { 0: '—', 1: 'Muy débil', 2: 'Débil', 3: 'Aceptable', 4: 'Buena', 5: 'Fuerte' };
function medidorFortaleza(v) {
return Object.keys(PASS_REGLAS).filter(k => PASS_REGLAS[k](v || '')).length;
}
(function conectarMedidorPass() {
const inp = document.getElementById('password');
const meter = document.getElementById('pwMeter');
const hint = document.getElementById('pwHint');
if (!inp || !meter) return;
const pintar = () => {
const v = inp.value || '';
const score = medidorFortaleza(v);
meter.setAttribute('data-score', String(v ? score : 0));
if (hint) hint.textContent = v ? ('Seguridad: ' + PASS_ETIQUETAS[score]) : '';
};
inp.addEventListener('input', pintar);
})();
// Extraer token de la URL
function obtenerToken() {
      const params = new URLSearchParams(window.location.search);
      return params.get('token');
    }

    // Verificar token al cargar la página
    async function verificarToken() {
      const token = obtenerToken();

      if (!token) {
        document.getElementById('seccion-formulario').classList.add('hidden');
        document.getElementById('seccion-error').classList.remove('hidden');
        return;
      }

      try {
        const res = await fetchAPI(`/api/verificar-token/${token}`);
        const data = await res.json();

        if (!data.valido) {
          document.getElementById('seccion-formulario').classList.add('hidden');
          document.getElementById('seccion-error').classList.remove('hidden');
        }
      } catch (err) {
        console.error('Error verificando token:', err);
        document.getElementById('seccion-formulario').classList.add('hidden');
        document.getElementById('seccion-error').classList.remove('hidden');
      }
    }

    // Enviar nueva contraseña
document.getElementById('form-restablecer').addEventListener('submit', async (e) => {
e.preventDefault();
const token = obtenerToken();
//  FIX crash: leer por NAME desde el form (inmune a ids rotos/ausentes)
// y validar nulos ANTES de operar. El error anterior venía de
// document.getElementById(...) = null cuando el markup tenía ids dañados.
const password = e.target.elements['password'] ? e.target.elements['password'].value : '';
const passwordConfirmar = e.target.elements['password_confirmar'] ? e.target.elements['password_confirmar'].value : '';
if (!password || !passwordConfirmar) {
mostrarAlerta(' Completa los dos campos de contraseña para continuar.');
return;
}

      if (password !== passwordConfirmar) {
        mostrarAlerta(' Las contraseñas no coinciden');
        return;
      }

      const validacion = validarPasswordCliente(password);
      if (!validacion.valido) {
        mostrarAlerta(' ' + validacion.mensaje);
        return;
      }

      const btn = document.getElementById('btnRestablecer');
      const textoOriginal = btn.textContent;
      btn.disabled = true;
      btn.textContent = ' Restableciendo...';

      try {
        const res = await fetchAPI('/api/restablecer-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, password })
        });

        const r = await res.json();

        if (res.ok) {
          mostrarAlerta(' ' + (r.mensaje || 'Contraseña restablecida exitosamente.'), 'success');
          document.getElementById('form-restablecer').reset();
          setTimeout(() => { window.location.href = 'index.html'; }, 2500);
        } else {
          mostrarAlerta(' ' + (r.error || 'Error al restablecer la contraseña'));
          if (r.error && r.error.includes('expirado')) {
            setTimeout(() => {
              document.getElementById('seccion-formulario').classList.add('hidden');
              document.getElementById('seccion-error').classList.remove('hidden');
            }, 2000);
          }
        }
      } catch (err) {
        console.error('Error:', err);
        mostrarAlerta(' Error de conexión: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = textoOriginal;
      }
    });

    // Inicializar
    verificarToken();
