function fetchAPI(url, options = {}) {
      return fetch(url, { ...options, credentials: 'include' });
    }

    function mostrarAlerta(msg, tipo = 'error') {
      const el = document.getElementById('alerta');
      el.innerHTML = `<div class="alert alert-${tipo}">${msg}</div>`;
      if (tipo !== 'success') setTimeout(() => { el.innerHTML = ''; }, 6000);
    }

    document.getElementById('form-recuperar').addEventListener('submit', async (e) => {
      e.preventDefault();

      const email = document.getElementById('email').value.trim();
      if (!email) {
        mostrarAlerta('Por favor ingresa tu correo electrónico');
        return;
      }

      const btn = document.getElementById('btnEnviar');
      const textoOriginal = btn.textContent;
      btn.disabled = true;
      btn.textContent = ' Enviando...';

      try {
        const res = await fetchAPI('/api/recuperar-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });

        const r = await res.json();

        if (res.ok) {
          mostrarAlerta(' ' + (r.mensaje || 'Si el email está registrado, recibirás instrucciones.'), 'success');
          document.getElementById('form-recuperar').reset();
        } else {
          mostrarAlerta(' ' + (r.error || 'Error al procesar la solicitud'));
        }
      } catch (err) {
        console.error('Error:', err);
        mostrarAlerta(' Error de conexión: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = textoOriginal;
      }
    });
