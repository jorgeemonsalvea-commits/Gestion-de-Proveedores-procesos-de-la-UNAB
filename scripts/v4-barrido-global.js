/* eslint-env node */
'use strict';

// ============================================================================
// Sprint 9 · V4 — BARRIDO GLOBAL (admin.js + email.js + server.js + css/html)
// ----------------------------------------------------------------------------
// D20: correos sin pictogramas (Outlook no soporta SVG): se eliminan.
// D19/P14: © ® ™ se conservan (lookahead negativo).
// Estrategia:
//   1) Parches específicos en admin.js: sitios donde el icono debe quedar
//      como ico() (botones tema/sonido, maps de historial/auditoría,
//      estado de ciclo, vencimiento y badges de evaluación).
//   2) Strip genérico del resto de pictogramas en .js (toasts Swal, textos
//      de botones textContent, console.log, asuntos, comentarios).
//   3) .css: strip SOLO dentro de comentarios (protege content con escape CSS, p.ej. '\2715').
//   4) .html: limpieza de texto visible y atributos (mecánica V3).
// Uso: node scripts/v4-barrido-global.js          (dry-run)
//      node scripts/v4-barrido-global.js --apply  (escribe)
// Idempotente: segunda pasada = "sin cambios".
// ============================================================================

const fs = require('fs');
const path = require('path');

const APPLY = process.argv.includes('--apply');
const ROOT = process.cwd();

// Pictogramas (Extended_Pictographic + glifos sueltos usados como icono),
// excluyendo signos tipográficos/legales © ® ™ (D19).
const PICTO = /(?![\u00A9\u00AE\u2122])(?:\p{Extended_Pictographic}|[\u2715\u2716\u2717\u274C\u2705\u26A0\u23F3\u23F0\u2600\u263E\u267B\u270F\u2139\u260E])\uFE0F?/gu;

function strip(s) {
  PICTO.lastIndex = 0;
  return String(s).replace(PICTO, '').replace(/\uFE0F/g, '');
}

// ----------------------------------------------------------------------------
// 1) Parches específicos admin.js (el icono sobrevive como ico())
// ----------------------------------------------------------------------------
const PATCHES_ADMIN = [
  // D1 tema / D4 sonido: textContent -> innerHTML + ico()
  { re: /btn\.textContent\s*=\s*tema\s*===\s*'oscuro'\s*\?\s*'\u{2600}\uFE0F?'\s*:\s*'\u{1F319}';/gu,
    to: "btn.innerHTML = tema === 'oscuro' ? ico('sun') : ico('moon');" },
  { re: /btn\.textContent\s*=\s*sonidoActivado\s*\?\s*'\u{1F50A}\uFE0F?'\s*:\s*'\u{1F507}';/gu,
    to: "btn.innerHTML = sonidoActivado ? ico('volume') : ico('volume-off');" },
  { re: /btnSonido\.textContent\s*=\s*sonidoActivado\s*\?\s*'\u{1F50A}\uFE0F?'\s*:\s*'\u{1F507}';/gu,
    to: "btnSonido.innerHTML = sonidoActivado ? ico('volume') : ico('volume-off');" },

  // Maps de iconos de historial (proveedor) y auditoría (admin)
  { re: /registro:\s*'\u{1F389}\uFE0F?'/gu, to: "registro: ico('award')" },
  { re: /documento_subido:\s*'\u{1F4E4}\uFE0F?'/gu, to: "documento_subido: ico('upload')" },
  { re: /documento_reemplazado:\s*'\u{1F504}\uFE0F?'/gu, to: "documento_reemplazado: ico('refresh')" },
  { re: /documento_eliminado:\s*'\u{1F5D1}\uFE0F?'/gu, to: "documento_eliminado: ico('trash')" },
  { re: /documento_aprobado:\s*'\u2705\uFE0F?'/gu, to: "documento_aprobado: ico('check')" },
  { re: /documento_rechazado:\s*'\u274C\uFE0F?'/gu, to: "documento_rechazado: ico('x')" },
  { re: /documento_verificado:\s*'\u{1F50D}\uFE0F?'/gu, to: "documento_verificado: ico('search')" },
  { re: /datos_actualizados:\s*'\u270F\uFE0F?'/gu, to: "datos_actualizados: ico('edit')" },
  { re: /recordatorio_enviado:\s*'\u{1F4E8}\uFE0F?'/gu, to: "recordatorio_enviado: ico('send')" },
  { re: /nota_agregada:\s*'\u{1F4DD}\uFE0F?'/gu, to: "nota_agregada: ico('message')" },
  { re: /documento_no_aplica:\s*'\u{1F4CB}\uFE0F?'/gu, to: "documento_no_aplica: ico('clipboard')" },
  { re: /documento_requiere_carga:\s*'\u{1F4C4}\uFE0F?'/gu, to: "documento_requiere_carga: ico('file')" },
  { re: /gestion_actualizada:\s*'\u{1F4CB}\uFE0F?'/gu, to: "gestion_actualizada: ico('clipboard')" },
  { re: /cambio_etapa:\s*'\u{1F504}\uFE0F?'/gu, to: "cambio_etapa: ico('refresh')" },
  { re: /evaluacion_subida:\s*'\u{1F4C4}\uFE0F?'/gu, to: "evaluacion_subida: ico('file')" },
  { re: /evaluacion_estado_cambiado:\s*'\u{1F4CB}\uFE0F?'/gu, to: "evaluacion_estado_cambiado: ico('clipboard')" },
  { re: /evaluacion_eliminada:\s*'\u{1F5D1}\uFE0F?'/gu, to: "evaluacion_eliminada: ico('trash')" },
  { re: /solicitud_actualizacion:\s*'\u{1F504}\uFE0F?'/gu, to: "solicitud_actualizacion: ico('refresh')" },
  { re: /vencimiento_automatico:\s*'\u23F0\uFE0F?'/gu, to: "vencimiento_automatico: ico('clock')" },
  { re: /vencimiento_forzado:\s*'\u26A1\uFE0F?'/gu, to: "vencimiento_forzado: ico('zap')" },
  { re: /proceso_reiniciado:\s*'\u267B\uFE0F?'/gu, to: "proceso_reiniciado: ico('refresh')" },
  { re: /reinicio_automatico:\s*'\u267B\uFE0F?'/gu, to: "reinicio_automatico: ico('refresh')" },
  { re: /tipo_persona_definido:\s*'\u{1F9FE}\uFE0F?'/gu, to: "tipo_persona_definido: ico('file-text')" },
  { re: /email_cambiado:\s*'\u{1F4E7}\uFE0F?'/gu, to: "email_cambiado: ico('mail')" },
  { re: /login_exitoso:\s*'\u{1F510}\uFE0F?'/gu, to: "login_exitoso: ico('lock')" },
  { re: /login_fallido_admin:\s*'\u26A0\uFE0F?'/gu, to: "login_fallido_admin: ico('alert')" },
  { re: /\|\|\s*'\u{1F4CC}\uFE0F?'/gu, to: "|| ico('pin')" },

  // Estado de ciclo (Historial de actualizaciones)
  { re: /const estadoIcon = c\.estado === 'activo' \? '\u{1F7E2}\uFE0F?' : c\.estado === 'cerrado'\s*\?\s*'\u{1F512}\uFE0F?' : '\u{1F534}\uFE0F?';/gu,
    to: "const estadoIcon = c.estado === 'activo' ? ico('check-circle', 'ico-exito') : c.estado === 'cerrado' ? ico('lock', 'ico-muted') : ico('x-circle', 'ico-peligro');" },

  // Vencimiento en modal de ciclo
  { re: /const vencimientoLabel = estadoVencimiento === 'vencido' \? '\u{1F534}\uFE0F? Vencido' : estadoVencimiento === 'proximo_a_vencer' \? '\u{1F7E1}\uFE0F? Próximo a vencer' : '\u{1F7E2}\uFE0F? Vigente';/gu,
    to: "const vencimientoLabel = estadoVencimiento === 'vencido' ? ico('x-circle', 'ico-peligro') + ' Vencido' : estadoVencimiento === 'proximo_a_vencer' ? ico('clock', 'ico-advertencia') + ' Próximo a vencer' : ico('check-circle', 'ico-exito') + ' Vigente';" },

  // Badges de evaluación inicial (rompen la comilla y concatenan ico())
  { re: /(?<=badge-faltante\s*">\s*)\u{1F4E6}\uFE0F?/gu, to: "' + ico('archive') + '" },
  { re: /(?<=badge-aprobado\s*">\s*)\u2705\uFE0F?/gu, to: "' + ico('check') + '" },
  { re: /(?<=badge-rechazado\s*">\s*)\u274C\uFE0F?/gu, to: "' + ico('x') + '" },
  { re: /(?<=badge-pendiente\s*">\s*)\u23F0\uFE0F?/gu, to: "' + ico('clock') + '" }
];

const PATCHES = { 'public/js/admin.js': PATCHES_ADMIN };

// ----------------------------------------------------------------------------
// 4) Limpieza HTML (mecánica V3): texto visible + atributos seguros
// ----------------------------------------------------------------------------
function cleanHtml(html) {
  return String(html).replace(
    /(<!--[\s\S]*?-->)|(<script\b[^>]*>[\s\S]*?<\/script>)|(<style\b[^>]*>[\s\S]*?<\/style>)|(<[^>]*>)|([^<]+)/gi,
    (m, comment, script, style, tag, text) => {
      if (script || style) return m;
      if (comment) return strip(comment);
      if (tag) {
        return tag.replace(
          /(placeholder|title|aria-label|alt|value|data-original-title)\s*=\s*("[^"]*"|'[^']*')/gi,
          (mm, attr, val) => attr + '=' + val.charAt(0) + strip(val.slice(1, -1)).trim() + val.charAt(0)
        );
      }
      return strip(text);
    }
  );
}

// ----------------------------------------------------------------------------
// Núcleo
// ----------------------------------------------------------------------------
const TARGETS = [
  'public/js/admin.js',
  'email.js',
  'server.js',
  'public/style.css',
  'public/admin.html'
];

function processFile(rel) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) { console.log('SKIP ' + rel + ' (no existe)'); return; }
  const orig = fs.readFileSync(abs, 'utf8');
  let src = orig;

  (PATCHES[rel] || []).forEach(p => { src = src.replace(p.re, () => p.to); });

  if (rel.endsWith('.css')) {
    src = src.replace(/\/\*[\s\S]*?\*\//g, m => strip(m));   // solo comentarios
  } else if (rel.endsWith('.html')) {
    src = cleanHtml(src);
  } else {
    src = strip(src);                                         // D20 en correos
  }

  if (src !== orig) {
    if (APPLY) { fs.writeFileSync(abs, src, 'utf8'); console.log('OK   ' + rel); }
    else console.log('DRY  ' + rel);
  } else {
    console.log('==   ' + rel + ' sin cambios');
  }
}

TARGETS.forEach(processFile);
console.log(APPLY ? 'V4 barrido aplicado.' : 'Dry-run completado. Aplica con --apply.');