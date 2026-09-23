/* eslint-env node */
'use strict';

// ============================================================================
// Sprint 9 · V3 — VERIFICADOR DE CIERRE (solo lectura)
// ----------------------------------------------------------------------------
// Valida los 4 criterios de cierre de V3 sin escribir nada:
//   1) Cero pictogramas en el alcance V3 (JS + HTML + scripts extraídos).
//   2) Sintaxis OK (node --check) en todo JS tocado + admin.js.
//   3) HTML del alcance sin <script> inline (extracción completa).
//   4) Hotfix Métricas aplicado (P13: sin ${ico(...)} dentro de atributos).
// Uso:  node scripts/v3-verificar-cierre.js
// Sale con código 1 si hay fallos (integrable a CI después).
// ============================================================================

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = process.cwd();

const SCOPE_JS = [
  'public/js/utils.js',
  'public/js/proveedor.js'
];

const SCOPE_HTML = [
  'public/index.html',
  'public/proveedor.html',
  'public/recuperar-password.html',
  'public/restablecer-password.html',
  'public/habeas-data.html'
];

const ADMIN_JS = 'public/js/admin.js';
const EXTRAIDOS_RE = /^v3-.*\.js$/;

// Pictogramas (D10): Extended_Pictographic + símbolos sueltos que se usan como glifos.
// D10: © (U+00A9), ® (U+00AE) y ™ (U+2122) son Extended_Pictographic en Unicode
// pero signos tipográficos/legales: se conservan, no se cuentan ni se barren.
const PICTO = /(?![\u00A9\u00AE\u2122])(?:\p{Extended_Pictographic}|[\u2715\u2716\u2717\u274C\u2705\u26A0\u23F3\u23F0\u2600\u263E\u267B\u270F\u2139\u260E])\uFE0F?/gu;

function leer(rel) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return null;
  return fs.readFileSync(abs, 'utf8');
}

function contarPictos(rel) {
  const txt = leer(rel);
  if (txt === null) return null;
  PICTO.lastIndex = 0;
  const m = txt.match(PICTO);
  return m ? m.length : 0;
}

function checkSintaxis(rel) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return { ok: false, msg: 'no existe' };
  const r = spawnSync(process.execPath, ['--check', abs], { encoding: 'utf8' });
  return { ok: r.status === 0, msg: r.status === 0 ? 'ok' : (r.stderr || '').split('\n')[0] };
}

function main() {
  let fallos = 0;

  // ---- 1) Pictogramas en alcance ----
  console.log('== V3 · pictogramas en alcance (D10) ==');
  const jsDir = path.join(ROOT, 'public/js');
  const extraidos = fs.existsSync(jsDir)
    ? fs.readdirSync(jsDir).filter(f => EXTRAIDOS_RE.test(f)).map(f => 'public/js/' + f)
    : [];
  const jsAlcance = SCOPE_JS.concat(extraidos);

  for (const rel of jsAlcance.concat(SCOPE_HTML)) {
    const n = contarPictos(rel);
    if (n === null) { console.log('SKIP ' + rel + ' (no existe)'); continue; }
    if (n > 0) { fallos++; console.log('FAIL ' + rel + ' -> ' + n + ' pictograma(s)'); }
    else { console.log('OK   ' + rel + ' -> 0'); }
  }

  // ---- 2) Sintaxis ----
  console.log('== V3 · sintaxis (node --check) ==');
  for (const rel of jsAlcance.concat([ADMIN_JS])) {
    const r = checkSintaxis(rel);
    if (!r.ok) { fallos++; console.log('FAIL ' + rel + ' -> ' + r.msg); }
    else { console.log('OK   ' + rel); }
  }

  // ---- 3) HTML sin scripts inline ----
  console.log('== V3 · HTML solo markup (sin <script> inline) ==');
  for (const rel of SCOPE_HTML) {
    const txt = leer(rel);
    if (txt === null) { console.log('SKIP ' + rel + ' (no existe)'); continue; }
    const inline = txt.match(/<script\b(?![^>]*\bsrc\s*=)[^>]*>/gi);
    if (inline && inline.length) {
      fallos++;
      console.log('FAIL ' + rel + ' -> ' + inline.length + ' script(s) inline sin extraer');
    } else {
      console.log('OK   ' + rel + ' -> solo scripts externos');
    }
  }

  // ---- 4) Hotfix Métricas (P13) + parches M2/M3 ----
  console.log('== V3 · hotfix Métricas en admin.js ==');
  const admin = leer(ADMIN_JS) || '';

  if (/title="[^"]*\$\{ico\(/.test(admin)) {
    fallos++;
    console.log('FAIL admin.js -> queda ${ico(...)} dentro de un atributo title (P13)');
  } else {
    console.log('OK   admin.js -> sin ${ico(...)} en atributos title');
  }

  if (/class="prod-fila" title="[^"]*Verificados:/.test(admin)) {
    console.log('OK   admin.js -> parche M1 aplicado (title en texto plano)');
  } else {
    console.log('WARN admin.js -> no encuentro el ancla de M1; revisar manualmente');
  }

  if (/'\u2705 Verificados'/.test(admin)) {
    fallos++;
    console.log('FAIL admin.js -> chips de Métricas aún con emoji (M2 pendiente)');
  } else {
    console.log('OK   admin.js -> parche M2 aplicado (chips con ico())');
  }

  if (/metricas: '\u{1F4CA}/u.test(admin)) {
    fallos++;
    console.log('FAIL admin.js -> MODULOS_TITULO aún con emoji (M3 pendiente)');
  } else {
    console.log('OK   admin.js -> parche M3 aplicado (breadcrumb texto plano)');
  }

  // ---- Veredicto ----
  console.log('');
  if (fallos === 0) {
    console.log('V3 CIERRE: TODO EN VERDE. Procedo con acta de cierre y CONTEXTO v6.');
  } else {
    console.log('V3 CIERRE: ' + fallos + ' fallo(s). Resolver antes de cerrar el bloque.');
  }
  process.exit(fallos === 0 ? 0 : 1);
}

main();