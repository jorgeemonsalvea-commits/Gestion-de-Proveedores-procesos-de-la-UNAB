/* eslint-env node */
'use strict';

// ============================================================================
// Sprint 9 · V4 — BARRIDO BACKEND (database.js + security.js)
// ----------------------------------------------------------------------------
// Strip de pictogramas (D10) en console.* / comentarios / mensajes devueltos.
// Excluye signos tipográficos © ® ™ (P14). Idempotente.
// Uso: node scripts/v4-barrido-backend.js          (dry-run)
//      node scripts/v4-barrido-backend.js --apply  (escribe)
// ============================================================================

const fs = require('fs');
const path = require('path');

const APPLY = process.argv.includes('--apply');
const ROOT = process.cwd();

// D19/P14: lookahead negativo conserva © ® ™
const PICTO = /(?![\u00A9\u00AE\u2122])(?:\p{Extended_Pictographic}|[\u2715\u2716\u2717\u274C\u2705\u26A0\u23F3\u23F0\u2600\u263E\u267B\u270F\u2139\u260E])\uFE0F?/gu;

const TARGETS = ['database.js', 'security.js'];

function strip(s) {
  PICTO.lastIndex = 0;
  return String(s).replace(PICTO, '').replace(/\uFE0F/g, '');
}

let cambios = 0;

TARGETS.forEach(rel => {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) { console.log('SKIP ' + rel + ' (no existe)'); return; }
  const orig = fs.readFileSync(abs, 'utf8');
  const out = strip(orig);
  if (out === orig) { console.log('==   ' + rel + ' sin cambios'); return; }
  cambios++;
  if (APPLY) {
    fs.writeFileSync(abs, out, 'utf8');
    console.log('OK   ' + rel);
  } else {
    console.log('DRY  ' + rel);
  }
});

console.log(APPLY ? 'Barrido backend aplicado.' : 'Dry-run completado. Aplica con --apply.');