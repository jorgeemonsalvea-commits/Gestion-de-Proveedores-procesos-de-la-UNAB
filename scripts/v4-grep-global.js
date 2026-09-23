/* eslint-env node */
'use strict';

// ============================================================================
// Sprint 9 · V4 — GREP GLOBAL v2 (puerta de cierre D21)
// Reporta cada pictograma como:  FAIL ruta:linea:columna U+XXXX glifo | línea
// Así los parches Busca/Reemplaza se construyen con ancla exacta sin subir
// archivos completos. © ® ™ excluidos (D19/P14). Solo lectura.
// Uso: node scripts/v4-grep-global.js
// ============================================================================

const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();

// D19: lookahead negativo excluye signos tipográficos/legales © ® ™
const PICTO = /(?![\u00A9\u00AE\u2122])(?:\p{Extended_Pictographic}|[\u2715\u2716\u2717\u274C\u2705\u26A0\u23F3\u23F0\u2600\u263E\u267B\u270F\u2139\u260E])\uFE0F?/gu;

// D22: tests/ excluidos por decisión de jefa: los emojis de describe/comentarios
// son marcadores internos de desarrollo y nunca se envían al usuario.
const DIRS = ['public', 'scripts'];
const ROOT_JS = ['server.js', 'email.js', 'security.js', 'database.js'];
const EXCLUDE_DIRS = new Set([
  'node_modules', 'vendor', '.git', 'backups', 'uploads',
  'sessions', 'plantillas', 'fonts', 'img', '_recuperados'
]);
const EXT = new Set(['.js', '.html', '.css']);

let total = 0;

function codepoint(ch) {
  return 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
}

function scanFile(abs) {
  const txt = fs.readFileSync(abs, 'utf8');
  const rel = path.relative(ROOT, abs);
  const lines = txt.split('\n');
  let count = 0;

  lines.forEach((line, i) => {
    PICTO.lastIndex = 0;
    let m;
    while ((m = PICTO.exec(line)) !== null) {
      count++;
      console.log(
        'FAIL ' + rel + ':' + (i + 1) + ':' + (m.index + 1) +
        ' ' + codepoint(m[0]) + ' ' + m[0] +
        '  | ' + line.trim().slice(0, 160)
      );
    }
  });

  if (!count) console.log('OK   ' + rel);
  total += count;
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!EXCLUDE_DIRS.has(entry.name)) walk(path.join(dir, entry.name));
    } else if (EXT.has(path.extname(entry.name))) {
      scanFile(path.join(dir, entry.name));
    }
  }
}

DIRS.forEach(d => {
  const abs = path.join(ROOT, d);
  if (fs.existsSync(abs)) walk(abs);
});
ROOT_JS.forEach(f => {
  const abs = path.join(ROOT, f);
  if (fs.existsSync(abs)) scanFile(abs);
});

console.log('');
if (total === 0) {
  console.log('V4 GREP GLOBAL: 0 pictogramas. Cierre habilitado.');
} else {
  console.log('V4 GREP GLOBAL: ' + total + ' pictograma(s). Pegar este reporte completo para construir los parches exactos.');
  process.exit(1);
}