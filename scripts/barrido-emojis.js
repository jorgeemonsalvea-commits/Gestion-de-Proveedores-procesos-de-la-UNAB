#!/usr/bin/env node
// ==========================================
// 🔧 V2.3-CODEMOD · Barrido automático de emojis → ico()
// ------------------------------------------
// Reglas (D10):
//  · Dentro de TEMPLATE LITERALS (`...`): emoji → ${ico('clave')} (mapeado) o '' (sin mapear).
//  · Dentro de COMENTARIOS: se elimina el emoji.
//  · Strings '...' / "..." NO se tocan (campos de datos como icono:'🔴' se migran aparte).
// Idempotente: correrlo 2 veces = 0 cambios la 2ª vez.
// Uso:  node scripts/barrido-emojis.js            (dry-run, solo reporta)
//         node scripts/barrido-emojis.js --apply  (escribe los cambios)
// ==========================================
const fs = require('fs');
const path = require('path');

const APPLY = process.argv.includes('--apply');
const ROOT = path.join(__dirname, '..');
const OBJETIVOS = [
  'public/js/admin.js',
  'public/js/proveedor.js',
  'public/js/utils.js'
];

// 🗺️ Emoji → clave del catálogo ICONOS (utils.js)
const MAPA = {
  '✅':'check','❌':'x','👁️':'eye','👁':'eye','⬇️':'download','⬆️':'upload',
  '📥':'inbox','🗑️':'trash','🗑':'trash','📦':'archive','➕':'plus','💾':'save',
  '👥':'users','🧍':'user','🏢':'briefcase','📄':'file-text','📋':'file-text',
  '📜':'file-text','🧾':'file-text','📎':'file','📁':'folder','🗂️':'folder',
  '⏳':'clock','🕐':'clock','📅':'calendar','🔔':'bell','🔕':'bell-off',
  '⚙️':'settings','🔄':'refresh','✏️':'edit','📧':'mail','✉️':'mail',
  '📨':'send','📤':'upload','📊':'chart','📈':'chart','📉':'chart',
  '🔍':'search','🔒':'lock','🔓':'lock','🔑':'key','⚠️':'alert','ℹ️':'info',
  '❓':'help','🏠':'home','🚫':'ban','🛡️':'shield','':'shield'
};

// Detecta secuencia de emoji (pictograma + variación/ZWJ) en posición i
const EMOJI_RE = /(\p{Extended_Pictographic}(?:\uFE0F|\u200D\p{Extended_Pictographic})*)/yu;
function matchEmoji(s, i) {
  EMOJI_RE.lastIndex = i;
  const m = EMOJI_RE.exec(s);
  return m ? { seq: m[0], len: m[0].length } : null;
}

// Mini-lexer: CODE | LINE | BLOCK | SQ | DQ | TEMPLATE (con anidación ${ })
function barrer(contenido) {
  let out = '', i = 0, cambios = 0;
  const n = contenido.length;
  let estado = 'CODE';
  const stack = [];   // pila de TEMPLATE anidados
  let brace = 0;      // profundidad de {} dentro de ${ }
  while (i < n) {
    const ch = contenido[i], next = contenido[i + 1];
    if (estado === 'CODE') {
      if (ch === '/' && next === '/') { estado = 'LINE'; out += ch; i++; continue; }
      if (ch === '/' && next === '*') { estado = 'BLOCK'; out += ch + next; i += 2; continue; }
      if (ch === "'" ) { estado = 'SQ'; out += ch; i++; continue; }
      if (ch === '"')  { estado = 'DQ'; out += ch; i++; continue; }
      if (ch === '`')  { estado = 'TEMPLATE'; out += ch; i++; continue; }
      if (ch === '$' && next === '{') { stack.push('TEMPLATE'); estado = 'CODE'; brace = 0; out += ch + next; i += 2; continue; }
      if (ch === '{') brace++;
      if (ch === '}') {
        if (brace > 0) brace--;
        else if (stack.length) { stack.pop(); estado = 'TEMPLATE'; out += ch; i++; continue; }
      }
      out += ch; i++; continue;
    }
    if (estado === 'LINE') {
      const m = matchEmoji(contenido, i);
      if (m) { i += m.len; cambios++; continue; }          // comentario: se elimina
      if (ch === '\n') estado = 'CODE';
      out += ch; i++; continue;
    }
    if (estado === 'BLOCK') {
      const m = matchEmoji(contenido, i);
      if (m) { i += m.len; cambios++; continue; }
      if (ch === '*' && next === '/') { estado = 'CODE'; out += ch + next; i += 2; continue; }
      out += ch; i++; continue;
    }
    if (estado === 'SQ' || estado === 'DQ') {
      const q = estado === 'SQ' ? "'" : '"';
      if (ch === '\\') { out += ch + next; i += 2; continue; }
      if (ch === q) estado = 'CODE';
      out += ch; i++; continue;                             // strings: NO tocar
    }
    if (estado === 'TEMPLATE') {
      if (ch === '\\') { out += ch + next; i += 2; continue; }
      if (ch === '`') { estado = 'CODE'; out += ch; i++; continue; }
      if (ch === '$' && next === '{') { stack.push('TEMPLATE'); estado = 'CODE'; brace = 0; out += ch + next; i += 2; continue; }
      const m = matchEmoji(contenido, i);
      if (m) {
        const clave = MAPA[m.seq];
        out += clave ? `\${ico('${clave}')}` : '';
        i += m.len; cambios++; continue;
      }
      out += ch; i++; continue;
    }
  }
  return { out, cambios };
}

let total = 0;
for (const rel of OBJETIVOS) {
  const ruta = path.join(ROOT, rel);
  if (!fs.existsSync(ruta)) { console.log(`⚠️  No existe ${rel}`); continue; }
  const src = fs.readFileSync(ruta, 'utf8');
  const { out, cambios } = barrer(src);
  total += cambios;
  console.log(`${cambios ? '🔧' : '✅'} ${rel}: ${cambios} reemplazo(s)`);
  if (APPLY && cambios) fs.writeFileSync(ruta, out, 'utf8');
}
console.log(APPLY ? `✅ Aplicados ${total} reemplazo(s).` : `ℹ️  Dry-run: ${total} reemplazo(s) pendientes. Usa --apply para escribir.`);