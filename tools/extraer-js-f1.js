// ==========================================
// 🧰 F1 (Sprint 6): EXTRACCIÓN DE JS INLINE → ARCHIVOS EXTERNOS
// Uso: node tools/extraer-js-f1.js
// - Extrae el ÚLTIMO bloque <script> inline (el que cierra antes de </body>)
//   de public/admin.html y public/proveedor.html.
// - Lo escribe en public/js/admin.js y public/js/proveedor.js.
// - Reemplaza el bloque por <script src="/js/..."></script>.
// - Idempotente: si el HTML ya referencia el externo, no toca nada.
// - Seguro: valida sintaxis con vm.Script ANTES de escribir y aborta
//   si detecta <script> anidados o si el bloque no aparece exactamente 1 vez.
// ==========================================
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const pubDir = path.join(__dirname, '..', 'public');
const jsDir = path.join(pubDir, 'js');

const OBJETIVOS = [
  { html: 'admin.html', js: 'admin.js' },
  { html: 'proveedor.html', js: 'proveedor.js' }
];

function extraer(htmlFile, jsFile) {
  const htmlPath = path.join(pubDir, htmlFile);
  const jsPath = path.join(jsDir, jsFile);
  let html = fs.readFileSync(htmlPath, 'utf8');

  // Idempotencia: ya migrado → no hacer nada
  if (html.includes(`<script src="/js/${jsFile}"></script>`)) {
    console.log(`⏭️  ${htmlFile}: ya usa /js/${jsFile} — se omite.`);
    return;
  }

  // Último bloque inline: <script> ... </script> seguido de </body>
  const re = /<script>([\s\S]*?)<\/script>[ \t\r\n]*<\/body>/;
  const m = html.match(re);
  if (!m) {
    console.error(`❌ ${htmlFile}: no se encontró el bloque <script> inline antes de </body>. Abortando sin cambios.`);
    process.exitCode = 1;
    return;
  }
  const code = m[1];

  // Seguridad 1: sin <script> anidados dentro del código
  if (/<script/i.test(code)) {
    console.error(`❌ ${htmlFile}: el bloque inline contiene "<script" anidado. Revisión manual requerida.`);
    process.exitCode = 1;
    return;
  }

  // Seguridad 2: el JS debe compilar antes de moverlo
  try {
    new vm.Script(code, { filename: jsFile });
  } catch (e) {
    console.error(`❌ ${htmlFile}: el JS inline NO compila (${e.message}). Abortando sin cambios.`);
    process.exitCode = 1;
    return;
  }

  if (!fs.existsSync(jsDir)) fs.mkdirSync(jsDir, { recursive: true });
  fs.writeFileSync(jsPath, code.replace(/^\s*\n/, ''), 'utf8');
  html = html.replace(re, `<script src="/js/${jsFile}"></script>\n</body>`);
  fs.writeFileSync(htmlPath, html, 'utf8');
  console.log(`✅ ${htmlFile} → /js/${jsFile} (${code.length} caracteres extraídos)`);
}

console.log('🧰 F1: extrayendo JS inline a archivos externos...');
OBJETIVOS.forEach(o => extraer(o.html, o.js));
if (!process.exitCode) {
  console.log('✅ F1 completado. Verifica con: node --check public/js/admin.js && node --check public/js/proveedor.js');
}