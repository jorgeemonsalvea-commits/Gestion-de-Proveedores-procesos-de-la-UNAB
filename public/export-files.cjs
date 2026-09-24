// ./scripts/export-files.cjs

/**
 * export-files.cjs
 *
 * Uso:
 * node scripts/export-files.cjs <salida.md> <archivo1> [archivo2] ...
 *
 * Ejemplo:
 * node scripts/export-files.cjs audit/tests-bundle.md tests/auth.test.js tests/rbac.test.js
 *
 * Genera un solo archivo con varios archivos completos, numerados.
 */

const fs = require('fs');
const path = require('path');

const [,, outputArg, ...files] = process.argv;

if (!outputArg || files.length === 0) {
  console.error('Uso:');
  console.error('node scripts/export-files.cjs <salida.md> <archivo1> [archivo2] ...');
  console.error('');
  console.error('Ejemplo:');
  console.error('node scripts/export-files.cjs audit/tests-bundle.md tests/auth.test.js tests/rbac.test.js');
  process.exit(1);
}

const outputPath = path.resolve(process.cwd(), outputArg);

const out = [
  '# Exportación de archivos completos',
  `Generado: ${new Date().toISOString()}`,
  '',
  '> Este archivo es solo para revisión técnica. No ejecutar directamente.'
];

for (const fileArg of files) {
  const filePath = path.resolve(process.cwd(), fileArg);

  if (!fs.existsSync(filePath)) {
    out.push('', `## ${fileArg}`, '', 'Archivo no encontrado.');
    continue;
  }

  let content = '';

  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    out.push('', `## ${fileArg}`, '', 'No se pudo leer el archivo.');
    continue;
  }

  const lines = content.split(/\r?\n/);

  out.push(
    '',
    `## ${fileArg} (${lines.length} líneas)`,
    '',
    '```js'
  );

  for (let i = 0; i < lines.length; i += 1) {
    out.push(`${String(i + 1).padStart(6, ' ')} | ${lines[i]}`);
  }

  out.push('```');
}

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, out.join('\n'), 'utf8');

console.log(`[OK] Exportación generada en: ${outputPath}`);
console.log(`[INFO] Archivos incluidos: ${files.join(', ')}`);