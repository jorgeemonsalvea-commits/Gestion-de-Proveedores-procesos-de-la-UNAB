// scripts/gc-uploads.js — Elimina de uploads/ (y opcionalmente del mirror) los .enc
// que NINGUNA fila de la BD referencia (huérfanos/duplicados de archivados fallidos).
// Reglas de seguridad:
//  - NUNCA borra archivos cuyo nombre empieza por "evaluacion_" (los resuelve el visor de ciclos).
//  - Por defecto es DRY-RUN (solo lista). Con --fix borra. Con --mirror incluye el mirror de backups.
// Uso:
//   node scripts/gc-uploads.js                 → diagnóstico
//   node scripts/gc-uploads.js --fix           → limpia uploads/
//   node scripts/gc-uploads.js --fix --mirror  → limpia uploads/ + mirror
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { db } = require('../database');
const FIX = process.argv.includes('--fix');
const CON_MIRROR = process.argv.includes('--mirror');
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, '..');
const uploadsDir = path.join(dataDir, 'uploads');
const mirrorDir = path.join(dataDir, 'backups', 'uploads_mirror');

// Referencias válidas = rutas en documentos + evaluacion_inicial de proveedores
const refs = new Set();
db.prepare(`SELECT archivo FROM documentos WHERE archivo IS NOT NULL AND archivo != 'no_aplica'`)
    .all().forEach(r => refs.add(String(r.archivo).replace(/\\/g, '/')));
db.prepare(`SELECT evaluacion_inicial AS archivo FROM proveedores WHERE evaluacion_inicial IS NOT NULL AND evaluacion_inicial != ''`)
    .all().forEach(r => refs.add(String(r.archivo).replace(/\\/g, '/')));

function escanear(dirBase) {
    const huerfanos = [];
    if (!fs.existsSync(dirBase)) return huerfanos;
    const caminar = (dir) => {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, e.name);
            if (e.isDirectory()) { caminar(full); continue; }
            if (!e.name.endsWith('.enc')) continue;
            if (e.name.startsWith('evaluacion_')) continue; // protegidas (visor de ciclos)
            const rel = path.relative(uploadsDir, full).replace(/\\/g, '/');
            if (!refs.has(rel)) huerfanos.push({ full, rel, size: fs.statSync(full).size });
        }
    };
    caminar(dirBase);
    return huerfanos;
}

const objetivos = [{ nombre: 'uploads', dir: uploadsDir }];
if (CON_MIRROR) objetivos.push({ nombre: 'mirror', dir: mirrorDir });

for (const obj of objetivos) {
    const huerfanos = escanear(obj.dir);
    const mb = (huerfanos.reduce((s, h) => s + h.size, 0) / 1024 / 1024).toFixed(1);
    console.log(`\n🗑️ ${obj.dir}: ${huerfanos.length} huérfano(s) (${mb} MB)`);
    huerfanos.slice(0, 15).forEach(h => console.log(`   - ${h.rel}`));
    if (huerfanos.length > 15) console.log(`   … y ${huerfanos.length - 15} más`);
    if (FIX) {
        huerfanos.forEach(h => fs.unlinkSync(h.full));
        console.log(`✅ ${obj.nombre}: ${huerfanos.length} archivo(s) eliminado(s), ${mb} MB liberados`);
    }
}
console.log(FIX ? '\n✅ GC completado.' : '\n🔍 Dry-run: ejecuta con --fix para eliminar (y --mirror para incluir el mirror).');