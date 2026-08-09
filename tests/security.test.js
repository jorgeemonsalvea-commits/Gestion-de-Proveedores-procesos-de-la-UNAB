const fs = require('fs');
const path = require('path');
const os = require('os');

// Variables de entorno de prueba (NO usar las reales)
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters-min!';
process.env.SESSION_SECRET = 'test-session-secret-32-characters-min!';
process.env.ADMIN_EMAIL = 'admin@test.local';
process.env.ADMIN_PASSWORD_INICIAL = 'AdminTest123!';
process.env.PORT = '3999';
process.env.APP_URL = 'http://localhost:3999';

// Directorio temporal único por corrida
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proveedores-test-'));
process.env.RAILWAY_VOLUME_MOUNT_PATH = dataDir;

let serverInstance = null;

beforeAll(async () => {
  const { app } = require('../server');
  serverInstance = app.listen(0); // puerto aleatorio
});

afterAll(async () => {
  if (serverInstance) {
    await new Promise(resolve => serverInstance.close(resolve));
  }
  try {
    const { db } = require('../server');
    if (db && typeof db.close === 'function') db.close();
  } catch (e) { /* ignorar */ }
  try {
    fs.rmSync(dataDir, { recursive: true, force: true });
  } catch (e) { /* ignorar en Windows (locks) */ }
});

const {
  cifrarArchivo,
  descifrarArchivo,
  calcularHash,
  verificarHash,
  validarPassword,
  generarPasswordAleatoria
} = require('../security');

describe('🔐 security.js', () => {
  describe('Cifrado AES-256-GCM', () => {
    const key = 'test-encryption-key-32-characters-min!';

    test('cifra y descifra correctamente', () => {
      const original = Buffer.from('Documento PDF confidencial');
      const cifrado = cifrarArchivo(original, key);
      const descifrado = descifrarArchivo(cifrado, key);
      expect(descifrado.equals(original)).toBe(true);
    });

    test('falla con clave incorrecta', () => {
      const original = Buffer.from('Test');
      const cifrado = cifrarArchivo(original, key);
      expect(() => descifrarArchivo(cifrado, 'clave-incorrecta-32-chars!!')).toThrow();
    });

    test('rechaza buffers vacíos', () => {
      expect(() => cifrarArchivo(Buffer.from(''), key)).toThrow('vacío');
    });

    test('produce salidas diferentes (salt+iv aleatorios)', () => {
      const original = Buffer.from('Mismo contenido');
      const c1 = cifrarArchivo(original, key);
      const c2 = cifrarArchivo(original, key);
      expect(c1.equals(c2)).toBe(false);
    });
  });

  describe('Hash SHA-256', () => {
    test('verifica integridad correctamente', () => {
      const buf = Buffer.from('Archivo original');
      const hash = calcularHash(buf);
      expect(hash).toHaveLength(64);
      expect(verificarHash(buf, hash)).toBe(true);
      expect(verificarHash(Buffer.from('modificado'), hash)).toBe(false);
    });
  });

  describe('Política de contraseñas', () => {
    test('rechaza menos de 8 caracteres', () => {
      expect(validarPassword('Ab1!').valido).toBe(false);
    });

    test('rechaza sin mayúscula', () => {
      expect(validarPassword('abcdef123!').valido).toBe(false);
    });

    test('rechaza sin número', () => {
      expect(validarPassword('Abcdefgh!').valido).toBe(false);
    });

    test('rechaza sin especial', () => {
      expect(validarPassword('Abcdef123').valido).toBe(false);
    });

    test('acepta contraseña fuerte', () => {
      expect(validarPassword('MiPass2026!').valido).toBe(true);
    });

    test('genera contraseñas aleatorias válidas', () => {
      const p = generarPasswordAleatoria(16);
      expect(p).toHaveLength(16);
      expect(validarPassword(p).valido).toBe(true);
    });
  });
});