// ==========================================
// 1. IMPORTACIONES Y CONFIGURACIÓN
// ==========================================
const crypto = require('crypto');

// Constantes de cifrado AES-256-GCM
const CONFIG = {
  algorithm: 'aes-256-gcm',
  ivLength: 16,           // 128 bits
  authTagLength: 16,      // 128 bits
  saltLength: 16,         // 128 bits
  keyLength: 32,          // 256 bits
  iterations: 100000,     // PBKDF2 iterations
  hashAlgorithm: 'sha512',
  minPasswordLength: 8,
  minKeyLength: 32
};


// ==========================================
// 2. FUNCIONES DE DERIVACIÓN DE CLAVES
// ==========================================
/**
 * Deriva una clave criptográfica desde una contraseña maestra y salt
 * Usa PBKDF2 con SHA-512 para resistencia a ataques de fuerza bruta
 * 
 * @param {string} masterPassword - Contraseña maestra
 * @param {Buffer} salt - Salt aleatorio de 16 bytes
 * @returns {Buffer} Clave derivada de 32 bytes (256 bits)
 */
function derivarClave(masterPassword, salt) {
  // Validar parámetros
  if (!masterPassword || typeof masterPassword !== 'string') {
    throw new Error('La contraseña maestra es requerida y debe ser un string');
  }
  
  if (!Buffer.isBuffer(salt) || salt.length !== CONFIG.saltLength) {
    throw new Error(`El salt debe ser un Buffer de ${CONFIG.saltLength} bytes`);
  }
  
  return crypto.pbkdf2Sync(
    masterPassword, 
    salt, 
    CONFIG.iterations, 
    CONFIG.keyLength, 
    CONFIG.hashAlgorithm
  );
}


// ==========================================
// 3. FUNCIONES DE CIFRADO Y DESCIFRADO
// ==========================================

/**
 * Cifra un buffer usando AES-256-GCM con clave derivada de PBKDF2
 * 
 * Formato del buffer cifrado:
 * [salt (16 bytes)] [iv (16 bytes)] [authTag (16 bytes)] [datos cifrados]
 * 
 * @param {Buffer} buffer - Datos a cifrar
 * @param {string} encryptionKey - Clave maestra de cifrado
 * @returns {Buffer} Buffer cifrado con salt, iv, authTag y datos
 */
function cifrarArchivo(buffer, encryptionKey) {
  // Validar parámetros
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('El archivo debe ser un Buffer válido');
  }
  
  if (buffer.length === 0) {
    throw new Error('El archivo está vacío');
  }
  
  if (!encryptionKey || encryptionKey.length < CONFIG.minKeyLength) {
    throw new Error(`La clave de cifrado debe tener al menos ${CONFIG.minKeyLength} caracteres`);
  }
  
  try {
    // Generar valores aleatorios criptográficamente seguros
    const salt = crypto.randomBytes(CONFIG.saltLength);
    const iv = crypto.randomBytes(CONFIG.ivLength);
    
    // Derivar clave desde la contraseña maestra
    const key = derivarClave(encryptionKey, salt);
    
    // Crear cipher y cifrar
    const cipher = crypto.createCipheriv(CONFIG.algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Concatenar: salt + iv + authTag + datos cifrados
    return Buffer.concat([salt, iv, authTag, encrypted]);
  } catch (err) {
    console.error('Error cifrando archivo:', err.message);
    throw new Error(`Error al cifrar el archivo: ${err.message}`);
  }
}

/**
 * Descifra un buffer cifrado con AES-256-GCM
 * 
 * @param {Buffer} encryptedBuffer - Buffer cifrado (salt + iv + authTag + datos)
 * @param {string} encryptionKey - Clave maestra de cifrado
 * @returns {Buffer} Datos descifrados
 * @throws {Error} Si el buffer es inválido o la clave es incorrecta
 */
function descifrarArchivo(encryptedBuffer, encryptionKey) {
  // Validar parámetros
  if (!Buffer.isBuffer(encryptedBuffer)) {
    throw new Error('El buffer cifrado debe ser un Buffer válido');
  }
  
  // Tamaño mínimo: salt (16) + iv (16) + authTag (16) = 48 bytes
  const minSize = CONFIG.saltLength + CONFIG.ivLength + CONFIG.authTagLength;
  
  if (encryptedBuffer.length < minSize) {
    throw new Error(`El buffer cifrado es demasiado pequeño (mínimo ${minSize} bytes)`);
  }
  
  if (!encryptionKey || encryptionKey.length < CONFIG.minKeyLength) {
    throw new Error(`La clave de cifrado debe tener al menos ${CONFIG.minKeyLength} caracteres`);
  }
  
  try {
    // Extraer componentes del buffer cifrado
    const salt = encryptedBuffer.slice(0, CONFIG.saltLength);
    const iv = encryptedBuffer.slice(CONFIG.saltLength, CONFIG.saltLength + CONFIG.ivLength);
    const authTag = encryptedBuffer.slice(
      CONFIG.saltLength + CONFIG.ivLength, 
      CONFIG.saltLength + CONFIG.ivLength + CONFIG.authTagLength
    );
    const encrypted = encryptedBuffer.slice(CONFIG.saltLength + CONFIG.ivLength + CONFIG.authTagLength);
    
    // Derivar clave y descifrar
    const key = derivarClave(encryptionKey, salt);
    const decipher = crypto.createDecipheriv(CONFIG.algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    // Error específico para clave incorrecta vs otros errores
    if (err.message.includes('Unsupported state') || 
        err.message.includes('decipher') ||
        err.message.includes('tag')) {
      throw new Error('Clave de cifrado incorrecta o archivo corrupto');
    }
    throw new Error(`Error al descifrar el archivo: ${err.message}`);
  }
}

/**
 * Verifica si un buffer parece estar cifrado (tiene el formato esperado)
 * 
 * @param {Buffer} buffer - Buffer a verificar
 * @returns {boolean} true si parece estar cifrado
 */
function esBufferCifrado(buffer) {
  if (!Buffer.isBuffer(buffer)) return false;
  
  const minSize = CONFIG.saltLength + CONFIG.ivLength + CONFIG.authTagLength;
  if (buffer.length < minSize) return false;
  
  // Verificar que no sea un PDF sin cifrar (empieza con %PDF)
  const header = buffer.slice(0, 4).toString();
  if (header === '%PDF') return false;
  
  return true;
}


// ==========================================
// 4. FUNCIONES DE HASH
// ==========================================

/**
 * Calcula el hash SHA-256 de un buffer
 * Útil para verificar integridad de archivos
 * 
 * @param {Buffer} buffer - Datos a hashear
 * @returns {string} Hash hexadecimal de 64 caracteres
 */
function calcularHash(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('El buffer debe ser un Buffer válido');
  }
  
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Verifica si un buffer coincide con un hash esperado
 * 
 * @param {Buffer} buffer - Datos a verificar
 * @param {string} hashEsperado - Hash hexadecimal esperado
 * @returns {boolean} true si coinciden
 */
function verificarHash(buffer, hashEsperado) {
  const hashCalculado = calcularHash(buffer);
  return crypto.timingSafeEqual(
    Buffer.from(hashCalculado),
    Buffer.from(hashEsperado)
  );
}


// ==========================================
// 5. VALIDACIÓN DE CONTRASEÑAS
// ==========================================

/**
 * Valida que una contraseña cumpla con los requisitos de seguridad
 * 
 * Requisitos:
 * - Mínimo 8 caracteres
 * - Al menos una letra mayúscula (A-Z)
 * - Al menos una letra minúscula (a-z)
 * - Al menos un número (0-9)
 * - Al menos un carácter especial (!@#$%^&*...)
 * 
 * @param {string} password - Contraseña a validar
 * @returns {Object} { valido: boolean, mensaje: string }
 */
function validarPassword(password) {
  // Validar que sea string
  if (!password || typeof password !== 'string') {
    return { 
      valido: false, 
      mensaje: 'La contraseña debe ser un texto válido' 
    };
  }
  
  // Trim para evitar espacios al inicio/final
  const trimmed = password.trim();
  
  if (trimmed.length < CONFIG.minPasswordLength) {
    return { 
      valido: false, 
      mensaje: `La contraseña debe tener al menos ${CONFIG.minPasswordLength} caracteres` 
    };
  }
  
  if (!/[A-Z]/.test(trimmed)) {
    return { 
      valido: false, 
      mensaje: 'Debe contener al menos una letra mayúscula (A-Z)' 
    };
  }
  
  if (!/[a-z]/.test(trimmed)) {
    return { 
      valido: false, 
      mensaje: 'Debe contener al menos una letra minúscula (a-z)' 
    };
  }
  
  if (!/[0-9]/.test(trimmed)) {
    return { 
      valido: false, 
      mensaje: 'Debe contener al menos un número (0-9)' 
    };
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(trimmed)) {
    return { 
      valido: false, 
      mensaje: 'Debe contener al menos un carácter especial (!@#$%^&*...)' 
    };
  }
  
  return { valido: true, mensaje: 'Contraseña válida' };
}


function generarPasswordAleatoria(length = 16) {
  const mayusculas = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const minusculas = 'abcdefghijklmnopqrstuvwxyz';
  const numeros = '0123456789';
  const especiales = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const todos = mayusculas + minusculas + numeros + especiales;
  
  let password = '';
  
  // Asegurar al menos uno de cada tipo
  password += mayusculas[crypto.randomInt(0, mayusculas.length)];
  password += minusculas[crypto.randomInt(0, minusculas.length)];
  password += numeros[crypto.randomInt(0, numeros.length)];
  password += especiales[crypto.randomInt(0, especiales.length)];
  
  // Completar el resto aleatoriamente
  for (let i = 4; i < length; i++) {
    password += todos[crypto.randomInt(0, todos.length)];
  }
  
  // Mezclar la contraseña
  const array = password.split('');
  for (let i = array.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
  
  return array.join('');
}


// ==========================================
// 6. GENERACIÓN DE CLAVES MAESTRAS
// ==========================================

/**
 * Genera una clave maestra aleatoria segura para cifrado
 * 
 * @param {number} length - Longitud en caracteres (default: 64)
 * @returns {string} Clave maestra aleatoria
 */
function generarClaveMaestra(length = 64) {
  return crypto.randomBytes(length).toString('hex').substring(0, length);
}

/**
 * Verifica si una clave maestra es válida
 * 
 * @param {string} key - Clave a verificar
 * @returns {boolean} true si es válida
 */
function validarClaveMaestra(key) {
  if (!key || typeof key !== 'string') return false;
  return key.length >= CONFIG.minKeyLength;
}


// ==========================================
// 7. FUNCIONES AUXILIARES
// ==========================================

/**
 * Obtiene información de configuración de seguridad
 * 
 * @returns {Object} Configuración actual
 */
function obtenerConfiguracionSeguridad() {
  return {
    algoritmo: CONFIG.algorithm,
    longitudClave: CONFIG.keyLength * 8 + ' bits',
    longitudIV: CONFIG.ivLength * 8 + ' bits',
    iteracionesPBKDF2: CONFIG.iterations,
    algoritmoHash: CONFIG.hashAlgorithm,
    longitudMinimaPassword: CONFIG.minPasswordLength
  };
}

/**
 * Verifica que el sistema de cifrado esté funcionando correctamente
 * Realiza un test de cifrado/descifrado con datos de prueba
 * 
 * @returns {Object} Resultado del test
 */
function verificarSistemaCifrado(encryptionKey) {
  try {
    const datosPrueba = Buffer.from('Test de cifrado AES-256-GCM');
    const cifrado = cifrarArchivo(datosPrueba, encryptionKey);
    const descifrado = descifrarArchivo(cifrado, encryptionKey);
    
    const correcto = datosPrueba.equals(descifrado);
    
    return {
      funcional: correcto,
      mensaje: correcto 
        ? '✅ Sistema de cifrado funcionando correctamente' 
        : ' Los datos descifrados no coinciden con los originales',
      configuracion: obtenerConfiguracionSeguridad()
    };
  } catch (err) {
    return {
      funcional: false,
      mensaje: `❌ Error en el sistema de cifrado: ${err.message}`,
      configuracion: obtenerConfiguracionSeguridad()
    };
  }
}


// ==========================================
// 8. EXPORTACIÓN
// ==========================================
module.exports = {
  // Funciones principales de cifrado
  cifrarArchivo,
  descifrarArchivo,
  esBufferCifrado,
  
  // Funciones de hash
  calcularHash,
  verificarHash,
  
  // Validación de contraseñas
  validarPassword,
  generarPasswordAleatoria,
  
  // Gestión de claves
  generarClaveMaestra,
  validarClaveMaestra,
  derivarClave,
  
  // Funciones auxiliares
  obtenerConfiguracionSeguridad,
  verificarSistemaCifrado,
  
  // Configuración
  CONFIG
};