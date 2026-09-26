const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');
const sharp = require('sharp');

const PORT = process.env.PORT || 3000;
const HEARTBEAT_INTERVAL_MS = 10000;
const PROTOCOL_VERSION = 2;
const UPDATE_REQUIRED_ERROR = 'Hay una version nueva de la app. Instala la actualizacion para seguir usandola.';

// Despues de un error no atrapado el proceso puede quedar en un estado inconsistente (ej. usuarios "en linea" que no lo estan).
// Es mas seguro apagarse de forma ordenada y dejar que Render lo reinicie limpio en unos segundos; la app se reconecta sola.
process.on('uncaughtException', (err) => {
  console.log('Error no atrapado, se reinicia el servidor de forma ordenada:', err && err.stack ? err.stack : err);
  shutdown('uncaughtException', 1);
});

process.on('unhandledRejection', (err) => {
  console.log('Promesa rechazada sin atrapar en algun lado (se ignora para no tumbar el servidor):', err && err.message ? err.message : err);
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.log('Error inesperado en la conexion a la base de datos (se ignora para no tumbar el servidor):', err.message);
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      public_key TEXT NOT NULL,
      push_token TEXT
    );
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture TEXT;`);
  // Protocolo v2: identidad (firma + DH) y prekey firmada para X3DH
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_sign_pub TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_dh_pub TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS spk_id INTEGER;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS spk_pub TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS spk_sig TEXT;`);

  // La tabla pending_messages del protocolo v1 se deja como estaba; ya no se usa.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS inbox (
      id BIGSERIAL PRIMARY KEY,
      to_username TEXT NOT NULL,
      from_username TEXT NOT NULL,
      envelope TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS inbox_to_username_idx ON inbox (to_username, id);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      last_used_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS auth_sessions_username_idx ON auth_sessions (username);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      owner TEXT NOT NULL,
      contact TEXT NOT NULL,
      PRIMARY KEY (owner, contact)
    );
  `);
  await pool.query(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);`);

  // Una sola vez: antes todos veian a todos, asi que los usuarios que ya existian quedan como contactos entre si
  const seeded = await pool.query(`INSERT INTO meta (key, value) VALUES ('contacts_seeded', '1') ON CONFLICT (key) DO NOTHING RETURNING key`);
  if (seeded.rows.length > 0) {
    await pool.query(`
      INSERT INTO contacts (owner, contact)
      SELECT a.username, b.username FROM users a JOIN users b ON a.username <> b.username
      ON CONFLICT DO NOTHING
    `);
    console.log('Contactos iniciales creados a partir de los usuarios existentes');
  }
  console.log('Tablas verificadas/creadas en la base de datos');
}

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 30;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 72; // bcrypt ignora todo despues de 72 bytes

function isNonEmptyString(value, maxLength) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function isBase64Key(value, bytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  return Buffer.from(value, 'base64').length === bytes;
}

function isValidIdentity(identity) {
  return !!identity && isBase64Key(identity.signPub, 32) && isBase64Key(identity.dhPub, 32);
}

function isValidSignedPreKey(spk) {
  return !!spk && Number.isInteger(spk.id) && spk.id > 0 && spk.id <= 2147483647
    && isBase64Key(spk.pub, 32) && isBase64Key(spk.sig, 64);
}

// Reglas estrictas solo para cuentas nuevas; las cuentas existentes siguen funcionando igual
function validateNewUsername(username) {
  if (typeof username !== 'string') return 'Nombre de usuario invalido';
  if (username.trim() !== username) return 'El nombre de usuario no puede empezar ni terminar con espacios';
  if (username.length < USERNAME_MIN_LENGTH || username.length > USERNAME_MAX_LENGTH) {
    return `El nombre de usuario debe tener entre ${USERNAME_MIN_LENGTH} y ${USERNAME_MAX_LENGTH} caracteres`;
  }
  if (/[\u0000-\u001f\u007f]/.test(username)) return 'El nombre de usuario tiene caracteres no permitidos';
  return null;
}

function validateNewPassword(password) {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
    return `La contraseña debe tener al menos ${PASSWORD_MIN_LENGTH} caracteres`;
  }
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_LENGTH) return 'La contraseña es demasiado larga';
  return null;
}

// Limite de intentos fallidos por IP y por usuario, para frenar ataques de fuerza bruta.
// Solo cuentan los fallos, asi que la reconexion automatica de la app nunca se bloquea.
const FAILED_AUTH_LIMIT_PER_IP = 20;
const FAILED_AUTH_LIMIT_PER_USER = 10;
const FAILED_AUTH_WINDOW_MS = 15 * 60 * 1000;
const failedAuthAttempts = new Map(); // "ip:..." o "user:..." -> { count, firstAttemptAt }

function isAuthBlocked(key, limit) {
  const entry = failedAuthAttempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) {
    failedAuthAttempts.delete(key);
    return false;
  }
  return entry.count >= limit;
}

function recordFailedAuth(key, limit) {
  const entry = failedAuthAttempts.get(key);
  if (!entry || Date.now() - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) {
    failedAuthAttempts.set(key, { count: 1, firstAttemptAt: Date.now() });
  } else {
    entry.count += 1;
    if (entry.count === limit) console.log(`Demasiados intentos fallidos (${key}), se bloquea temporalmente`);
  }
}

function isPasswordAuthBlocked(ip, username) {
  return isAuthBlocked(`ip:${ip}`, FAILED_AUTH_LIMIT_PER_IP) || isAuthBlocked(`user:${String(username).toLowerCase()}`, FAILED_AUTH_LIMIT_PER_USER);
}

function recordFailedPasswordAuth(ip, username) {
  recordFailedAuth(`ip:${ip}`, FAILED_AUTH_LIMIT_PER_IP);
  recordFailedAuth(`user:${String(username).toLowerCase()}`, FAILED_AUTH_LIMIT_PER_USER);
}

function getClientIp(req) {
  // Render pone la IP real del cliente en x-forwarded-for
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'desconocida';
}

const TOO_MANY_ATTEMPTS_ERROR = 'Demasiados intentos fallidos, espera unos minutos';

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createAuthSession(username) {
  const token = crypto.randomBytes(32).toString('base64');
  await pool.query('INSERT INTO auth_sessions (token_hash, username) VALUES ($1, $2)', [hashToken(token), username]);
  return token;
}

const http = require('http');

const httpServer = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Servidor de chat activo');
});

// La foto de perfil viaja en base64 por aqui, por eso el limite es generoso; el default de ws (100 MB) es demasiado
const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
const MAX_ENVELOPE_LENGTH = 200000; // los archivos van por Supabase; el mensaje cifrado solo lleva texto y llaves
const wss = new WebSocketServer({ server: httpServer, maxPayload: MAX_MESSAGE_BYTES });
const onlineUsers = new Map(); // username -> { socket, tokenHash }

// Copia en memoria de los usuarios, para no leer toda la tabla (con fotos) en cada envio de la lista.
// Este servidor es el unico que escribe en la tabla users, asi que se mantiene al dia actualizandola junto con la BD.
const knownUsers = new Map(); // username -> { profilePicture, identity, spk }
const contactsOf = new Map(); // owner -> Set(contact)

function rowToKnownUser(row) {
  return {
    profilePicture: row.profile_picture,
    identity: row.identity_sign_pub && row.identity_dh_pub ? { signPub: row.identity_sign_pub, dhPub: row.identity_dh_pub } : null,
    spk: row.spk_id ? { id: row.spk_id, pub: row.spk_pub, sig: row.spk_sig } : null,
  };
}

async function loadKnownUsers() {
  const result = await pool.query('SELECT username, profile_picture, identity_sign_pub, identity_dh_pub, spk_id, spk_pub, spk_sig FROM users');
  knownUsers.clear();
  for (const row of result.rows) knownUsers.set(row.username, rowToKnownUser(row));

  const contacts = await pool.query('SELECT owner, contact FROM contacts');
  contactsOf.clear();
  for (const row of contacts.rows) addContactInMemory(row.owner, row.contact);
  console.log(`${knownUsers.size} usuario(s) y ${contacts.rows.length} contacto(s) cargados en memoria`);
}

function addContactInMemory(owner, contact) {
  if (!contactsOf.has(owner)) contactsOf.set(owner, new Set());
  contactsOf.get(owner).add(contact);
}

// Agrega el contacto en la BD y en memoria. Devuelve true si es nuevo.
async function addContact(owner, contact) {
  if (owner === contact) return false;
  if (contactsOf.get(owner)?.has(contact)) return false;
  await pool.query('INSERT INTO contacts (owner, contact) VALUES ($1, $2) ON CONFLICT DO NOTHING', [owner, contact]);
  addContactInMemory(owner, contact);
  return true;
}

// Las fotos se reducen al tamaño del avatar de la app (40 pt, 120 px en pantallas 3x) para que cada una pese unos KB.
const PROFILE_PICTURE_SIZE_PX = 160;
const PROFILE_PICTURE_MAX_BASE64_LENGTH = 20000; // las que ya son mas chicas que esto no se tocan

async function shrinkProfilePicture(base64) {
  const output = await sharp(Buffer.from(base64, 'base64'))
    .rotate() // respeta la orientacion EXIF antes de quitar los metadatos
    .resize(PROFILE_PICTURE_SIZE_PX, PROFILE_PICTURE_SIZE_PX, { fit: 'cover' })
    .jpeg({ quality: 75 })
    .toBuffer();
  return output.toString('base64');
}

// Reduce las fotos que se guardaron antes de existir la reduccion. Corre en segundo plano al arrancar.
async function shrinkExistingProfilePictures() {
  let shrunk = 0;
  for (const [username, info] of knownUsers) {
    const original = info.profilePicture;
    if (!original || original.length <= PROFILE_PICTURE_MAX_BASE64_LENGTH) continue;
    try {
      const small = await shrinkProfilePicture(original);
      // Solo se reemplaza si nadie subio otra foto mientras tanto
      const updated = await pool.query(
        'UPDATE users SET profile_picture = $1 WHERE username = $2 AND profile_picture = $3',
        [small, username, original]
      );
      if (updated.rowCount > 0 && info.profilePicture === original) info.profilePicture = small;
      shrunk++;
      console.log(`Foto de perfil de ${username} reducida de ${original.length} a ${small.length} caracteres`);
    } catch (err) {
      console.log(`No se pudo reducir la foto de perfil de ${username}, se deja como estaba:`, err.message);
    }
  }
  if (shrunk > 0) sendUserListToEveryone();
}

function sendJson(socket, obj) {
  if (socket && socket.readyState === socket.OPEN) socket.send(JSON.stringify(obj));
}

// Cada quien recibe solo a sus contactos (antes se mandaba la lista de todos los usuarios registrados a todos)
function sendUserList(username) {
  const online = onlineUsers.get(username);
  if (!online) return;
  const me = knownUsers.get(username);
  const users = [];
  for (const contact of contactsOf.get(username) || []) {
    const info = knownUsers.get(contact);
    if (!info) continue;
    users.push({ username: contact, profilePicture: info.profilePicture, identity: info.identity, online: onlineUsers.has(contact) });
  }
  sendJson(online.socket, { type: 'user-list', users, me: { username, profilePicture: me?.profilePicture || null } });
}

// Avisa a quienes tienen a `username` como contacto (cambio de conexion, foto o llaves)
function notifyWatchers(username) {
  for (const [owner, contacts] of contactsOf) {
    if (contacts.has(username)) sendUserList(owner);
  }
}

function sendUserListToEveryone() {
  for (const username of onlineUsers.keys()) sendUserList(username);
}

// Si Expo dice que el dispositivo ya no existe (app desinstalada, etc.), se borra el token para no seguir mandandole.
// Solo se borra si sigue siendo el mismo token, por si el usuario ya registro uno nuevo mientras tanto.
async function clearPushTokenIfUnregistered(username, pushToken, pushResult) {
  if (!pushResult || pushResult.status !== 'error' || pushResult.details?.error !== 'DeviceNotRegistered') return;
  await pool.query('UPDATE users SET push_token = NULL WHERE username = $1 AND push_token = $2', [username, pushToken]);
  console.log(`Token de notificaciones de ${username} ya no es valido, se borro`);
}

// La notificacion no dice quien escribio: Expo, Apple y Google no tienen por que saber quien habla con quien
async function sendPushNotification(toUsername) {
  const result = await pool.query('SELECT push_token FROM users WHERE username = $1', [toUsername]);
  const pushToken = result.rows[0]?.push_token;
  if (!pushToken) return;

  try {
    const response = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: pushToken,
        title: 'Aeterna',
        body: 'Tienes un mensaje nuevo',
        sound: 'default',
        channelId: 'default',
      }),
    });
    const pushResponse = await response.json();
    await clearPushTokenIfUnregistered(toUsername, pushToken, pushResponse.data);

    if (pushResponse.data && pushResponse.data.id) {
      const ticketId = pushResponse.data.id;
      setTimeout(async () => {
        try {
          const receiptRes = await fetch('https://exp.host/--/api/v2/push/getReceipts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: [ticketId] }),
          });
          const receiptData = await receiptRes.json();
          await clearPushTokenIfUnregistered(toUsername, pushToken, receiptData.data?.[ticketId]);
        } catch (e) {
          console.log('Error obteniendo recibo de push:', e.message);
        }
      }, 15000);
    }
  } catch (err) {
    console.log('Error enviando push:', err.message);
  }
}

// Borrado de archivos cifrados en Supabase Storage. Necesita SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY en Render.
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const MEDIA_BUCKETS = ['videos', 'voices'];
const MEDIA_PATH_REGEX = /^[a-f0-9]{32}\.bin$/;
const MEDIA_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;

function supabaseHeaders() {
  // Las llaves secretas nuevas (sb_secret_...) no son JWT: van solo en "apikey". La service_role antigua va en los dos.
  const headers = { apikey: SUPABASE_SERVICE_ROLE_KEY, 'Content-Type': 'application/json' };
  if (!SUPABASE_SERVICE_ROLE_KEY.startsWith('sb_secret_')) headers.Authorization = `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`;
  return headers;
}

async function deleteMediaObjects(bucket, paths) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || paths.length === 0) return;
  const res = await fetch(`${SUPABASE_URL}/storage/v1/object/${bucket}`, {
    method: 'DELETE',
    headers: supabaseHeaders(),
    body: JSON.stringify({ prefixes: paths }),
  });
  if (!res.ok) console.log(`No se pudieron borrar ${paths.length} archivo(s) de ${bucket}: HTTP ${res.status}`);
}

// Red de seguridad: borra los archivos viejos que nadie marco como descargados (ej. mensajes que se autodestruyeron)
async function cleanupOldMedia() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return;
  for (const bucket of MEDIA_BUCKETS) {
    const res = await fetch(`${SUPABASE_URL}/storage/v1/object/list/${bucket}`, {
      method: 'POST',
      headers: supabaseHeaders(),
      body: JSON.stringify({ prefix: '', limit: 1000, offset: 0, sortBy: { column: 'created_at', order: 'asc' } }),
    });
    if (!res.ok) {
      console.log(`No se pudo listar ${bucket}: HTTP ${res.status}`);
      continue;
    }
    const items = await res.json();
    const cutoff = Date.now() - MEDIA_MAX_AGE_MS;
    const old = items.filter((item) => item.created_at && new Date(item.created_at).getTime() < cutoff).map((item) => item.name);
    if (old.length > 0) {
      await deleteMediaObjects(bucket, old);
      console.log(`Borrados ${old.length} archivo(s) viejos de ${bucket}`);
    }
  }
}

wss.on('connection', (socket, req) => {
  // myUsername solo se asigna despues de un login/resume exitoso
  let myUsername = null;
  let myTokenHash = null;
  const clientIp = getClientIp(req);

  socket.isAlive = true;
  socket.on('pong', () => {
    socket.isAlive = true;
  });

  socket.on('error', (err) => {
    console.log('Error en una conexion individual (se ignora para no tumbar el servidor):', err.message);
  });

  async function completeLogin(username, tokenHash) {
    myUsername = username;
    myTokenHash = tokenHash;
    const previousConnection = onlineUsers.get(username);
    if (previousConnection && previousConnection.socket !== socket) {
      console.log(`${username} ya tenia una conexion vieja abierta, cerrandola porque acaba de entrar con una nueva`);
      previousConnection.socket.terminate();
    }
    onlineUsers.set(username, { socket, tokenHash });
    sendUserList(username);
    notifyWatchers(username);

    // Los mensajes se quedan en inbox hasta que el telefono confirme (ack) que los guardo
    const pending = await pool.query('SELECT id, from_username, envelope FROM inbox WHERE to_username = $1 ORDER BY id ASC', [username]);
    for (const row of pending.rows) {
      if (socket.readyState !== socket.OPEN) break;
      sendJson(socket, { type: 'message', id: String(row.id), from: row.from_username, envelope: JSON.parse(row.envelope) });
    }
    if (pending.rows.length > 0) console.log(`Enviados ${pending.rows.length} mensaje(s) pendiente(s) a ${username}`);
  }

  function rejectOldClient(resultType) {
    sendJson(socket, { type: resultType, success: false, error: UPDATE_REQUIRED_ERROR, updateRequired: true });
  }

  socket.on('message', async (data) => {
    let parsed;
    try {
      parsed = JSON.parse(data.toString());
    } catch (e) {
      return;
    }
    if (!parsed || typeof parsed.type !== 'string') return;

    try {
      if (parsed.type === 'register') {
        if (parsed.v !== PROTOCOL_VERSION) return rejectOldClient('register-result');
        const { username, password, identity, spk } = parsed;

        const validationError = validateNewUsername(username) || validateNewPassword(password)
          || (isValidIdentity(identity) && isValidSignedPreKey(spk) ? null : 'Llaves invalidas');
        if (validationError) {
          sendJson(socket, { type: 'register-result', success: false, error: validationError });
          return;
        }

        // Se compara sin distinguir mayusculas para que nadie pueda registrar "Omar" si ya existe "omar".
        // Los nombres se guardan tal cual y el login sigue siendo exacto, asi las cuentas existentes no cambian.
        const existing = await pool.query('SELECT username FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (existing.rows.length > 0) {
          sendJson(socket, { type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' });
          return;
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const recoveryCode = crypto.randomBytes(6).toString('hex').toUpperCase();
        const recoveryCodeHash = await bcrypt.hash(recoveryCode, 10);
        // ON CONFLICT cubre el caso de dos registros con el mismo nombre al mismo tiempo
        const inserted = await pool.query(
          `INSERT INTO users (username, password_hash, public_key, recovery_code_hash, identity_sign_pub, identity_dh_pub, spk_id, spk_pub, spk_sig)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (username) DO NOTHING RETURNING username`,
          [username, passwordHash, identity.dhPub, recoveryCodeHash, identity.signPub, identity.dhPub, spk.id, spk.pub, spk.sig]
        );
        if (inserted.rows.length === 0) {
          sendJson(socket, { type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' });
          return;
        }
        knownUsers.set(username, { profilePicture: null, identity, spk });
        const token = await createAuthSession(username);
        console.log(`Nueva cuenta registrada: ${username}`);
        sendJson(socket, { type: 'register-result', success: true, recoveryCode, token });
        await completeLogin(username, hashToken(token));
        return;
      }

      if (parsed.type === 'reset-password') {
        if (parsed.v !== PROTOCOL_VERSION) return rejectOldClient('reset-password-result');
        const { username, recoveryCode, newPassword } = parsed;

        if (isPasswordAuthBlocked(clientIp, username)) {
          sendJson(socket, { type: 'reset-password-result', success: false, error: TOO_MANY_ATTEMPTS_ERROR });
          return;
        }
        if (!isNonEmptyString(username, 200) || !isNonEmptyString(recoveryCode, 100)) {
          sendJson(socket, { type: 'reset-password-result', success: false, error: 'Usuario o código de recuperación incorrectos' });
          return;
        }
        const passwordError = validateNewPassword(newPassword);
        if (passwordError) {
          sendJson(socket, { type: 'reset-password-result', success: false, error: passwordError });
          return;
        }

        const result = await pool.query('SELECT recovery_code_hash FROM users WHERE username = $1', [username]);
        const row = result.rows[0];

        if (!row || !row.recovery_code_hash || !(await bcrypt.compare(recoveryCode, row.recovery_code_hash))) {
          recordFailedPasswordAuth(clientIp, username);
          sendJson(socket, { type: 'reset-password-result', success: false, error: 'Usuario o código de recuperación incorrectos' });
          return;
        }

        const newHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [newHash, username]);
        // Cambiar la contraseña cierra todas las sesiones abiertas de esa cuenta
        await pool.query('DELETE FROM auth_sessions WHERE username = $1', [username]);
        const online = onlineUsers.get(username);
        if (online) online.socket.close(4001, 'Contraseña cambiada');
        console.log(`Contraseña restablecida para ${username}`);
        sendJson(socket, { type: 'reset-password-result', success: true });
        return;
      }

      if (parsed.type === 'login') {
        if (parsed.v !== PROTOCOL_VERSION) return rejectOldClient('login-result');
        const { username, password, identity, spk } = parsed;

        if (isPasswordAuthBlocked(clientIp, username)) {
          sendJson(socket, { type: 'login-result', success: false, error: TOO_MANY_ATTEMPTS_ERROR });
          return;
        }
        if (!isNonEmptyString(username, 200) || !isNonEmptyString(password, 1000)) {
          sendJson(socket, { type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' });
          return;
        }
        if (!isValidIdentity(identity) || !isValidSignedPreKey(spk)) {
          sendJson(socket, { type: 'login-result', success: false, error: 'Llaves invalidas' });
          return;
        }

        const result = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
          recordFailedPasswordAuth(clientIp, username);
          sendJson(socket, { type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' });
          return;
        }

        // Si la identidad cambia (app reinstalada o telefono nuevo), los contactos lo ven y la app les pide verificar
        const known = knownUsers.get(username) || { profilePicture: null, identity: null, spk: null };
        const identityChanged = !known.identity || known.identity.signPub !== identity.signPub || known.identity.dhPub !== identity.dhPub;
        await pool.query(
          'UPDATE users SET public_key = $1, identity_sign_pub = $2, identity_dh_pub = $3, spk_id = $4, spk_pub = $5, spk_sig = $6 WHERE username = $7',
          [identity.dhPub, identity.signPub, identity.dhPub, spk.id, spk.pub, spk.sig, username]
        );
        knownUsers.set(username, { ...known, identity, spk });
        if (identityChanged) console.log(`${username} inicio sesion con una identidad nueva`);

        const token = await createAuthSession(username);
        sendJson(socket, { type: 'login-result', success: true, token });
        console.log(`${username} inició sesión`);
        await completeLogin(username, hashToken(token));
        return;
      }

      // Reconexion con el token guardado: la contraseña no se vuelve a mandar
      if (parsed.type === 'resume') {
        if (parsed.v !== PROTOCOL_VERSION) return rejectOldClient('resume-result');
        const { username, token } = parsed;
        if (isAuthBlocked(`ip:${clientIp}`, FAILED_AUTH_LIMIT_PER_IP)) {
          sendJson(socket, { type: 'resume-result', success: false, error: TOO_MANY_ATTEMPTS_ERROR, retryLater: true });
          return;
        }
        if (!isNonEmptyString(username, 200) || !isNonEmptyString(token, 200)) {
          sendJson(socket, { type: 'resume-result', success: false });
          return;
        }
        const tokenHash = hashToken(token);
        const session = await pool.query(
          'UPDATE auth_sessions SET last_used_at = NOW() WHERE token_hash = $1 AND username = $2 RETURNING username',
          [tokenHash, username]
        );
        if (session.rows.length === 0) {
          recordFailedAuth(`ip:${clientIp}`, FAILED_AUTH_LIMIT_PER_IP);
          sendJson(socket, { type: 'resume-result', success: false });
          return;
        }
        sendJson(socket, { type: 'resume-result', success: true });
        await completeLogin(username, tokenHash);
        return;
      }

      // Todo lo que sigue necesita sesion iniciada
      if (!myUsername) return;

      if (parsed.type === 'logout') {
        if (myTokenHash) await pool.query('DELETE FROM auth_sessions WHERE token_hash = $1', [myTokenHash]);
        await pool.query('UPDATE users SET push_token = NULL WHERE username = $1', [myUsername]);
        socket.close(1000, 'Sesion cerrada');
        return;
      }

      if (parsed.type === 'publish-spk') {
        if (!isValidSignedPreKey(parsed.spk)) return;
        const { spk } = parsed;
        await pool.query('UPDATE users SET spk_id = $1, spk_pub = $2, spk_sig = $3 WHERE username = $4', [spk.id, spk.pub, spk.sig, myUsername]);
        const known = knownUsers.get(myUsername);
        if (known) known.spk = spk;
        return;
      }

      if (parsed.type === 'get-bundle') {
        const target = knownUsers.get(parsed.username);
        const bundle = target && target.identity && target.spk ? { identity: target.identity, spk: target.spk } : null;
        sendJson(socket, { type: 'bundle-result', requestId: parsed.requestId, username: parsed.username, bundle });
        return;
      }

      if (parsed.type === 'add-contact') {
        const wanted = typeof parsed.username === 'string' ? parsed.username.trim() : '';
        let found = null;
        for (const name of knownUsers.keys()) {
          if (name.toLowerCase() === wanted.toLowerCase()) found = name;
        }
        if (!found || found === myUsername) {
          sendJson(socket, { type: 'add-contact-result', requestId: parsed.requestId, success: false, error: 'No existe un usuario con ese nombre' });
          return;
        }
        await addContact(myUsername, found);
        sendJson(socket, { type: 'add-contact-result', requestId: parsed.requestId, success: true, username: found });
        sendUserList(myUsername);
        return;
      }

      if (parsed.type === 'remove-contact') {
        if (!isNonEmptyString(parsed.username, 200)) return;
        await pool.query('DELETE FROM contacts WHERE owner = $1 AND contact = $2', [myUsername, parsed.username]);
        contactsOf.get(myUsername)?.delete(parsed.username);
        sendUserList(myUsername);
        return;
      }

      if (parsed.type === 'register-push-token') {
        if (isNonEmptyString(parsed.token, 500)) {
          await pool.query('UPDATE users SET push_token = $1 WHERE username = $2', [parsed.token, myUsername]);
        }
        return;
      }

      if (parsed.type === 'update-profile-picture') {
        if (typeof parsed.profilePicture === 'string') {
          let profilePicture;
          try {
            profilePicture = await shrinkProfilePicture(parsed.profilePicture);
          } catch (err) {
            console.log(`La foto de perfil que mando ${myUsername} no es una imagen valida, se ignora:`, err.message);
            return;
          }
          await pool.query('UPDATE users SET profile_picture = $1 WHERE username = $2', [profilePicture, myUsername]);
          const known = knownUsers.get(myUsername);
          if (known) known.profilePicture = profilePicture;
          sendUserList(myUsername);
          notifyWatchers(myUsername);
        }
        return;
      }

      if (parsed.type === 'direct-message') {
        const { to, clientId, envelope, silent } = parsed;
        const validEnvelope = envelope && isNonEmptyString(envelope.h, 2000) && isNonEmptyString(envelope.c, MAX_ENVELOPE_LENGTH)
          && isNonEmptyString(envelope.nonce, 64);
        if (!isNonEmptyString(to, 200) || !isNonEmptyString(clientId, 100) || !validEnvelope) {
          console.log(`Mensaje directo invalido de ${myUsername}, se descarta`);
          return;
        }
        if (!knownUsers.has(to)) {
          sendJson(socket, { type: 'rejected', clientId, error: 'El destinatario no existe' });
          return;
        }

        const envelopeJson = JSON.stringify({ h: envelope.h, c: envelope.c, nonce: envelope.nonce });
        const inserted = await pool.query(
          'INSERT INTO inbox (to_username, from_username, envelope) VALUES ($1, $2, $3) RETURNING id',
          [to, myUsername, envelopeJson]
        );
        const id = String(inserted.rows[0].id);
        // Solo despues de guardarlo se le confirma al que envia; asi su app sabe que ya no tiene que reintentar
        sendJson(socket, { type: 'accepted', clientId });

        // El que recibe un mensaje ve al remitente en su lista aunque no lo hubiera agregado
        await addContact(myUsername, to);
        if (await addContact(to, myUsername)) sendUserList(to);

        const recipient = onlineUsers.get(to);
        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {
          sendJson(recipient.socket, { type: 'message', id, from: myUsername, envelope: JSON.parse(envelopeJson) });
        } else if (!silent) {
          await sendPushNotification(to);
        }
        return;
      }

      if (parsed.type === 'ack') {
        const ids = Array.isArray(parsed.ids) ? parsed.ids.filter((id) => /^\d{1,18}$/.test(String(id))).slice(0, 500) : [];
        if (ids.length > 0) {
          await pool.query('DELETE FROM inbox WHERE to_username = $1 AND id = ANY($2::bigint[])', [myUsername, ids]);
        }
        return;
      }

      if (parsed.type === 'media-done') {
        const { bucket, path } = parsed;
        if (MEDIA_BUCKETS.includes(bucket) && typeof path === 'string' && MEDIA_PATH_REGEX.test(path)) {
          await deleteMediaObjects(bucket, [path]);
        }
        return;
      }
    } catch (err) {
      console.log('Error procesando mensaje:', err.message);
    }
  });

  socket.on('close', () => {
    try {
      if (myUsername) {
        const current = onlineUsers.get(myUsername);
        if (current && current.socket === socket) {
          onlineUsers.delete(myUsername);
          notifyWatchers(myUsername);
        }
      }
    } catch (err) {
      console.log('Error manejando el cierre de una conexion (se ignora para no tumbar el servidor):', err.message);
    }
  });
});

const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((socket) => {
    if (socket.isAlive === false) {
      console.log('Terminando una conexion inactiva (zombie) que ya no respondia');
      return socket.terminate();
    }
    socket.isAlive = false;
    socket.ping();
  });
}, HEARTBEAT_INTERVAL_MS);

const userListRefreshInterval = setInterval(() => {
  try {
    sendUserListToEveryone();
  } catch (e) {
    console.log('Error actualizando la lista de usuarios en el intervalo:', e.message);
  }
}, 30000);

const failedAuthCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of failedAuthAttempts) {
    if (now - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) failedAuthAttempts.delete(key);
  }
}, FAILED_AUTH_WINDOW_MS);

// Limpieza periodica: mensajes que nunca se recogieron, sesiones abandonadas y archivos viejos
async function periodicCleanup() {
  try {
    const inbox = await pool.query(`DELETE FROM inbox WHERE created_at < NOW() - INTERVAL '30 days'`);
    const sessions = await pool.query(`DELETE FROM auth_sessions WHERE last_used_at < NOW() - INTERVAL '90 days'`);
    if (inbox.rowCount > 0 || sessions.rowCount > 0) {
      console.log(`Limpieza: ${inbox.rowCount} mensaje(s) viejos y ${sessions.rowCount} sesion(es) abandonadas borrados`);
    }
    await cleanupOldMedia();
  } catch (err) {
    console.log('Error en la limpieza periodica:', err.message);
  }
}
const cleanupInterval = setInterval(periodicCleanup, 6 * 60 * 60 * 1000);

wss.on('close', () => {
  clearInterval(heartbeatInterval);
  clearInterval(userListRefreshInterval);
  clearInterval(failedAuthCleanupInterval);
  clearInterval(cleanupInterval);
});

// Apagado ordenado: Render manda SIGTERM al redeployar. Se avisa a los telefonos con codigo 1001 (la app se reconecta sola),
// se deja de aceptar conexiones y se cierra el pool de la BD. Si algo se atora, se fuerza la salida a los 5 segundos.
let isShuttingDown = false;
async function shutdown(reason, exitCode) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Apagando el servidor (${reason})...`);
  setTimeout(() => process.exit(exitCode), 5000);

  try {
    for (const socket of wss.clients) socket.close(1001, 'Servidor reiniciando');
    wss.close();
    await new Promise((resolve) => httpServer.close(resolve));
    await pool.end();
  } catch (err) {
    console.log('Error durante el apagado:', err.message);
  }
  process.exit(exitCode);
}

process.on('SIGTERM', () => shutdown('SIGTERM', 0));
process.on('SIGINT', () => shutdown('SIGINT', 0));

wss.on('error', (err) => {
  console.log('Error en el servidor de WebSockets (se ignora para no tumbar el servidor):', err.message);
});

initDatabase()
  .then(loadKnownUsers)
  .then(() => {
    // Si no se puede abrir el puerto, salir: si no, el proceso quedaria vivo sin escuchar
    httpServer.once('error', (err) => {
      console.error('No se pudo abrir el puerto, se cierra el proceso para que se reinicie:', err.message);
      process.exit(1);
    });
    httpServer.listen(PORT, () => {
      console.log(`Servidor de chat corriendo en el puerto ${PORT}`);
      if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
        console.log('Aviso: faltan SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY, los archivos de Supabase no se borraran');
      }
      shrinkExistingProfilePictures().catch((err) => console.log('Error reduciendo fotos de perfil existentes:', err.message));
      periodicCleanup();
    });
  })
  .catch((err) => {
    // Sin base de datos el servidor no sirve; se sale para que la plataforma lo reinicie en vez de quedar vivo sin escuchar
    console.error('Error inicializando la base de datos, se cierra el proceso para que se reinicie:', err);
    process.exit(1);
  });
