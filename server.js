const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const HEARTBEAT_INTERVAL_MS = 10000;

process.on('uncaughtException', (err) => {
  console.log('Error no atrapado en algun lado (se ignora para no tumbar el servidor):', err.message);
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_messages (
      id SERIAL PRIMARY KEY,
      to_username TEXT NOT NULL,
      from_username TEXT NOT NULL,
      from_public_key TEXT,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS counter INTEGER;`);
  console.log('Tablas verificadas/creadas en la base de datos');
}

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 30;
const PASSWORD_MIN_LENGTH = 6;
const PASSWORD_MAX_LENGTH = 72; // bcrypt ignora todo despues de 72 bytes

function isNonEmptyString(value, maxLength) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
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

// Limite de intentos fallidos de login / reset por IP, para frenar ataques de fuerza bruta.
// Solo cuentan los fallos, asi que la reconexion automatica de la app con la contraseña correcta nunca se bloquea.
const FAILED_AUTH_LIMIT = 20;
const FAILED_AUTH_WINDOW_MS = 15 * 60 * 1000;
const failedAuthAttempts = new Map(); // ip -> { count, firstAttemptAt }

function isAuthBlocked(ip) {
  const entry = failedAuthAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) {
    failedAuthAttempts.delete(ip);
    return false;
  }
  return entry.count >= FAILED_AUTH_LIMIT;
}

function recordFailedAuth(ip) {
  const entry = failedAuthAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) {
    failedAuthAttempts.set(ip, { count: 1, firstAttemptAt: Date.now() });
  } else {
    entry.count += 1;
    if (entry.count === FAILED_AUTH_LIMIT) console.log(`Demasiados intentos fallidos desde ${ip}, se bloquea temporalmente`);
  }
}

function getClientIp(req) {
  // Render pone la IP real del cliente en x-forwarded-for
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'desconocida';
}

const TOO_MANY_ATTEMPTS_ERROR = 'Demasiados intentos fallidos, espera unos minutos';

const http = require('http');

const httpServer = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Servidor de chat activo');
});

// La foto de perfil viaja en base64 por aqui, por eso el limite es generoso; el default de ws (100 MB) es demasiado
const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
const wss = new WebSocketServer({ server: httpServer, maxPayload: MAX_MESSAGE_BYTES });
const onlineUsers = new Map(); // username -> { socket, publicKey }

// Copia en memoria de los usuarios, para no leer toda la tabla (con fotos) en cada broadcast.
// Este servidor es el unico que escribe en la tabla users, asi que se mantiene al dia actualizandola junto con la BD.
const knownUsers = new Map(); // username -> { publicKey, profilePicture }

async function loadKnownUsers() {
  const result = await pool.query('SELECT username, public_key, profile_picture FROM users');
  knownUsers.clear();
  for (const row of result.rows) {
    knownUsers.set(row.username, { publicKey: row.public_key, profilePicture: row.profile_picture });
  }
  console.log(`${knownUsers.size} usuario(s) cargados en memoria`);
}

function broadcastUserList() {
  const list = [];
  for (const [username, info] of knownUsers) {
    list.push({
      username,
      publicKey: info.publicKey,
      profilePicture: info.profilePicture,
      online: onlineUsers.has(username),
    });
  }
  const payload = JSON.stringify({ type: 'user-list', users: list });
  for (const [, info] of onlineUsers) {
    if (info.socket.readyState === info.socket.OPEN) info.socket.send(payload);
  }
}

async function sendPushNotification(toUsername, fromUsername) {
  const result = await pool.query('SELECT push_token FROM users WHERE username = $1', [toUsername]);
  const pushToken = result.rows[0]?.push_token;
  if (!pushToken) return;

  try {
    const response = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: pushToken,
        title: 'Nuevo mensaje',
        body: `${fromUsername} te mandó un mensaje cifrado`,
        sound: 'default',
        channelId: 'default',
      }),
    });
    const result2 = await response.json();
    console.log('Respuesta de Expo Push:', JSON.stringify(result2));

    if (result2.data && result2.data.id) {
      const ticketId = result2.data.id;
      setTimeout(async () => {
        try {
          const receiptRes = await fetch('https://exp.host/--/api/v2/push/getReceipts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: [ticketId] }),
          });
          const receiptData = await receiptRes.json();
          console.log('Recibo de entrega:', JSON.stringify(receiptData));
        } catch (e) {
          console.log('Error obteniendo recibo:', e.message);
        }
      }, 15000);
    }
  } catch (err) {
    console.log('Error enviando push:', err.message);
  }
}

wss.on('connection', (socket, req) => {
  let myUsername = null;
  const clientIp = getClientIp(req);

  socket.isAlive = true;
  socket.on('pong', () => {
    socket.isAlive = true;
  });

  socket.on('error', (err) => {
    console.log('Error en una conexion individual (se ignora para no tumbar el servidor):', err.message);
  });

  socket.on('message', async (data) => {
    let parsed;
    try {
      parsed = JSON.parse(data.toString());
    } catch (e) {
      return;
    }

    try {
      if (parsed.type === 'register') {
        const { username, password, publicKey } = parsed;

        const validationError = validateNewUsername(username) || validateNewPassword(password)
          || (isNonEmptyString(publicKey, 200) ? null : 'Llave publica invalida');
        if (validationError) {
          socket.send(JSON.stringify({ type: 'register-result', success: false, error: validationError }));
          return;
        }

        const existing = await pool.query('SELECT username FROM users WHERE username = $1', [username]);
        if (existing.rows.length > 0) {
          socket.send(JSON.stringify({ type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' }));
          return;
        }

        const passwordHash = bcrypt.hashSync(password, 10);
        const recoveryCode = crypto.randomBytes(6).toString('hex').toUpperCase();
        const recoveryCodeHash = bcrypt.hashSync(recoveryCode, 10);
        // ON CONFLICT cubre el caso de dos registros con el mismo nombre al mismo tiempo
        const inserted = await pool.query(
          'INSERT INTO users (username, password_hash, public_key, recovery_code_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (username) DO NOTHING RETURNING username',
          [username, passwordHash, publicKey, recoveryCodeHash]
        );
        if (inserted.rows.length === 0) {
          socket.send(JSON.stringify({ type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' }));
          return;
        }
        knownUsers.set(username, { publicKey, profilePicture: null });
        console.log(`Nueva cuenta registrada: ${username}`);
        socket.send(JSON.stringify({ type: 'register-result', success: true, recoveryCode }));
        return;
      }

      if (parsed.type === 'reset-password') {
        const { username, recoveryCode, newPassword } = parsed;

        if (isAuthBlocked(clientIp)) {
          socket.send(JSON.stringify({ type: 'reset-password-result', success: false, error: TOO_MANY_ATTEMPTS_ERROR }));
          return;
        }
        if (!isNonEmptyString(username, 200) || !isNonEmptyString(recoveryCode, 100)) {
          socket.send(JSON.stringify({ type: 'reset-password-result', success: false, error: 'Usuario o código de recuperación incorrectos' }));
          return;
        }
        const passwordError = validateNewPassword(newPassword);
        if (passwordError) {
          socket.send(JSON.stringify({ type: 'reset-password-result', success: false, error: passwordError }));
          return;
        }

        const result = await pool.query('SELECT recovery_code_hash FROM users WHERE username = $1', [username]);
        const row = result.rows[0];

        if (!row || !row.recovery_code_hash || !bcrypt.compareSync(recoveryCode, row.recovery_code_hash)) {
          recordFailedAuth(clientIp);
          socket.send(JSON.stringify({ type: 'reset-password-result', success: false, error: 'Usuario o código de recuperación incorrectos' }));
          return;
        }

        const newHash = bcrypt.hashSync(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [newHash, username]);
        console.log(`Contraseña restablecida para ${username}`);
        socket.send(JSON.stringify({ type: 'reset-password-result', success: true }));
        return;
      }

      if (parsed.type === 'login') {
        const { username, password, publicKey } = parsed;

        if (isAuthBlocked(clientIp)) {
          socket.send(JSON.stringify({ type: 'login-result', success: false, error: TOO_MANY_ATTEMPTS_ERROR }));
          return;
        }
        if (!isNonEmptyString(username, 200) || !isNonEmptyString(password, 1000)) {
          socket.send(JSON.stringify({ type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' }));
          return;
        }
        if (!isNonEmptyString(publicKey, 200)) {
          socket.send(JSON.stringify({ type: 'login-result', success: false, error: 'Llave publica invalida' }));
          return;
        }

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
          recordFailedAuth(clientIp);
          socket.send(JSON.stringify({ type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' }));
          return;
        }

        await pool.query('UPDATE users SET public_key = $1 WHERE username = $2', [publicKey, username]);
        knownUsers.set(username, { publicKey, profilePicture: user.profile_picture });

        myUsername = username;
        const previousConnection = onlineUsers.get(username);
        if (previousConnection && previousConnection.socket !== socket) {
          console.log(`${username} ya tenia una conexion vieja abierta, cerrandola porque acaba de entrar con una nueva`);
          previousConnection.socket.terminate();
        }
        onlineUsers.set(username, { socket, publicKey });
        socket.send(JSON.stringify({ type: 'login-result', success: true }));
        broadcastUserList();
        console.log(`${username} inició sesión`);

        const pendingResult = await pool.query(
          'SELECT * FROM pending_messages WHERE to_username = $1 ORDER BY id ASC',
          [username]
        );
        if (pendingResult.rows.length > 0) {
          // Solo se borran los mensajes que de verdad se enviaron; si llega uno nuevo mientras tanto, se queda guardado
          const deliveredIds = [];
          for (const row of pendingResult.rows) {
            if (socket.readyState !== socket.OPEN) break;
            socket.send(JSON.stringify({
              type: 'direct-message',
              from: row.from_username,
              fromPublicKey: row.from_public_key,
              ciphertext: row.ciphertext,
              nonce: row.nonce,
              counter: row.counter,
            }));
            deliveredIds.push(row.id);
          }
          if (deliveredIds.length > 0) {
            await pool.query('DELETE FROM pending_messages WHERE id = ANY($1::int[])', [deliveredIds]);
          }
          console.log(`Entregados ${deliveredIds.length} de ${pendingResult.rows.length} mensaje(s) pendiente(s) a ${username}`);
        }
        return;
      }

      if (parsed.type === 'register-push-token') {
        if (myUsername && isNonEmptyString(parsed.token, 500)) {
          await pool.query('UPDATE users SET push_token = $1 WHERE username = $2', [parsed.token, myUsername]);
          console.log(`Token de notificaciones guardado para ${myUsername}`);
        }
        return;
      }

      if (parsed.type === 'update-profile-picture') {
        if (myUsername && typeof parsed.profilePicture === 'string') {
          await pool.query('UPDATE users SET profile_picture = $1 WHERE username = $2', [parsed.profilePicture, myUsername]);
          const known = knownUsers.get(myUsername);
          if (known) known.profilePicture = parsed.profilePicture;
          console.log(`Foto de perfil actualizada para ${myUsername}`);
          broadcastUserList();
        }
        return;
      }

      if (parsed.type === 'read-receipt') {
        const recipient = onlineUsers.get(parsed.to);
        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {
          recipient.socket.send(JSON.stringify({
            type: 'read-receipt',
            from: myUsername,
            messageId: parsed.messageId,
          }));
        }
        return;
      }

      if (parsed.type === 'direct-message') {
        if (!myUsername) return;

        const hasValidCounter = parsed.counter === undefined || parsed.counter === null
          || (Number.isInteger(parsed.counter) && parsed.counter >= 0 && parsed.counter <= 2147483647);
        if (!isNonEmptyString(parsed.to, 200) || !isNonEmptyString(parsed.ciphertext, 1000000)
          || !isNonEmptyString(parsed.nonce, 200) || !hasValidCounter) {
          console.log(`Mensaje directo invalido de ${myUsername}, se descarta`);
          return;
        }

        const userResult = await pool.query('SELECT public_key FROM users WHERE username = $1', [myUsername]);
        const fromPublicKey = userResult.rows[0]?.public_key || null;

        const payload = {
          type: 'direct-message',
          from: myUsername,
          fromPublicKey,
          ciphertext: parsed.ciphertext,
          nonce: parsed.nonce,
          counter: parsed.counter,
        };

        const recipient = onlineUsers.get(parsed.to);
        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {
          recipient.socket.send(JSON.stringify(payload));
          console.log(`Mensaje entregado: ${myUsername} -> ${parsed.to}`);
        } else {
          const recipientExists = await pool.query('SELECT 1 FROM users WHERE username = $1', [parsed.to]);
          if (recipientExists.rows.length === 0) {
            console.log(`${myUsername} intento mandar un mensaje a ${parsed.to}, que no existe; se descarta`);
            return;
          }
          await pool.query(
            'INSERT INTO pending_messages (to_username, from_username, from_public_key, ciphertext, nonce, counter) VALUES ($1, $2, $3, $4, $5, $6)',
            [parsed.to, myUsername, fromPublicKey, parsed.ciphertext, parsed.nonce, parsed.counter]
          );
          console.log(`${parsed.to} esta desconectado, mensaje guardado para despues`);
          await sendPushNotification(parsed.to, myUsername);
        }
        return;
      }
    } catch (err) {
      console.log('Error procesando mensaje:', err.message);
    }
  });

  socket.on('close', async () => {
    try {
      if (myUsername) {
        const current = onlineUsers.get(myUsername);
        if (current && current.socket === socket) {
          onlineUsers.delete(myUsername);
          console.log(`${myUsername} se desconecto`);
          broadcastUserList();
        } else {
          console.log(`Se cerro una conexion vieja de ${myUsername} que ya habia sido reemplazada por una nueva, no se hace nada`);
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
    broadcastUserList();
  } catch (e) {
    console.log('Error actualizando la lista de usuarios en el intervalo:', e.message);
  }
}, 15000);

const failedAuthCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of failedAuthAttempts) {
    if (now - entry.firstAttemptAt > FAILED_AUTH_WINDOW_MS) failedAuthAttempts.delete(ip);
  }
}, FAILED_AUTH_WINDOW_MS);

wss.on('close', () => {
  clearInterval(heartbeatInterval);
  clearInterval(userListRefreshInterval);
  clearInterval(failedAuthCleanupInterval);
});

wss.on('error', (err) => {
  console.log('Error en el servidor de WebSockets (se ignora para no tumbar el servidor):', err.message);
});

initDatabase()
  .then(loadKnownUsers)
  .then(() => {
    httpServer.listen(PORT, () => {
      console.log(`Servidor de chat corriendo en el puerto ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Error inicializando la base de datos:', err);
  });
  