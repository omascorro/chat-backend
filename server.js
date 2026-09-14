const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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
  console.log('✅ Tablas verificadas/creadas en la base de datos');
}

const wss = new WebSocketServer({ port: PORT });
const onlineUsers = new Map(); // username -> { socket, publicKey }

async function broadcastUserList() {
  const result = await pool.query('SELECT username, public_key FROM users');
  const list = result.rows.map((row) => ({
    username: row.username,
    publicKey: row.public_key,
    online: onlineUsers.has(row.username),
  }));
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
    console.log('🔔 Respuesta de Expo Push:', JSON.stringify(result2));

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
          console.log('🧾 Recibo de entrega:', JSON.stringify(receiptData));
        } catch (e) {
          console.log('Error obteniendo recibo:', e.message);
        }
      }, 15000);
    }
  } catch (err) {
    console.log('⚠️ Error enviando push:', err.message);
  }
}

wss.on('connection', (socket) => {
  let myUsername = null;

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

        const existing = await pool.query('SELECT username FROM users WHERE username = $1', [username]);
        if (existing.rows.length > 0) {
          socket.send(JSON.stringify({ type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' }));
          return;
        }

        const passwordHash = bcrypt.hashSync(password, 10);
        const recoveryCode = crypto.randomBytes(6).toString('hex').toUpperCase();
        const recoveryCodeHash = bcrypt.hashSync(recoveryCode, 10);
        await pool.query(
          'INSERT INTO users (username, password_hash, public_key, recovery_code_hash) VALUES ($1, $2, $3, $4)',
          [username, passwordHash, publicKey, recoveryCodeHash]
        );
        console.log(`📝 Nueva cuenta registrada: ${username}`);
        socket.send(JSON.stringify({ type: 'register-result', success: true, recoveryCode }));
        return;
      }

      if (parsed.type === 'reset-password') {
        const { username, recoveryCode, newPassword } = parsed;
        const result = await pool.query('SELECT recovery_code_hash FROM users WHERE username = $1', [username]);
        const row = result.rows[0];

        if (!row || !row.recovery_code_hash || !bcrypt.compareSync(recoveryCode, row.recovery_code_hash)) {
          socket.send(JSON.stringify({ type: 'reset-password-result', success: false, error: 'Usuario o código de recuperación incorrectos' }));
          return;
        }

        const newHash = bcrypt.hashSync(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [newHash, username]);
        console.log(`🔑 Contraseña restablecida para ${username}`);
        socket.send(JSON.stringify({ type: 'reset-password-result', success: true }));
        return;
      }

      if (parsed.type === 'login') {
        const { username, password, publicKey } = parsed;

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
          socket.send(JSON.stringify({ type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' }));
          return;
        }

        await pool.query('UPDATE users SET public_key = $1 WHERE username = $2', [publicKey, username]);

        myUsername = username;
        onlineUsers.set(username, { socket, publicKey });
        socket.send(JSON.stringify({ type: 'login-result', success: true }));
        await broadcastUserList();
        console.log(`👤 ${username} inició sesión`);

        const pendingResult = await pool.query(
          'SELECT * FROM pending_messages WHERE to_username = $1 ORDER BY id ASC',
          [username]
        );
        if (pendingResult.rows.length > 0) {
          for (const row of pendingResult.rows) {
            socket.send(JSON.stringify({
              type: 'direct-message',
              from: row.from_username,
              fromPublicKey: row.from_public_key,
              ciphertext: row.ciphertext,
              nonce: row.nonce,
            }));
          }
          console.log(`📬 Entregados ${pendingResult.rows.length} mensaje(s) pendiente(s) a ${username}`);
          await pool.query('DELETE FROM pending_messages WHERE to_username = $1', [username]);
        }
        return;
      }

      if (parsed.type === 'register-push-token') {
        if (myUsername) {
          await pool.query('UPDATE users SET push_token = $1 WHERE username = $2', [parsed.token, myUsername]);
          console.log(`🔔 Token de notificaciones guardado para ${myUsername}`);
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

        const userResult = await pool.query('SELECT public_key FROM users WHERE username = $1', [myUsername]);
        const fromPublicKey = userResult.rows[0]?.public_key || null;

        const payload = {
          type: 'direct-message',
          from: myUsername,
          fromPublicKey,
          ciphertext: parsed.ciphertext,
          nonce: parsed.nonce,
        };

        const recipient = onlineUsers.get(parsed.to);
        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {
          recipient.socket.send(JSON.stringify(payload));
          console.log(`📩 Mensaje entregado: ${myUsername} → ${parsed.to}`);
        } else {
          await pool.query(
            'INSERT INTO pending_messages (to_username, from_username, from_public_key, ciphertext, nonce) VALUES ($1, $2, $3, $4, $5)',
            [parsed.to, myUsername, fromPublicKey, parsed.ciphertext, parsed.nonce]
          );
          console.log(`📥 ${parsed.to} está desconectado, mensaje guardado para después`);
          await sendPushNotification(parsed.to, myUsername);
        }
        return;
      }
    } catch (err) {
      console.log('⚠️ Error procesando mensaje:', err.message);
    }
  });

  socket.on('close', async () => {
    if (myUsername) {
      onlineUsers.delete(myUsername);
      console.log(`❌ ${myUsername} se desconectó`);
      await broadcastUserList();
    }
  });
});

initDatabase()
  .then(() => {
    console.log(`🚀 Servidor de chat corriendo en el puerto ${PORT}`);
  })
  .catch((err) => {
    console.error('❌ Error inicializando la base de datos:', err);
  });