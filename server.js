const { WebSocketServer } = require('ws');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 3000;
const USERS_FILE = './users.json';
const PENDING_FILE = './pending_messages.json';

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function loadPending() {
  if (!fs.existsSync(PENDING_FILE)) return {};
  return JSON.parse(fs.readFileSync(PENDING_FILE, 'utf-8'));
}
function savePending(data) {
  fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2));
}

let registeredUsers = loadUsers(); // username -> { passwordHash, publicKey, pushToken }
let pendingMessages = loadPending(); // username -> [ mensajes guardados ]

const wss = new WebSocketServer({ port: PORT });
const onlineUsers = new Map(); // username -> { socket, publicKey }

function broadcastUserList() {
  const list = Object.keys(registeredUsers).map((uname) => ({
    username: uname,
    publicKey: registeredUsers[uname].publicKey,
    online: onlineUsers.has(uname),
  }));
  const payload = JSON.stringify({ type: 'user-list', users: list });
  for (const [, info] of onlineUsers) {
    if (info.socket.readyState === info.socket.OPEN) info.socket.send(payload);
  }
}

async function sendPushNotification(toUsername, fromUsername) {
  const user = registeredUsers[toUsername];
  if (!user || !user.pushToken) return;
  try {
    const response = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: user.pushToken,
        title: 'Nuevo mensaje',
        body: `${fromUsername} te mandó un mensaje cifrado`,
        sound: 'default',
      }),
    });
    const result = await response.json();
    console.log('🔔 Respuesta de Expo Push:', JSON.stringify(result));

    if (result.data && result.data.id) {
      const ticketId = result.data.id;
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

  socket.on('message', (data) => {
    let parsed;
    try {
      parsed = JSON.parse(data.toString());
    } catch (e) {
      return;
    }

    if (parsed.type === 'register') {
      const { username, password, publicKey } = parsed;
      if (registeredUsers[username]) {
        socket.send(JSON.stringify({ type: 'register-result', success: false, error: 'Ese nombre de usuario ya existe' }));
        return;
      }
      const passwordHash = bcrypt.hashSync(password, 10);
      registeredUsers[username] = { passwordHash, publicKey };
      saveUsers(registeredUsers);
      console.log(`📝 Nueva cuenta registrada: ${username}`);
      socket.send(JSON.stringify({ type: 'register-result', success: true }));
      return;
    }

    if (parsed.type === 'login') {
      const { username, password, publicKey } = parsed;
      const user = registeredUsers[username];
      if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        socket.send(JSON.stringify({ type: 'login-result', success: false, error: 'Usuario o contraseña incorrectos' }));
        return;
      }
      user.publicKey = publicKey;
      saveUsers(registeredUsers);

      myUsername = username;
      onlineUsers.set(username, { socket, publicKey });
      socket.send(JSON.stringify({ type: 'login-result', success: true }));
      broadcastUserList();
      console.log(`👤 ${username} inició sesión`);

      const pending = pendingMessages[username];
      if (pending && pending.length > 0) {
        for (const msg of pending) {
          socket.send(JSON.stringify(msg));
        }
        console.log(`📬 Entregados ${pending.length} mensaje(s) pendiente(s) a ${username}`);
        delete pendingMessages[username];
        savePending(pendingMessages);
      }
      return;
    }

    if (parsed.type === 'register-push-token') {
      if (myUsername && registeredUsers[myUsername]) {
        registeredUsers[myUsername].pushToken = parsed.token;
        saveUsers(registeredUsers);
        console.log(`🔔 Token de notificaciones guardado para ${myUsername}`);
      }
      return;
    }

    if (parsed.type === 'direct-message') {
      if (!myUsername) return; // Ignoramos mensajes de conexiones que no iniciaron sesión
      const fromPublicKey = registeredUsers[myUsername] ? registeredUsers[myUsername].publicKey : null;
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
        if (!pendingMessages[parsed.to]) pendingMessages[parsed.to] = [];
        pendingMessages[parsed.to].push(payload);
        savePending(pendingMessages);
        console.log(`📥 ${parsed.to} está desconectado, mensaje guardado para después`);
        sendPushNotification(parsed.to, myUsername);
      }
      return;
    }
  });

  socket.on('close', () => {
    if (myUsername) {
      onlineUsers.delete(myUsername);
      console.log(`❌ ${myUsername} se desconectó`);
      broadcastUserList();
    }
  });
});

console.log(`🚀 Servidor de chat corriendo en el puerto ${PORT}`);