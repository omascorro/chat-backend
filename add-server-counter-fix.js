const fs = require('fs');
const path = 'server.js';

let src = fs.readFileSync(path, 'utf8');
const hadCRLF = src.indexOf('\r\n') !== -1;
if (hadCRLF) src = src.split('\r\n').join('\n');

function applyReplace(source, oldStr, newStr, label) {
  const count = source.split(oldStr).length - 1;
  if (count !== 1) {
    throw new Error("No se encontro (o se encontro mas de una vez) el ancla: " + label + " (coincidencias: " + count + ")");
  }
  return source.split(oldStr).join(newStr);
}

// 1. servidor HTTP normal para que UptimeRobot vea 200 OK en vez de 426
src = applyReplace(
  src,
  "const wss = new WebSocketServer({ port: PORT });",
  "const http = require('http');\n\nconst httpServer = http.createServer((req, res) => {\n  res.writeHead(200, { 'Content-Type': 'text/plain' });\n  res.end('Servidor de chat activo');\n});\n\nconst wss = new WebSocketServer({ server: httpServer });",
  "servidor HTTP normal para que UptimeRobot vea 200 OK en vez de 426"
);

// 2. agregar columna counter a pending_messages
src = applyReplace(
  src,
  "  await pool.query(`\n    CREATE TABLE IF NOT EXISTS pending_messages (\n      id SERIAL PRIMARY KEY,\n      to_username TEXT NOT NULL,\n      from_username TEXT NOT NULL,\n      from_public_key TEXT,\n      ciphertext TEXT NOT NULL,\n      nonce TEXT NOT NULL,\n      created_at TIMESTAMP DEFAULT NOW()\n    );\n  `);\n  console.log('Tablas verificadas/creadas en la base de datos');",
  "  await pool.query(`\n    CREATE TABLE IF NOT EXISTS pending_messages (\n      id SERIAL PRIMARY KEY,\n      to_username TEXT NOT NULL,\n      from_username TEXT NOT NULL,\n      from_public_key TEXT,\n      ciphertext TEXT NOT NULL,\n      nonce TEXT NOT NULL,\n      created_at TIMESTAMP DEFAULT NOW()\n    );\n  `);\n  await pool.query(`ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS counter INTEGER;`);\n  console.log('Tablas verificadas/creadas en la base de datos');",
  "agregar columna counter a pending_messages"
);

// 3. reenviar counter al entregar pendientes al iniciar sesion
src = applyReplace(
  src,
  "          for (const row of pendingResult.rows) {\n            socket.send(JSON.stringify({\n              type: 'direct-message',\n              from: row.from_username,\n              fromPublicKey: row.from_public_key,\n              ciphertext: row.ciphertext,\n              nonce: row.nonce,\n            }));\n          }",
  "          for (const row of pendingResult.rows) {\n            socket.send(JSON.stringify({\n              type: 'direct-message',\n              from: row.from_username,\n              fromPublicKey: row.from_public_key,\n              ciphertext: row.ciphertext,\n              nonce: row.nonce,\n              counter: row.counter,\n            }));\n          }",
  "reenviar counter al entregar pendientes al iniciar sesion"
);

// 4. incluir counter al entregar en vivo y al guardar como pendiente
src = applyReplace(
  src,
  "        const payload = {\n          type: 'direct-message',\n          from: myUsername,\n          fromPublicKey,\n          ciphertext: parsed.ciphertext,\n          nonce: parsed.nonce,\n        };\n\n        const recipient = onlineUsers.get(parsed.to);\n        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {\n          recipient.socket.send(JSON.stringify(payload));\n          console.log(`Mensaje entregado: ${myUsername} -> ${parsed.to}`);\n        } else {\n          await pool.query(\n            'INSERT INTO pending_messages (to_username, from_username, from_public_key, ciphertext, nonce) VALUES ($1, $2, $3, $4, $5)',\n            [parsed.to, myUsername, fromPublicKey, parsed.ciphertext, parsed.nonce]\n          );",
  "        const payload = {\n          type: 'direct-message',\n          from: myUsername,\n          fromPublicKey,\n          ciphertext: parsed.ciphertext,\n          nonce: parsed.nonce,\n          counter: parsed.counter,\n        };\n\n        const recipient = onlineUsers.get(parsed.to);\n        if (recipient && recipient.socket.readyState === recipient.socket.OPEN) {\n          recipient.socket.send(JSON.stringify(payload));\n          console.log(`Mensaje entregado: ${myUsername} -> ${parsed.to}`);\n        } else {\n          await pool.query(\n            'INSERT INTO pending_messages (to_username, from_username, from_public_key, ciphertext, nonce, counter) VALUES ($1, $2, $3, $4, $5, $6)',\n            [parsed.to, myUsername, fromPublicKey, parsed.ciphertext, parsed.nonce, parsed.counter]\n          );",
  "incluir counter al entregar en vivo y al guardar como pendiente"
);

// 5. escuchar en el puerto con el servidor HTTP (en vez de que lo haga el WebSocketServer solo)
src = applyReplace(
  src,
  "initDatabase()\n  .then(() => {\n    console.log(`Servidor de chat corriendo en el puerto ${PORT}`);\n  })",
  "initDatabase()\n  .then(() => {\n    httpServer.listen(PORT, () => {\n      console.log(`Servidor de chat corriendo en el puerto ${PORT}`);\n    });\n  })",
  "escuchar en el puerto con el servidor HTTP (en vez de que lo haga el WebSocketServer solo)"
);

if (hadCRLF) src = src.split('\n').join('\r\n');
fs.writeFileSync(path, src, 'utf8');
console.log('Listo: contador de mensajes reenviado por el servidor y health-check HTTP agregado en', path);
