# mojrg — P2P мессенджер с server authority

## Terminology
- клиент = diddy (пользователь)
- сервер = trust root / authority
- identity = ed25519 keypair (не производная от пароля)

## Architecture

```
diddy <──TCP/bincode──> server <──TCP/bincode──> diddy
                                (подписанные identity)
```

Сервер НЕ хранит сообщения. Сервер — только identity provider + auth.

### Server authority
Сервер — единственный trust root. Каждый diddy hardcode'ит `SERVER_PUBKEY`.
Неподписанные identities считаются invalid.

### Что хранит server (SQLite: mojrg.db)
- diddy id (blake3 hash от pubkey → u128)
- pubkey (ed25519)
- salt
- pwd_hash (argon2id)
- server signature (ed25519: Sign(server_sk, diddy_pubkey))
- created_at

Сервер НЕ хранит переписки, сообщения, чаты.

### Что хранит client локально (bincode: identity.bin)
- pubkey
- encrypted_privkey (chacha20poly1305, key = argon2id(password, salt))
- nonce
- salt
- diddy_id
- server_signature

## Registration flow
1. diddy генерирует ed25519 keypair (random, НЕ из пароля)
2. argon2id(password, salt) → key → chacha20poly1305 encrypt(privkey)
3. diddy отправляет на сервер: pubkey + pwd_hash + salt
4. сервер: Sign(server_sk, pubkey) → signature
5. сервер сохраняет в SQLite
6. сервер возвращает: diddy_id + signature

## Login flow (challenge-response)
1. diddy → сервер: LoginRequest { diddy_id }
2. сервер → diddy: AuthChallenge { challenge: [u8; 32] }
3. diddy расшифровывает privkey паролем, подписывает challenge
4. diddy → сервер: LoginChallengeResponse { diddy_id, signature }
5. сервер Verify(pubkey, challenge, signature) → LoginSuccess/Error

## Verify flow (для проверки чужих diddys)
1. diddy → сервер: VerifyRequest { diddy_id }
2. сервер → diddy: VerifyResponse { diddy_id, pubkey, signature }
3. diddy Verify(SERVER_PUBKEY, pubkey, signature) → valid/invalid

## Crypto stack

| Purpose | Algorithm |
|---------|-----------|
| Identity / signatures | ed25519 |
| Key exchange | x25519 (future) |
| Message encryption | chacha20poly1305 (future) |
| Password KDF | argon2id |
| Local key encryption | argon2id → chacha20poly1305 |
| Wire format | bincode (binary, length-prefixed) |
| Transport | TCP (QUIC/quinn future) |

## Project structure

```
mojrg/
├── client/           # diddy client
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs       # CLI, registration/login flow
│       ├── protocol.rs   # message types + framing
│       └── identity.rs   # LocalIdentity: gen, lock, unlock, sign
├── server/           # authority server
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs       # TCP listener, request handlers
│       ├── protocol.rs   # message types + framing
│       └── db.rs         # SQLite CRUD
├── tauri/            # future gui wrapper
└── INIT.md           # this file
```

## Running

```bash
# terminal 1 — server
cd server && RUST_LOG=info cargo run
# выведет: server pubkey: <hex>
# скопировать hex в client/src/main.rs → SERVER_PUBKEY

# terminal 2 — client
cd client && cargo run
# первый запуск → регистрация
# следующие → логин
```

## Future plans

- face-to-face chats (E2E encrypted)
- group chats
- distributed sync via consensus
- offline message merge / conflict resolution
- cache synchronization
- peer discovery (DHT-based)

## Code style

- Комментарии лаконичные, без воды
- brainrot gen alpha slang допускается в логах и сообщениях
