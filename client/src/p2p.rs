use crate::crypto::{self, SERVER_PUBKEY};
use crate::db::MessageDb;
use crate::identity::LocalIdentity;
use crate::protocol::*;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub async fn listen(
    identity: LocalIdentity,
    port: u16,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    println!("p2p listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("p2p connect from {peer}");
        let id = identity.clone();
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(id, stream, db).await {
                eprintln!("p2p error from {peer}: {e}");
            }
        });
    }
}

pub async fn connect(
    identity: LocalIdentity,
    addr: &str,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(addr).await?;
    println!("connected to {addr}");
    handle_outgoing(identity, stream, db).await
}

async fn handle_incoming(
    identity: LocalIdentity,
    mut stream: TcpStream,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = read_packet(&mut stream).await?;
    let init = match packet {
        Packet::HandshakeInit {
            diddy_id,
            identity_pubkey,
            server_signature,
            encryption_pubkey,
        } => (diddy_id, identity_pubkey, server_signature, encryption_pubkey),
        _ => return Err("expected HandshakeInit".into()),
    };
    let (peer_diddy_id, peer_pubkey, peer_sig, peer_enc_pubkey) = init;

    if crypto::compute_diddy_id(&peer_pubkey) != peer_diddy_id {
        return Err("peer diddy_id mismatch".into());
    }
    crypto::verify_diddy(&peer_pubkey, &peer_sig[..64].try_into()?, &SERVER_PUBKEY)?;

    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    let resp_enc_secret = EphemeralSecret::random_from_rng(OsRng);
    let resp_enc_pubkey = PublicKey::from(&resp_enc_secret);

    let diddy_id = identity.diddy_id.expect("identity missing diddy_id");
    let identity_pubkey = identity.pubkey;
    let server_signature = identity
        .server_signature
        .as_ref()
        .expect("identity missing server_signature")
        .clone();

    write_packet(
        &mut stream,
        &Packet::Challenge {
            challenge,
            diddy_id,
            identity_pubkey,
            server_signature,
            encryption_pubkey: resp_enc_pubkey.to_bytes(),
        },
    )
    .await?;

    let packet = read_packet(&mut stream).await?;
    let sig = match packet {
        Packet::ChallengeResponse { signature } => signature,
        _ => return Err("expected ChallengeResponse".into()),
    };

    let peer_vk = ed25519_dalek::VerifyingKey::from_bytes(&peer_pubkey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    peer_vk.verify_strict(&challenge, &sig)?;

    let shared =
        crypto::derive_shared_secret(resp_enc_secret, &PublicKey::from(peer_enc_pubkey));

    println!("peer authenticated! diddy_id={peer_diddy_id}");
    messaging_loop(stream, shared, identity, peer_pubkey, peer_diddy_id, db).await
}

async fn handle_outgoing(
    identity: LocalIdentity,
    mut stream: TcpStream,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let init_enc_secret = EphemeralSecret::random_from_rng(OsRng);
    let init_enc_pubkey = PublicKey::from(&init_enc_secret);

    let diddy_id = identity.diddy_id.expect("identity missing diddy_id");
    let identity_pubkey = identity.pubkey;
    let server_signature = identity
        .server_signature
        .as_ref()
        .expect("identity missing server_signature")
        .clone();

    write_packet(
        &mut stream,
        &Packet::HandshakeInit {
            diddy_id,
            identity_pubkey,
            server_signature,
            encryption_pubkey: init_enc_pubkey.to_bytes(),
        },
    )
    .await?;

    let packet = read_packet(&mut stream).await?;
    let (challenge, peer_diddy_id, peer_pubkey, peer_sig, peer_enc_pubkey) = match packet {
        Packet::Challenge {
            challenge,
            diddy_id,
            identity_pubkey,
            server_signature,
            encryption_pubkey,
        } => (
            challenge,
            diddy_id,
            identity_pubkey,
            server_signature,
            encryption_pubkey,
        ),
        _ => return Err("expected Challenge".into()),
    };

    if crypto::compute_diddy_id(&peer_pubkey) != peer_diddy_id {
        return Err("peer diddy_id mismatch".into());
    }
    crypto::verify_diddy(&peer_pubkey, &peer_sig[..64].try_into()?, &SERVER_PUBKEY)?;

    let sig = identity.sign(&challenge);

    write_packet(
        &mut stream,
        &Packet::ChallengeResponse { signature: sig },
    )
    .await?;

    let shared =
        crypto::derive_shared_secret(init_enc_secret, &PublicKey::from(peer_enc_pubkey));

    println!("peer authenticated! diddy_id={peer_diddy_id}");
    messaging_loop(stream, shared, identity, peer_pubkey, peer_diddy_id, db).await
}

fn display_message(sender_id: u128, my_id: u128, body: &str) {
    let who = if sender_id == my_id {
        "you".to_string()
    } else {
        sender_id.to_string()
    };
    println!("{who}:\n{body}");
}

fn stored_from_chat(
    chat: &ChatMessage,
    peer_diddy_id: u128,
    body: &str,
    pending: bool,
) -> crate::db::StoredMessage {
    crate::db::StoredMessage {
        id: chat.id.to_string(),
        peer_id: peer_diddy_id,
        sender_id: chat.from,
        body: body.to_string(),
        timestamp: chat.timestamp,
        nonce: chat.nonce.to_vec(),
        ciphertext: chat.ciphertext.clone(),
        signature: chat.signature.to_vec(),
        pending,
    }
}

fn verify_chat(chat: &ChatMessage, pubkey: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut v = chat.clone();
    v.signature = [0u8; 64];
    let bytes = bincode::serialize(&v)?;
    crypto::verify_message_sig(pubkey, &bytes, &chat.signature)?;
    Ok(())
}

fn decrypt_body(chat: &ChatMessage, key: &[u8; 32]) -> anyhow::Result<String> {
    let pt = crypto::decrypt_message(key, &chat.nonce, &chat.ciphertext)?;
    Ok(String::from_utf8_lossy(&pt).to_string())
}

fn chat_from_stored(
    m: &crate::db::StoredMessage,
) -> Result<ChatMessage, Box<dyn std::error::Error>> {
    let id: Uuid = m.id.parse()?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&m.nonce);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&m.signature);
    Ok(ChatMessage {
        id,
        from: m.sender_id,
        to: m.peer_id,
        timestamp: m.timestamp,
        nonce,
        ciphertext: m.ciphertext.clone(),
        signature: sig,
    })
}

async fn do_sync(
    stream: &mut TcpStream,
    db: &MessageDb,
    my_id: u128,
    peer_id: u128,
    peer_pubkey: &[u8; 32],
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let my_ts = db.latest_timestamp(peer_id)?;
    write_packet(stream, &Packet::SyncRequest(my_ts)).await?;

    let packet = read_packet(stream).await?;
    match packet {
        Packet::SyncRequest(peer_ts) => {
            let missed = db.messages_since(peer_id, peer_ts)?;
            let mut chats = Vec::new();
            for m in &missed {
                if m.sender_id != my_id || m.nonce.len() != 12 || m.signature.len() != 64 {
                    continue;
                }
                chats.push(chat_from_stored(m)?);
            }
            write_packet(stream, &Packet::SyncGive(chats)).await?;
        }
        _ => return Err("expected SyncRequest".into()),
    }

    let packet = read_packet(stream).await?;
    match packet {
        Packet::SyncGive(msgs) => {
            for chat in &msgs {
                if db.get(peer_id, &chat.id.to_string())?.is_some() {
                    continue;
                }
                if verify_chat(chat, peer_pubkey).is_err() {
                    continue;
                }
                let body = match decrypt_body(chat, key) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                db.insert(&stored_from_chat(chat, peer_id, &body, false))?;
                display_message(chat.from, my_id, &body);
            }
        }
        _ => return Err("expected SyncGive".into()),
    }

    Ok(())
}

async fn messaging_loop(
    mut stream: TcpStream,
    key: [u8; 32],
    identity: LocalIdentity,
    peer_pubkey: [u8; 32],
    peer_diddy_id: u128,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let my_diddy_id = identity.diddy_id.expect("identity missing diddy_id");

    for msg in db.messages_since(peer_diddy_id, 0)? {
        display_message(msg.sender_id, my_diddy_id, &msg.body);
    }

    do_sync(&mut stream, &db, my_diddy_id, peer_diddy_id, &peer_pubkey, &key).await?;

    let (mut reader, mut writer) = tokio::io::split(stream);

    let recv_db = db.clone();
    let recv = tokio::spawn(async move {
        loop {
            let packet = read_packet(&mut reader)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            match packet {
                Packet::Message(chat) => {
                    if verify_chat(&chat, &peer_pubkey).is_err() {
                        continue;
                    }
                    let body = match decrypt_body(&chat, &key) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    if recv_db
                        .get(peer_diddy_id, &chat.id.to_string())
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .is_none()
                    {
                        recv_db
                            .insert(&stored_from_chat(&chat, peer_diddy_id, &body, false))
                            .map_err(|e| anyhow::anyhow!("db insert: {e}"))?;
                    }
                    display_message(chat.from, my_diddy_id, &body);
                }
                _ => {
                    anyhow::bail!("unexpected packet in messaging loop");
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let send_db = db.clone();
    let send_id = identity.clone();
    let send = tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            let n = std::io::stdin().read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let id = Uuid::new_v4();
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let (nonce, ciphertext) = crypto::encrypt_message(&key, line.as_bytes());

            let mut chat = ChatMessage {
                id,
                from: my_diddy_id,
                to: peer_diddy_id,
                timestamp: ts,
                nonce,
                ciphertext,
                signature: [0u8; 64],
            };

            let msg_bytes = bincode::serialize(&chat)?;
            chat.signature = send_id.sign(&msg_bytes);

            send_db
                .insert(&stored_from_chat(&chat, peer_diddy_id, line, true))
                .map_err(|e| anyhow::anyhow!("db insert: {e}"))?;

            match write_packet(&mut writer, &Packet::Message(chat)).await {
                Ok(()) => {
                    send_db
                        .mark_not_pending(peer_diddy_id, &id.to_string())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    display_message(my_diddy_id, my_diddy_id, line);
                }
                Err(e) => {
                    eprintln!("send failed, queued: {e}");
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        _ = recv => {},
        _ = send => {},
    }

    Ok(())
}
