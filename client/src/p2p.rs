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

async fn messaging_loop(
    stream: TcpStream,
    key: [u8; 32],
    identity: LocalIdentity,
    peer_pubkey: [u8; 32],
    peer_diddy_id: u128,
    db: MessageDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let my_diddy_id = identity.diddy_id.expect("identity missing diddy_id");
    let (mut reader, mut writer) = tokio::io::split(stream);

    for msg in db.messages_since(peer_diddy_id, 0)? {
        let who = if msg.sender_id == my_diddy_id { "you" } else { "peer" };
        println!("[{who} @ {}] {}", msg.timestamp, msg.body);
    }

    let recv_db = db.clone();
    let recv = tokio::spawn(async move {
        loop {
            let packet = read_packet(&mut reader)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            match packet {
                Packet::Message(chat) => {
                    let sig = chat.signature;
                    let mut verify_chat = chat.clone();
                    verify_chat.signature = [0u8; 64];
                    let msg_bytes = bincode::serialize(&verify_chat).map_err(|e| anyhow::anyhow!("{e}"))?;
                    crypto::verify_message_sig(&peer_pubkey, &msg_bytes, &sig)
                        .map_err(|e| anyhow::anyhow!("bad msg sig: {e}"))?;

                    let pt = crypto::decrypt_message(&key, &chat.nonce, &chat.ciphertext)?;
                    let body = String::from_utf8_lossy(&pt).to_string();

                    recv_db.insert(&crate::db::StoredMessage {
                        id: chat.id.to_string(),
                        peer_id: peer_diddy_id,
                        sender_id: chat.from,
                        body: body.clone(),
                        timestamp: chat.timestamp,
                    })
                    .map_err(|e| anyhow::anyhow!("db insert: {e}"))?;

                    println!("received message {}", chat.id);
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

            send_db.insert(&crate::db::StoredMessage {
                id: id.to_string(),
                peer_id: peer_diddy_id,
                sender_id: my_diddy_id,
                body: line.to_string(),
                timestamp: ts,
            })
            .map_err(|e| anyhow::anyhow!("db insert: {e}"))?;

            write_packet(&mut writer, &Packet::Message(chat))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        _ = recv => {},
        _ = send => {},
    }

    Ok(())
}
