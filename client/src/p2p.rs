use crate::crypto::{self, SERVER_PUBKEY};
use crate::identity::LocalIdentity;
use crate::protocol::*;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub async fn listen(identity: LocalIdentity, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    println!("p2p listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("p2p connect from {peer}");
        let id = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(id, stream).await {
                eprintln!("p2p error from {peer}: {e}");
            }
        });
    }
}

pub async fn connect(
    identity: LocalIdentity,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(addr).await?;
    println!("connected to {addr}");
    handle_outgoing(identity, stream).await
}

async fn handle_incoming(
    identity: LocalIdentity,
    mut stream: TcpStream,
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
    messaging_loop(stream, shared).await
}

async fn handle_outgoing(
    identity: LocalIdentity,
    mut stream: TcpStream,
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
    messaging_loop(stream, shared).await
}

async fn messaging_loop(
    stream: TcpStream,
    key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = tokio::io::split(stream);

    let recv = tokio::spawn(async move {
        loop {
            let packet = read_packet(&mut reader)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            match packet {
                Packet::Message { nonce, ciphertext } => {
                    let pt = crypto::decrypt_message(&key, &nonce, &ciphertext)?;
                    let msg = String::from_utf8_lossy(&pt);
                    println!("peer: {msg}");
                }
                _ => {
                    anyhow::bail!("unexpected packet in messaging loop");
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

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
            let (nonce, ciphertext) = crypto::encrypt_message(&key, line.as_bytes());
            write_packet(&mut writer, &Packet::Message { nonce, ciphertext })
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
