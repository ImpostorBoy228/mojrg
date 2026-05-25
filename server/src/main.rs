mod protocol;
mod db;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use db::{Database, DiddyRecord};
use protocol::*;

fn diddy_id(pubkey: &[u8; 32]) -> u128 {
    u128::from_le_bytes(blake3::hash(pubkey).as_bytes()[..16].try_into().unwrap())
}

fn u128_to_bytes(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn load_or_gen_keypair() -> (SigningKey, [u8; 32]) {
    if let Ok(data) = std::fs::read("server_key.bin") {
        if data.len() == 64 {
            let seed: [u8; 32] = data[..32].try_into().unwrap();
            let pk: [u8; 32] = data[32..].try_into().unwrap();
            let sk = SigningKey::from_bytes(&seed);
            return (sk, pk);
        }
    }
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pk = sk.verifying_key().to_bytes();
    let seed: [u8; 32] = sk.to_bytes();
    let mut blob = Vec::with_capacity(64);
    blob.extend_from_slice(&seed);
    blob.extend_from_slice(&pk);
    std::fs::write("server_key.bin", &blob).expect("failed to write server_key.bin");
    info!("fresh server keypair -> {}", hex::encode(pk));
    (sk, pk)
}

type RelayMap = Arc<Mutex<HashMap<u128, UnboundedSender<ServerMessage>>>>;

async fn stun_loop() -> Result<(), Box<dyn std::error::Error>> {
    let sock = tokio::net::UdpSocket::bind(format!("0.0.0.0:{STUN_PORT}")).await?;
    info!("stun listening on 0.0.0.0:{STUN_PORT}");
    let mut buf = [0u8; 64];
    loop {
        let (_n, from) = sock.recv_from(&mut buf).await?;
        let response = format!("{}:{}", from.ip(), from.port());
        let _ = sock.send_to(response.as_bytes(), from).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (server_sk, server_pk) = load_or_gen_keypair();
    info!("server pubkey: {}", hex::encode(server_pk));

    let db = Arc::new(Mutex::new(Database::open("mojrg.db")?));
    let relay: RelayMap = Arc::new(Mutex::new(HashMap::new()));

    // spawn STUN endpoint
    tokio::spawn(async {
        if let Err(e) = stun_loop().await {
            error!("stun error: {e}");
        }
    });

    let listener = TcpListener::bind(format!("0.0.0.0:{PORT}")).await?;
    info!("listening on 0.0.0.0:{PORT}");

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("connect from {peer}");

        let db = Arc::clone(&db);
        let sk = server_sk.clone();
        let relay = Arc::clone(&relay);

        let peer_str = peer.to_string();
        tokio::spawn(async move {
            let did = match handle_conn(stream, &db, &sk, &relay).await {
                Ok(Some(d)) => Some(d),
                Ok(None) => { info!("{peer_str} disconnected (unauthed)"); None }
                Err(e) => {
                    if e.to_string() != "early eof" {
                        warn!("{peer_str} error: {e}");
                    }
                    None
                }
            };
            if let Some(did) = did {
                let did_bytes = u128_to_bytes(did);
                let d = db.lock().await;
                let _ = d.remove_announcement(&did_bytes);
                drop(d);
                let mut r = relay.lock().await;
                r.remove(&did);
                info!("diddy {did} disconnected");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    db: &Mutex<Database>,
    server_sk: &SigningKey,
    relay: &RelayMap,
) -> Result<Option<u128>, Box<dyn std::error::Error>> {
    let peer_addr = stream.peer_addr().ok();
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));

    let mut pending_challenge: Option<[u8; 32]> = None;
    let mut authed_id: Option<u128> = None;

    macro_rules! send {
        ($msg:expr) => {
            send_message(&mut *writer.lock().await, $msg).await?;
        };
    }

    loop {
        let msg: ClientMessage = recv_message(&mut reader).await?;

        match msg {
            ClientMessage::Register { pubkey, pwd_hash, salt } => {
                let exists = { db.lock().await.by_pubkey(&pubkey)?.is_some() };
                if exists {
                    send!(&ServerMessage::RegistrationError {
                        reason: "pubkey already registered".into(),
                    });
                    continue;
                }

                let id = diddy_id(&pubkey);
                let sig: ed25519_dalek::Signature = server_sk.sign(&pubkey);
                let signature: [u8; 64] = sig.to_bytes();

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let rec = DiddyRecord {
                    id: u128_to_bytes(id),
                    pubkey,
                    salt,
                    pwd_hash,
                    signature,
                    created_at: now,
                };

                if let Some(s) = db.lock().await.register(&rec).err().map(|e| e.to_string()) {
                    error!("db insert failed: {s}");
                    send!(&ServerMessage::RegistrationError {
                        reason: "internal error".into(),
                    });
                    continue;
                }

                info!("registered diddy {id}");
                send!(&ServerMessage::RegistrationSuccess {
                    diddy_id: id,
                    signature,
                });
            }

            ClientMessage::LoginRequest { diddy_id } => {
                let exists = {
                    let d = db.lock().await;
                    d.by_id(&u128_to_bytes(diddy_id))?.is_some()
                };
                if !exists {
                    send!(&ServerMessage::LoginError {
                        reason: "unknown diddy_id".into(),
                    });
                    continue;
                }

                let mut challenge = [0u8; 32];
                OsRng.fill_bytes(&mut challenge);
                pending_challenge = Some(challenge);

                send!(&ServerMessage::AuthChallenge { challenge });
            }

            ClientMessage::LoginChallengeResponse { diddy_id, signature } => {
                let challenge = match pending_challenge.take() {
                    Some(c) => c,
                    None => {
                        send!(&ServerMessage::LoginError {
                            reason: "no pending challenge".into(),
                        });
                        continue;
                    }
                };

                let rec = {
                    let d = db.lock().await;
                    d.by_id(&u128_to_bytes(diddy_id))?
                };
                let rec = match rec {
                    Some(r) => r,
                    None => {
                        send!(&ServerMessage::LoginError {
                            reason: "unknown diddy_id".into(),
                        });
                        continue;
                    }
                };

                let vk = VerifyingKey::from_bytes(&rec.pubkey)?;
                let sig = ed25519_dalek::Signature::from_bytes(&signature);

                match vk.verify_strict(&challenge, &sig) {
                    Ok(()) => {
                        send!(&ServerMessage::LoginSuccess);
                        authed_id = Some(diddy_id);
                        info!("diddy {diddy_id} authed");

                        // register relay channel + spawn relay writer task
                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
                        {
                            let mut r = relay.lock().await;
                            r.insert(diddy_id, tx);
                        }
                        let w = writer.clone();
                        tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                let mut w = w.lock().await;
                                if let Err(e) = send_message(&mut *w, &msg).await {
                                    warn!("relay send to {diddy_id} failed: {e}");
                                    break;
                                }
                            }
                        });
                    }
                    Err(_) => {
                        send!(&ServerMessage::LoginError {
                            reason: "bad signature".into(),
                        });
                        warn!("diddy {diddy_id} bad sig");
                    }
                }
            }

            ClientMessage::VerifyRequest { diddy_id } => {
                let rec = {
                    let d = db.lock().await;
                    d.by_id(&u128_to_bytes(diddy_id))?
                };
                match rec {
                    Some(r) => {
                        send!(&ServerMessage::VerifyResponse {
                            diddy_id,
                            pubkey: r.pubkey,
                            signature: r.signature,
                        });
                    }
                    None => {
                        send!(&ServerMessage::VerifyError {
                            reason: "unknown diddy_id".into(),
                        });
                    }
                }
            }

            ClientMessage::Announce { tcp_port, udp_port } => {
                let diddy_id = match authed_id {
                    Some(id) => id,
                    None => {
                        send!(&ServerMessage::LoginError {
                            reason: "announce requires auth".into(),
                        });
                        continue;
                    }
                };
                let ip = peer_addr.map(|a| a.ip()).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                db.lock().await.announce(&u128_to_bytes(diddy_id), &ip, tcp_port, udp_port, now)?;
                info!("diddy {diddy_id} announced at {ip}:{tcp_port}(tcp)/{udp_port}(udp)");
                send!(&ServerMessage::AnnounceAck);
            }

            ClientMessage::QueryPeer { diddy_id: target_id } => {
                let lookup = db.lock().await.lookup(&u128_to_bytes(target_id))?;
                match lookup {
                    Some(ann) => {
                        let ip_bytes = ann.ip;
                        let ip = if ip_bytes.len() == 4 {
                            let mut arr = [0u8; 4];
                            arr.copy_from_slice(&ip_bytes);
                            IpAddr::V4(std::net::Ipv4Addr::from(arr))
                        } else if ip_bytes.len() == 16 {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&ip_bytes);
                            IpAddr::V6(std::net::Ipv6Addr::from(arr))
                        } else {
                            send!(&ServerMessage::PeerNotFound);
                            continue;
                        };
                        let online = relay.lock().await.contains_key(&target_id);
                        send!(&ServerMessage::PeerInfo {
                            diddy_id: target_id,
                            ip,
                            tcp_port: ann.tcp_port,
                            udp_port: ann.udp_port,
                            online,
                        });
                    }
                    None => {
                        send!(&ServerMessage::PeerNotFound);
                    }
                }
            }

            ClientMessage::RelayPacket { to_diddy_id, payload } => {
                let from_id = match authed_id {
                    Some(id) => id,
                    None => {
                        send!(&ServerMessage::LoginError {
                            reason: "relay requires auth".into(),
                        });
                        continue;
                    }
                };
                let r = relay.lock().await;
                if let Some(tx) = r.get(&to_diddy_id) {
                    let _ = tx.send(ServerMessage::RelayForward {
                        from_diddy_id: from_id,
                        payload,
                    });
                }
            }
        }
    }
}
