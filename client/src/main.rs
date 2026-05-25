mod crypto;
mod db;
mod identity;
mod p2p;
mod protocol;

use crate::crypto::SERVER_PUBKEY;
use db::MessageDb;
use identity::LocalIdentity;
use protocol::*;
use std::io::{self, BufRead, Write};
use tokio::net::TcpStream;

fn read_password(prompt: &str) -> io::Result<String> {
    if let Ok(pw) = rpassword::prompt_password(prompt) {
        return Ok(pw.trim().to_string());
    }
    let mut stdout = io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

const SERVER_ADDR: &str = "212.113.99.89:2888";

async fn auth_with_server(identity: &LocalIdentity) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(SERVER_ADDR).await.map_err(|e| e.to_string())?;
    let diddy_id = identity.diddy_id.ok_or("no diddy_id".to_string())?;

    send_message(&mut stream, &ClientMessage::LoginRequest { diddy_id }).await.map_err(|e| e.to_string())?;
    let msg = recv_message::<ServerMessage>(&mut stream).await.map_err(|e| e.to_string())?;
    let challenge = match msg {
        ServerMessage::AuthChallenge { challenge } => challenge,
        ServerMessage::LoginError { reason } => return Err(reason),
        other => return Err(format!("unexpected: {other:?}")),
    };

    let sig = identity.sign(&challenge);
    send_message(&mut stream, &ClientMessage::LoginChallengeResponse { diddy_id, signature: sig }).await.map_err(|e| e.to_string())?;
    let msg = recv_message::<ServerMessage>(&mut stream).await.map_err(|e| e.to_string())?;
    match msg {
        ServerMessage::LoginSuccess => {
            println!("logged in as diddy {diddy_id}");
            Ok(stream)
        }
        ServerMessage::LoginError { reason } => Err(reason),
        other => Err(format!("unexpected: {other:?}")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if SERVER_PUBKEY == [0u8; 32] {
        eprintln!("FIXME: hardcode SERVER_PUBKEY in main.rs");
        return Ok(());
    }

    let identity_path = std::env::args().nth(1).unwrap_or_else(|| "identity.bin".into());

    let identity = match LocalIdentity::load(&identity_path)? {
        Some(mut id) => {
            let pw = read_password("password: ")?;
            id.unlock(&pw).map_err(|_| "wrong password, you a opp")?;
            id
        }
        None => register_with_server(&identity_path).await?,
    };

    let db_path = std::path::Path::new(&identity_path).with_extension("db");
    let db = MessageDb::open(&db_path)?;

    println!("type 'help' for commands");
    print!("> ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    loop {
        line.clear();
        let n = std::io::stdin().read_line(&mut line)?;
        if n == 0 { break; }
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "help" => {
                println!("commands:");
                println!("  listen <port>       start P2P listener");
                println!("  chat <diddy_id>     discover + connect/relay");
                println!("  connect <addr>      direct TCP connect");
                println!("  quit                exit");
            }
            "listen" => {
                let port: u16 = parts.get(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(7331);
                let id2 = identity.clone();
                let dbc2 = db.clone();
                tokio::spawn(async move {
                    if let Err(e) = p2p::listen(id2, port, dbc2).await {
                        eprintln!("listen error: {e}");
                    }
                });
                // announce port to server (separate connection)
                let id2 = identity.clone();
                tokio::spawn(async move {
                    let mut s = match auth_with_server(&id2).await {
                        Ok(s) => s,
                        Err(e) => { eprintln!("announce auth failed: {e}"); return; }
                    };
                    if let Ok(()) = p2p::announce(&mut s, port, port.wrapping_add(1)).await {
                        println!("announced port {port}");
                    }
                    // keep connection alive, read relay messages
                    loop {
                        match recv_message::<ServerMessage>(&mut s).await {
                            Ok(ServerMessage::RelayForward { from_diddy_id, payload }) => {
                                if let Ok(_chat) = bincode::deserialize::<ChatMessage>(&payload) {
                                    println!("\n[msg from {from_diddy_id}]");
                                    print!("> ");
                                    let _ = std::io::stdout().flush();
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                println!("listening on port {port}");
            }
            "chat" => {
                let target: u128 = match parts.get(1).and_then(|s| s.parse().ok()) {
                    Some(id) => id,
                    None => { eprintln!("usage: chat <diddy_id>"); continue; }
                };
                // auth a fresh connection for this chat
                match auth_with_server(&identity).await {
                    Ok(stream) => {
                        if let Err(e) = p2p::chat(identity.clone(), stream, target, db.clone()).await {
                            eprintln!("chat error: {e}");
                        }
                        println!("\n--- chat ended ---");
                    }
                    Err(e) => eprintln!("auth failed: {e}"),
                }
            }
            "connect" => {
                let addr = match parts.get(1) {
                    Some(a) => a.to_string(),
                    None => { eprintln!("usage: connect <addr>"); continue; }
                };
                let id = identity.clone();
                let dbc = db.clone();
                tokio::spawn(async move {
                    if let Err(e) = p2p::connect(id, &addr, dbc).await {
                        eprintln!("connect error: {e}");
                    }
                });
            }
            "quit" => break,
            cmd => eprintln!("unknown: {cmd} (try 'help')"),
        }
        print!("> ");
        let _ = std::io::stdout().flush();
    }

    Ok(())
}

async fn register_with_server(identity_path: &str) -> Result<LocalIdentity, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(SERVER_ADDR).await?;
    let pw = read_password("new password: ")?;

    let mut id = LocalIdentity::generate();
    let pwd_hash = id.pwd_hash(&pw);
    let pubkey = id.pubkey;
    let salt = id.salt;

    id.lock(&pw);

    send_message(
        &mut stream,
        &ClientMessage::Register { pubkey, pwd_hash, salt },
    )
    .await?;

    match recv_message::<ServerMessage>(&mut stream).await? {
        ServerMessage::RegistrationSuccess {
            diddy_id,
            signature,
        } => {
            id.diddy_id = Some(diddy_id);
            id.server_signature = Some(signature.to_vec());
            id.save(identity_path)?;
            println!("registered! diddy_id = {diddy_id}");
            println!("identity saved -> {identity_path}");
            id.unlock(&pw)?;
            Ok(id)
        }
        ServerMessage::RegistrationError { reason } => {
            Err(format!("registration failed: {reason}").into())
        }
        other => Err(format!("unexpected server msg: {other:?}").into()),
    }
}
