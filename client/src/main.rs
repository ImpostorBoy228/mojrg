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

const SERVER_ADDR: &str = "127.0.0.1:2888";

fn parse_args() -> (String, String, Vec<String>) {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("listen") | Some("connect") => {
            ("identity.bin".into(), args[1].clone(), args[2..].to_vec())
        }
        Some(_) if args.len() >= 3 => {
            (args[1].clone(), args[2].clone(), args[3..].to_vec())
        }
        _ => {
            ("identity.bin".into(), String::new(), vec![])
        }
    }
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

async fn load_and_unlock(identity_path: &str) -> Result<Option<LocalIdentity>, Box<dyn std::error::Error>> {
    if let Some(mut id) = LocalIdentity::load(identity_path)? {
        let pw = read_password("password: ")?;
        id.unlock(&pw).map_err(|_| "wrong password, you a opp")?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if SERVER_PUBKEY == [0u8; 32] {
        eprintln!("FIXME: hardcode SERVER_PUBKEY in main.rs");
        return Ok(());
    }

    let (identity_path, cmd, rest) = parse_args();

    let identity = match load_and_unlock(&identity_path).await? {
        Some(id) => id,
        None => register_with_server(&identity_path).await?,
    };

    let db = MessageDb::open("mojrg_client.db")?;

    match cmd.as_str() {
        "listen" => {
            let port: u16 = rest.first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7331);
            p2p::listen(identity, port, db).await?;
        }
        "connect" => {
            let addr = rest.first().expect("usage: connect <addr>");
            p2p::connect(identity, addr, db).await?;
        }
        _ => {
            eprintln!("usage: {} [identity_file] listen <port> | connect <addr>", std::env::args().next().unwrap_or_default());
        }
    }

    Ok(())
}
