mod identity;
mod protocol;

use ed25519_dalek::{Signature, VerifyingKey};
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
// hardcoded trust root — server pubkey from ur one and only sigma server
const SERVER_PUBKEY: [u8; 32] = [
    0xe9, 0x47, 0x10, 0x55, 0xaf, 0x1f, 0x43, 0xe4,
    0x45, 0x26, 0x47, 0xf1, 0x91, 0xc8, 0xda, 0x85,
    0xc7, 0xe4, 0xa2, 0x8a, 0x9f, 0xf9, 0xe6, 0x40,
    0x3a, 0x3c, 0x94, 0x7a, 0x75, 0xf3, 0xe1, 0x57,
];
const IDENTITY_FILE: &str = "identity.bin";

#[allow(dead_code)]
fn verify_diddy(diddy_pubkey: &[u8; 32], sig: &[u8; 64]) -> Result<(), Box<dyn std::error::Error>> {
    let server_vk = VerifyingKey::from_bytes(&SERVER_PUBKEY)?;
    let signature = Signature::from_bytes(sig);
    server_vk.verify_strict(diddy_pubkey, &signature)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if SERVER_PUBKEY == [0u8; 32] {
        eprintln!("FIXME: hardcode SERVER_PUBKEY in main.rs");
        return Ok(());
    }

    let mut stream = TcpStream::connect(SERVER_ADDR).await?;

    if let Some(mut id) = LocalIdentity::load(IDENTITY_FILE)? {
        let pw = read_password("password: ")?;
        id.unlock(&pw).map_err(|_| "wrong password, you a opp")?;

        if id.diddy_id.is_none() || id.server_signature.is_none() {
            eprintln!("identity corrupted, delete {IDENTITY_FILE} and regen");
            return Ok(());
        }

        let diddy_id = id.diddy_id.unwrap();

        send_message(
            &mut stream,
            &ClientMessage::LoginRequest { diddy_id },
        )
        .await?;

        let challenge = match recv_message::<ServerMessage>(&mut stream).await? {
            ServerMessage::AuthChallenge { challenge } => challenge,
            ServerMessage::LoginError { reason } => {
                eprintln!("login rejected: {reason}");
                return Ok(());
            }
            other => {
                eprintln!("unexpected server msg: {other:?}");
                return Ok(());
            }
        };

        let sig = id.sign(&challenge);
        send_message(
            &mut stream,
            &ClientMessage::LoginChallengeResponse {
                diddy_id,
                signature: sig,
            },
        )
        .await?;

        match recv_message::<ServerMessage>(&mut stream).await? {
            ServerMessage::LoginSuccess => {
                println!("logged in as {diddy_id}, ur so sigma");
            }
            ServerMessage::LoginError { reason } => {
                eprintln!("login failed: {reason}");
                return Ok(());
            }
            other => {
                eprintln!("unexpected: {other:?}");
                return Ok(());
            }
        }
    } else {
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
                id.save(IDENTITY_FILE)?;
                println!("registered! diddy_id = {diddy_id}");
                println!("identity saved -> {IDENTITY_FILE}");
            }
            ServerMessage::RegistrationError { reason } => {
                eprintln!("registration failed: {reason}");
                return Ok(());
            }
            other => {
                eprintln!("unexpected: {other:?}");
                return Ok(());
            }
        }
    }

    Ok(())
}
