use std::fs;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Read;
use serde_json;

use ed25519_dalek::{SigningKey, VerifyingKey};

fn validate_password(password: &str, expected_pubkey: &[u8; 32]) -> bool {
    let seed = derive_seed_from_password(password);
    let signing_key = SigningKey::from_bytes(&seed[0..32].try_into().unwrap());
    let derived_pubkey = signing_key.verifying_key().to_bytes();
    
    derived_pubkey == *expected_pubkey
}
fn derive_seed_from_password(password: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(password.as_bytes());
    hasher.update(b"mojrg_p2p_salt_v1");
    
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[0..32]);
    seed
}

#[tokio::main]  
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:2888").await?;
    
    let magic: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    stream.write_all(&magic).await?;
    stream.flush().await?;
    
    println!("DEADBEEF sent");
    
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
    println!("Diddy response: {}", response);
    
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
        if let (Some(id), Some(pubkey), Some(password)) = (json.get("id"), json.get("pubkey"), json.get("password")) {
            fs::write("cache_colhoz.json", response)?;
            if let Some(pw_str) = password.as_str() {
                if let Some(pk_bytes) = pubkey.as_str().and_then(|s| hex::decode(s).ok()).filter(|v| v.len() == 32) {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&pk_bytes);
                    println!("password validation: {}", validate_password(pw_str, &arr));
                }
            }
        }
    }
    
    Ok(())
}
