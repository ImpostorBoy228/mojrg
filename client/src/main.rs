use std::fs;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde_json;
use ed25519_dalek::SigningKey;
use blake3;

fn validate_password(password: &str, salt: &[u8], expected_pubkey: &[u8; 32]) -> bool {
    let seed = derive_seed_from_password(password, salt);
    let signing_key = SigningKey::from_bytes(&seed);
    let derived_pubkey = signing_key.verifying_key().to_bytes();
    
    derived_pubkey == *expected_pubkey
}

fn derive_seed_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hasher = blake3::Hasher::new()
        .update(password.as_bytes())
        .update(salt)
        .finalize();
    key.copy_from_slice(hasher.as_bytes());
    key
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
        if let (Some(_id), Some(pubkey), Some(password), Some(salt)) = (json.get("id"), json.get("pubkey"), json.get("password"), json.get("salt")) {
            // cache identity without the password
            let cache = serde_json::json!({
                "id": _id,
                "pubkey": pubkey,
                "salt": salt,
            });
            fs::write("cache_colhoz.json", cache.to_string())?;
            if let Some(pw_str) = password.as_str() {
                // validate password client-side without storing it
                if let Some(salt_str) = salt.as_str().and_then(|s| hex::decode(s).ok()).filter(|v| v.len() == 16) {
                    let mut salt_arr = [0u8; 16];
                    salt_arr.copy_from_slice(&salt_str);
                    if let Some(pk_bytes) = pubkey.as_str().and_then(|s| hex::decode(s).ok()).filter(|v| v.len() == 32) {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&pk_bytes);
                        println!("password validation: {}", validate_password(pw_str, &salt_arr, &arr));
                    }
                }
            }
        }
    }
    
    Ok(())
}
