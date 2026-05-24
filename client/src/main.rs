use std::fs;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{Read, Write};
use serde_json;

#[tokio::main]  
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connection
    let mut stream = TcpStream::connect("127.0.0.1:2888").await?;
    
    // sending deadbeef
    let magic: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    stream.write_all(&magic).await?;
    stream.flush().await?;
    
    println!("DEADBEEF sent");
    
    // read response
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
    println!("Diddy response: {}", response);
    
    // json parse
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
        if let (Some(id), Some(password)) = (json.get("id"), json.get("password")) {
            fs::write("cache_colhoz.json", response)?;
        }
    }
    
    Ok(())
}