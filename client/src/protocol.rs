use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) mod serde_ba {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<const N: usize, S>(data: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(data)
    }

    pub fn deserialize<'de, const N: usize, D>(d: D) -> Result<[u8; N], D::Error>
    where D: Deserializer<'de> {
        struct BigVisitor<const M: usize>;
        impl<'de, const M: usize> de::Visitor<'de> for BigVisitor<M> {
            type Value = [u8; M];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "byte array [{}]", M)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_bytes(BigVisitor::<N>)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    Register {
        pubkey: [u8; 32],
        pwd_hash: [u8; 32],
        salt: [u8; 16],
    },
    LoginRequest {
        diddy_id: u128,
    },
    LoginChallengeResponse {
        diddy_id: u128,
        #[serde(with = "serde_ba")]
        signature: [u8; 64],
    },
    VerifyRequest {
        diddy_id: u128,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMessage {
    RegistrationSuccess {
        diddy_id: u128,
        #[serde(with = "serde_ba")]
        signature: [u8; 64],
    },
    RegistrationError {
        reason: String,
    },
    AuthChallenge {
        challenge: [u8; 32],
    },
    LoginSuccess,
    LoginError {
        reason: String,
    },
    VerifyResponse {
        diddy_id: u128,
        pubkey: [u8; 32],
        #[serde(with = "serde_ba")]
        signature: [u8; 64],
    },
    VerifyError {
        reason: String,
    },
}

pub async fn send_message(
    stream: &mut TcpStream,
    msg: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bincode::serialize(msg)?;
    let len = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv_message<T: for<'a> Deserialize<'a>>(
    stream: &mut TcpStream,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err("message too large".into());
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub id: uuid::Uuid,
    pub from: u128,
    pub to: u128,
    pub timestamp: u64,
    #[serde(with = "serde_ba")]
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_ba")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Packet {
    HandshakeInit {
        diddy_id: u128,
        #[serde(with = "serde_ba")]
        identity_pubkey: [u8; 32],
        server_signature: Vec<u8>,
        #[serde(with = "serde_ba")]
        encryption_pubkey: [u8; 32],
    },
    Challenge {
        challenge: [u8; 32],
        diddy_id: u128,
        #[serde(with = "serde_ba")]
        identity_pubkey: [u8; 32],
        server_signature: Vec<u8>,
        #[serde(with = "serde_ba")]
        encryption_pubkey: [u8; 32],
    },
    ChallengeResponse {
        #[serde(with = "serde_ba")]
        signature: [u8; 64],
    },
    Message(ChatMessage),
}

pub async fn write_packet(
    writer: &mut (impl AsyncWriteExt + Unpin),
    msg: &Packet,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bincode::serialize(msg)?;
    let len = (bytes.len() as u32).to_le_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_packet(
    reader: &mut (impl AsyncReadExt + Unpin),
) -> Result<Packet, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err("message too large".into());
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}
