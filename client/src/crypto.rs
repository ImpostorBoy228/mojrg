use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, EphemeralSecret};

pub const SERVER_PUBKEY: [u8; 32] = [
    0x32, 0xb0, 0xdb, 0x8e, 0x30, 0xdc, 0xa2, 0xc4,
    0x07, 0x25, 0xfb, 0xfb, 0xc4, 0x66, 0x9d, 0x4c,
    0xe0, 0x70, 0xaa, 0x25, 0xf9, 0x6f, 0x76, 0x56,
    0xab, 0x2a, 0x4c, 0x53, 0x79, 0x5f, 0xf6, 0x7f,
];

pub fn compute_diddy_id(pubkey: &[u8; 32]) -> u128 {
    u128::from_le_bytes(blake3::hash(pubkey).as_bytes()[..16].try_into().unwrap())
}

pub fn verify_diddy(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    server_pubkey: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let server_vk = VerifyingKey::from_bytes(server_pubkey)?;
    let sig = Signature::from_bytes(signature);
    server_vk.verify_strict(pubkey, &sig)?;
    Ok(())
}

pub fn derive_shared_secret(my_secret: EphemeralSecret, their_pub: &PublicKey) -> [u8; 32] {
    my_secret.diffie_hellman(their_pub).to_bytes()
}

pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .expect("encrypt_message failed");
    (nonce.as_slice().try_into().unwrap(), ct)
}

pub fn decrypt_message(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))?;
    Ok(pt)
}

#[allow(dead_code)]
pub fn sign_message(signing_key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    signing_key.sign(msg).to_bytes()
}

pub fn verify_message_sig(
    pubkey: &[u8; 32],
    msg: &[u8],
    signature: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    let vk = VerifyingKey::from_bytes(pubkey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(msg, &sig)?;
    Ok(())
}
