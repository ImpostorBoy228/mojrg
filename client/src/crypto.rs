use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, EphemeralSecret};

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
