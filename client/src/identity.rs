use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct LocalIdentity {
    pub pubkey: [u8; 32],
    encrypted_privkey: Vec<u8>,
    nonce: [u8; 12],
    pub salt: [u8; 16],
    pub diddy_id: Option<u128>,
    pub server_signature: Option<Vec<u8>>,

    #[serde(skip)]
    signing_key: Option<SigningKey>,
}

impl LocalIdentity {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        Self {
            pubkey: pk,
            encrypted_privkey: vec![],
            nonce: [0u8; 12],
            salt,
            diddy_id: None,
            server_signature: None,
            signing_key: Some(sk),
        }
    }

    fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .expect("argon2 failed");
        key
    }

    pub fn lock(&mut self, password: &str) {
        let sk = self.signing_key.take().expect("already locked");
        let privkey = sk.to_bytes();
        let key = Self::derive_key(password, &self.salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, privkey.as_slice()).unwrap();
        self.encrypted_privkey = ct;
        self.nonce = nonce.as_slice().try_into().unwrap();
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::derive_key(password, &self.salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&self.nonce);
        let pt = cipher
            .decrypt(nonce, self.encrypted_privkey.as_ref())
            .map_err(|_| "wrong password")?;
        let privkey: [u8; 32] = pt.try_into().unwrap();
        self.signing_key = Some(SigningKey::from_bytes(&privkey));
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.signing_key.is_some()
    }

    #[allow(dead_code)]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key
            .as_ref()
            .map(|sk| sk.verifying_key().to_bytes())
            .unwrap_or(self.pubkey)
    }

    pub fn pwd_hash(&self, password: &str) -> [u8; 32] {
        Self::derive_key(password, &self.salt)
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key
            .as_ref()
            .expect("not unlocked")
            .sign(msg)
            .to_bytes()
    }

    pub fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let data = bincode::serialize(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        match std::fs::read(path) {
            Ok(data) => {
                let mut id: Self = bincode::deserialize(&data)?;
                id.signing_key = None;
                Ok(Some(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
