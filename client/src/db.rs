use sled::Db;
use std::path::Path;

#[derive(Clone)]
pub struct MessageDb {
    db: Db,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub peer_id: u128,
    pub sender_id: u128,
    pub body: String,
    pub timestamp: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub pending: bool,
}

impl MessageDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn insert(&self, msg: &StoredMessage) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("{}_{}", msg.peer_id, msg.id);
        let value = bincode::serialize(msg)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn get(&self, peer_id: u128, msg_id: &str) -> Result<Option<StoredMessage>, Box<dyn std::error::Error>> {
        let key = format!("{peer_id}_{msg_id}");
        match self.db.get(key.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn messages_since(
        &self,
        peer_id: u128,
        since_ts: u64,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let prefix = format!("{peer_id}_");
        let mut msgs = Vec::new();
        for entry in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = entry?;
            let msg: StoredMessage = bincode::deserialize(&value)?;
            if msg.timestamp > since_ts {
                msgs.push(msg);
            }
        }
        msgs.sort_by_key(|m| m.timestamp);
        Ok(msgs)
    }

    pub fn latest_timestamp(&self, peer_id: u128) -> Result<u64, Box<dyn std::error::Error>> {
        let prefix = format!("{peer_id}_");
        let mut latest = 0u64;
        for entry in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = entry?;
            let msg: StoredMessage = bincode::deserialize(&value)?;
            if msg.timestamp > latest {
                latest = msg.timestamp;
            }
        }
        Ok(latest)
    }

    #[allow(dead_code)]
    pub fn pending_for(
        &self,
        peer_id: u128,
        sender_id: u128,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let prefix = format!("{peer_id}_");
        let mut msgs = Vec::new();
        for entry in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = entry?;
            let msg: StoredMessage = bincode::deserialize(&value)?;
            if msg.pending && msg.sender_id == sender_id {
                msgs.push(msg);
            }
        }
        msgs.sort_by_key(|m| m.timestamp);
        Ok(msgs)
    }

    pub fn mark_not_pending(&self, peer_id: u128, msg_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("{peer_id}_{msg_id}");
        if let Some(value) = self.db.get(key.as_bytes())? {
            let mut msg: StoredMessage = bincode::deserialize(&value)?;
            msg.pending = false;
            self.db.insert(key.as_bytes(), bincode::serialize(&msg)?)?;
            self.db.flush()?;
        }
        Ok(())
    }
}
