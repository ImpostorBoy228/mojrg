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
}

impl MessageDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn insert(&self, msg: &StoredMessage) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("{}:{}:{}", msg.peer_id, msg.timestamp, msg.id);
        let value = bincode::serialize(msg)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn messages_since(
        &self,
        peer_id: u128,
        since_ts: u64,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let prefix = format!("{peer_id}:");
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

    #[allow(dead_code)]
    pub fn latest_timestamp(&self, peer_id: u128) -> Result<u64, Box<dyn std::error::Error>> {
        let prefix = format!("{peer_id}:");
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
}
