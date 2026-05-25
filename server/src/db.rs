use std::net::IpAddr;
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DiddyRecord {
    pub id: [u8; 16],
    pub pubkey: [u8; 32],
    pub salt: [u8; 16],
    pub pwd_hash: [u8; 32],
    pub signature: [u8; 64],
    pub created_at: i64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerAnnouncement {
    pub diddy_id: [u8; 16],
    pub ip: Vec<u8>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub last_seen: i64,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS diddys (
                id      BLOB PRIMARY KEY,
                pubkey  BLOB NOT NULL UNIQUE,
                salt    BLOB NOT NULL,
                pwd_hash BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peer_locations (
                diddy_id BLOB PRIMARY KEY,
                ip       BLOB NOT NULL,
                tcp_port INTEGER NOT NULL,
                udp_port INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    pub fn register(&self, rec: &DiddyRecord) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT INTO diddys (id, pubkey, salt, pwd_hash, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rec.id.as_slice(),
                rec.pubkey.as_slice(),
                rec.salt.as_slice(),
                rec.pwd_hash.as_slice(),
                rec.signature.as_slice(),
                rec.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn by_pubkey(&self, pubkey: &[u8; 32]) -> Result<Option<DiddyRecord>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pubkey, salt, pwd_hash, signature, created_at
             FROM diddys WHERE pubkey = ?1",
        )?;
        let mut rows = stmt.query_map(params![pubkey.as_slice()], row_to_record)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn by_id(&self, id: &[u8; 16]) -> Result<Option<DiddyRecord>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pubkey, salt, pwd_hash, signature, created_at
             FROM diddys WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id.as_slice()], row_to_record)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn announce(
        &self,
        diddy_id: &[u8; 16],
        ip: &IpAddr,
        tcp_port: u16,
        udp_port: u16,
        now: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ip_bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO peer_locations (diddy_id, ip, tcp_port, udp_port, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![diddy_id, ip_bytes, tcp_port, udp_port, now],
        )?;
        Ok(())
    }

    pub fn lookup(&self, diddy_id: &[u8; 16]) -> Result<Option<PeerAnnouncement>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT diddy_id, ip, tcp_port, udp_port, last_seen
             FROM peer_locations WHERE diddy_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![diddy_id], row_to_announcement)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn remove_announcement(&self, diddy_id: &[u8; 16]) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "DELETE FROM peer_locations WHERE diddy_id = ?1",
            params![diddy_id],
        )?;
        Ok(())
    }
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<DiddyRecord> {
    fn to_arr<const N: usize>(v: Vec<u8>) -> [u8; N] {
        v.try_into().unwrap_or_else(|_| panic!("bad blob len"))
    }
    Ok(DiddyRecord {
        id: to_arr(row.get::<_, Vec<u8>>(0)?),
        pubkey: to_arr(row.get::<_, Vec<u8>>(1)?),
        salt: to_arr(row.get::<_, Vec<u8>>(2)?),
        pwd_hash: to_arr(row.get::<_, Vec<u8>>(3)?),
        signature: to_arr(row.get::<_, Vec<u8>>(4)?),
        created_at: row.get(5)?,
    })
}

fn row_to_announcement(row: &rusqlite::Row) -> rusqlite::Result<PeerAnnouncement> {
    Ok(PeerAnnouncement {
        diddy_id: row.get::<_, Vec<u8>>(0)?.try_into().unwrap_or_default(),
        ip: row.get(1)?,
        tcp_port: row.get(2)?,
        udp_port: row.get(3)?,
        last_seen: row.get(4)?,
    })
}
