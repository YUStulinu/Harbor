//! The local image store.
//!
//! ```text
//! <root>/blobs/sha256/<hex>     every blob (manifests, configs, compressed layers), by digest
//! <root>/layers/<hex>/fs/       a layer unpacked for overlayfs (whiteouts converted)
//! <root>/refs.json              image name -> manifest digest
//! ```
//! Blobs are written to a temporary file, checked against their digest and renamed into place,
//! so the store never holds a blob whose content does not match its name.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::manifest::{ImageConfig, Manifest};
use crate::unpack;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn digest_of(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// "sha256:<64 hex>" -> "<hex>", or an error for anything else (a digest also names a file).
pub fn digest_hex(digest: &str) -> io::Result<&str> {
    match digest.strip_prefix("sha256:") {
        Some(h)
            if h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
        {
            Ok(h)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported digest {digest}"),
        )),
    }
}

pub struct Store {
    root: PathBuf,
}

/// What the runtime needs to run an image (`harbor-registry inspect --json`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ImageInfo {
    pub name: String,
    pub digest: String,
    pub config: ImageConfig,
    /// Unpacked layer directories, bottom layer first.
    pub layers: Vec<PathBuf>,
    pub size: u64,
}

impl Store {
    pub fn open(root: &Path) -> io::Result<Store> {
        fs::create_dir_all(root.join("blobs").join("sha256"))?;
        fs::create_dir_all(root.join("layers"))?;
        Ok(Store {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self
            .root
            .join("blobs")
            .join("sha256")
            .join(digest_hex(digest)?))
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).map(|p| p.exists()).unwrap_or(false)
    }

    pub fn read_blob(&self, digest: &str) -> io::Result<Vec<u8>> {
        fs::read(self.blob_path(digest)?)
    }

    /// Streams a blob into the store, checking its digest. Returns its size.
    pub fn put_blob_from(&self, digest: &str, mut r: impl Read) -> io::Result<u64> {
        let dest = self.blob_path(digest)?;
        let tmp = dest.with_extension(format!("tmp{}", std::process::id()));
        let mut f = fs::File::create(&tmp)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut n = 0u64;
        loop {
            let k = r.read(&mut buf)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            f.write_all(&buf[..k])?;
            n += k as u64;
        }
        f.sync_all()?;
        let got = format!("sha256:{}", hex::encode(h.finalize()));
        if got != digest {
            let _ = fs::remove_file(&tmp);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("digest mismatch: expected {digest}, got {got}"),
            ));
        }
        fs::rename(&tmp, &dest)?;
        Ok(n)
    }

    pub fn put_blob(&self, data: &[u8]) -> io::Result<String> {
        let d = digest_of(data);
        if !self.has_blob(&d) {
            self.put_blob_from(&d, data)?;
        }
        Ok(d)
    }

    fn refs_path(&self) -> PathBuf {
        self.root.join("refs.json")
    }

    pub fn refs(&self) -> BTreeMap<String, String> {
        fs::read_to_string(self.refs_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn set_ref(&self, name: &str, digest: &str) -> io::Result<()> {
        let mut refs = self.refs();
        refs.insert(name.to_string(), digest.to_string());
        let tmp = self
            .root
            .join(format!("refs.json.tmp{}", std::process::id()));
        fs::write(&tmp, serde_json::to_vec_pretty(&refs)?)?;
        fs::rename(tmp, self.refs_path())
    }

    pub fn remove_ref(&self, name: &str) -> io::Result<bool> {
        let mut refs = self.refs();
        let had = refs.remove(name).is_some();
        let tmp = self
            .root
            .join(format!("refs.json.tmp{}", std::process::id()));
        fs::write(&tmp, serde_json::to_vec_pretty(&refs)?)?;
        fs::rename(tmp, self.refs_path())?;
        Ok(had)
    }

    /// Finds an image by its canonical name, by a short name that parses to it, or by digest.
    pub fn resolve(&self, name: &str) -> Option<(String, String)> {
        let refs = self.refs();
        if let Some(d) = refs.get(name) {
            return Some((name.to_string(), d.clone()));
        }
        if let Ok(r) = crate::reference::Reference::parse(name) {
            let canon = r.to_string();
            if let Some(d) = refs.get(&canon) {
                return Some((canon, d.clone()));
            }
            if let Some(d) = &r.digest
                && self.has_blob(d)
            {
                return Some((canon, d.clone()));
            }
        }
        refs.iter()
            .find(|(_, d)| d.as_str() == name)
            .map(|(n, d)| (n.clone(), d.clone()))
    }

    pub fn manifest(&self, digest: &str) -> io::Result<Manifest> {
        serde_json::from_slice(&self.read_blob(digest)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn layer_dir(&self, layer_digest: &str) -> io::Result<PathBuf> {
        Ok(self
            .root
            .join("layers")
            .join(digest_hex(layer_digest)?)
            .join("fs"))
    }

    /// Unpacks a stored layer blob for overlayfs (once; a marker file records completion).
    pub fn unpack_layer(&self, layer_digest: &str, media_type: &str) -> io::Result<PathBuf> {
        let dir = self.layer_dir(layer_digest)?;
        let done = dir.parent().unwrap().join("done");
        if done.exists() {
            return Ok(dir);
        }
        if dir.exists() {
            fs::remove_dir_all(&dir)?; // an earlier attempt was interrupted
        }
        fs::create_dir_all(&dir)?;
        let f = fs::File::open(self.blob_path(layer_digest)?)?;
        unpack::unpack_layer(f, media_type, &dir)?;
        fs::write(done, b"")?;
        Ok(dir)
    }

    pub fn info(&self, name: &str) -> io::Result<ImageInfo> {
        let (name, digest) = self.resolve(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no image {name} (pull it first)"),
            )
        })?;
        let m = self.manifest(&digest)?;
        let cfg: crate::manifest::ConfigFile =
            serde_json::from_slice(&self.read_blob(&m.config.digest)?)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut layers = Vec::new();
        for l in &m.layers {
            layers.push(self.unpack_layer(&l.digest, &l.media_type)?);
        }
        Ok(ImageInfo {
            name,
            digest,
            config: cfg.config.unwrap_or_default(),
            layers,
            size: m.layers.iter().map(|l| l.size).sum(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_are_checked_against_their_digest() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let d = s.put_blob(b"hello").unwrap();
        assert_eq!(
            d,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(s.read_blob(&d).unwrap(), b"hello");
        let wrong = format!("sha256:{}", "0".repeat(64));
        assert!(s.put_blob_from(&wrong, &b"hello"[..]).is_err());
        assert!(!s.has_blob(&wrong));
        assert!(digest_hex("sha256:../../etc").is_err());
        assert!(digest_hex("md5:abc").is_err());
    }

    #[test]
    fn refs_round_trip_and_resolve_short_names() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let d = s.put_blob(b"{}").unwrap();
        s.set_ref("docker.io/library/alpine:3.20", &d).unwrap();
        assert_eq!(s.resolve("alpine:3.20").unwrap().1, d);
        assert_eq!(
            s.resolve("docker.io/library/alpine:3.20").unwrap().0,
            "docker.io/library/alpine:3.20"
        );
        assert_eq!(s.resolve(&d).unwrap().0, "docker.io/library/alpine:3.20");
        assert!(s.resolve("alpine:3.19").is_none());
        assert!(s.remove_ref("docker.io/library/alpine:3.20").unwrap());
        assert!(s.resolve("alpine:3.20").is_none());
    }
}
