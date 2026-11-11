//! A registry client (Docker Registry HTTP API v2 / OCI distribution spec): pull an image into
//! the store, push one from the store to another registry.
//!
//! Authentication is the token flow public registries use: an anonymous request gets
//! `401` with `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`; a GET on the realm
//! with those parameters returns a token for the next requests.

use std::collections::HashMap;
use std::io::{self, Read};
use std::time::Duration;

use crate::manifest::{self, Index, Manifest};
use crate::reference::Reference;
use crate::store::{Store, digest_of};

pub struct Client {
    agent: ureq::Agent,
    tokens: HashMap<String, String>, // scope -> token
    pub log: bool,
}

#[derive(Debug, Default)]
pub struct PullReport {
    pub name: String,
    pub digest: String,
    pub layers: usize,
    pub downloaded_bytes: u64,
    pub reused_layers: usize,
}

fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Parses `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="..."`.
pub fn parse_challenge(h: &str) -> Option<HashMap<String, String>> {
    let rest = h
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| h.trim().strip_prefix("bearer "))?;
    let mut out = HashMap::new();
    let mut s = rest;
    while !s.is_empty() {
        let (k, v) = s.split_once('=')?;
        let k = k.trim().trim_start_matches(',').trim().to_string();
        let v = v.trim_start();
        let (val, after) = if let Some(q) = v.strip_prefix('"') {
            let end = q.find('"')?;
            (q[..end].to_string(), &q[end + 1..])
        } else {
            let end = v.find(',').unwrap_or(v.len());
            (v[..end].to_string(), &v[end..])
        };
        out.insert(k, val);
        s = after.trim_start_matches(',').trim_start();
    }
    Some(out)
}

impl Client {
    pub fn new() -> Client {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
            .timeout_read(Duration::from_secs(120))
            .user_agent("harbor-registry/0.1")
            .build();
        Client {
            agent,
            tokens: HashMap::new(),
            log: false,
        }
    }

    fn token_for(&mut self, challenge: &str) -> io::Result<String> {
        let c = parse_challenge(challenge)
            .ok_or_else(|| err(format!("unsupported auth challenge: {challenge}")))?;
        let realm = c
            .get("realm")
            .ok_or_else(|| err("auth challenge without realm"))?;
        let key = format!(
            "{}|{}",
            c.get("service").cloned().unwrap_or_default(),
            c.get("scope").cloned().unwrap_or_default()
        );
        if let Some(t) = self.tokens.get(&key) {
            return Ok(t.clone());
        }
        let mut req = self.agent.get(realm);
        for k in ["service", "scope"] {
            if let Some(v) = c.get(k) {
                req = req.query(k, v);
            }
        }
        let v: serde_json::Value = req.call().map_err(err)?.into_json()?;
        let t = v
            .get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| err("no token in auth response"))?
            .to_string();
        self.tokens.insert(key, t.clone());
        Ok(t)
    }

    /// A request, retried once with a bearer token if the registry asks for one.
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<ureq::Response> {
        let mut auth: Option<String> = None;
        for _ in 0..2 {
            let mut req = self.agent.request(method, url);
            for (k, v) in headers {
                req = req.set(k, v);
            }
            if let Some(t) = &auth {
                req = req.set("Authorization", &format!("Bearer {t}"));
            }
            let res = match body {
                Some(b) => req.send_bytes(b),
                None => req.call(),
            };
            match res {
                Ok(r) => return Ok(r),
                Err(ureq::Error::Status(401, r)) if auth.is_none() => {
                    let ch = r.header("www-authenticate").unwrap_or("").to_string();
                    auth = Some(self.token_for(&ch)?);
                }
                Err(ureq::Error::Status(code, r)) => {
                    let text = r.into_string().unwrap_or_default();
                    return Err(err(format!(
                        "{method} {url}: HTTP {code}: {}",
                        text.chars().take(300).collect::<String>()
                    )));
                }
                Err(e) => return Err(err(format!("{method} {url}: {e}"))),
            }
        }
        Err(err(format!("{method} {url}: unauthorized")))
    }

    fn get_manifest(&mut self, r: &Reference, reference: &str) -> io::Result<(String, Vec<u8>)> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            r.base_url(),
            r.repository,
            reference
        );
        let accept = manifest::accept_header();
        let res = self.send("GET", &url, &[("Accept", &accept)], None)?;
        let ct = res.content_type().to_string();
        let mut body = Vec::new();
        res.into_reader().take(16 << 20).read_to_end(&mut body)?;
        if reference.starts_with("sha256:") && digest_of(&body) != reference {
            return Err(err(format!("manifest digest mismatch for {reference}")));
        }
        Ok((ct, body))
    }

    /// Pulls `name` (for linux/`arch`) into the store, unpacking its layers. Layers already in
    /// the store are not downloaded again.
    pub fn pull(&mut self, store: &Store, name: &str, arch: &str) -> io::Result<PullReport> {
        let r = Reference::parse(name).map_err(err)?;
        let (ct, mut body) = self.get_manifest(&r, r.reference())?;
        if manifest::is_index(&ct, &body) {
            let idx: Index = serde_json::from_slice(&body).map_err(err)?;
            let d = idx
                .pick(arch)
                .ok_or_else(|| err(format!("{name} has no linux/{arch} image")))?
                .digest
                .clone();
            store.put_blob(&body)?;
            body = self.get_manifest(&r, &d)?.1;
        }
        let m: Manifest = serde_json::from_slice(&body).map_err(err)?;
        let digest = store.put_blob(&body)?;
        let mut rep = PullReport {
            name: r.to_string(),
            digest: digest.clone(),
            layers: m.layers.len(),
            ..Default::default()
        };
        for d in std::iter::once(&m.config).chain(m.layers.iter()) {
            if store.has_blob(&d.digest) {
                rep.reused_layers += (d.digest != m.config.digest) as usize;
                continue;
            }
            let url = format!("{}/v2/{}/blobs/{}", r.base_url(), r.repository, d.digest);
            if self.log {
                eprintln!("  {} ({:.1} MB)", d.digest, d.size as f64 / 1e6);
            }
            let res = self.send("GET", &url, &[], None)?;
            rep.downloaded_bytes += store.put_blob_from(&d.digest, res.into_reader())?;
        }
        for l in &m.layers {
            store.unpack_layer(&l.digest, &l.media_type)?;
        }
        store.set_ref(&r.to_string(), &digest)?;
        if r.tag.is_some() && r.digest.is_some() {
            // Also findable by the tag alone.
            let mut t = r.clone();
            t.digest = None;
            store.set_ref(&t.to_string(), &digest)?;
        }
        Ok(rep)
    }

    /// Pushes a stored image to `target` (blobs first, then the manifest).
    pub fn push(&mut self, store: &Store, local: &str, target: &str) -> io::Result<String> {
        let (_, digest) = store
            .resolve(local)
            .ok_or_else(|| err(format!("no image {local}")))?;
        let m = store.manifest(&digest)?;
        let t = Reference::parse(target).map_err(err)?;
        let base = format!("{}/v2/{}", t.base_url(), t.repository);
        for d in std::iter::once(&m.config).chain(m.layers.iter()) {
            if self
                .send("HEAD", &format!("{base}/blobs/{}", d.digest), &[], None)
                .is_ok()
            {
                continue;
            }
            let res = self.send("POST", &format!("{base}/blobs/uploads/"), &[], Some(b""))?;
            let loc = res
                .header("location")
                .ok_or_else(|| err("upload without Location"))?
                .to_string();
            let loc = if loc.starts_with('/') {
                format!("{}{}", t.base_url(), loc)
            } else {
                loc
            };
            let sep = if loc.contains('?') { '&' } else { '?' };
            let data = store.read_blob(&d.digest)?;
            self.send(
                "PUT",
                &format!("{loc}{sep}digest={}", d.digest),
                &[("Content-Type", "application/octet-stream")],
                Some(&data),
            )?;
        }
        let body = store.read_blob(&digest)?;
        let mt = if m.media_type.is_empty() {
            manifest::OCI_MANIFEST.to_string()
        } else {
            m.media_type.clone()
        };
        self.send(
            "PUT",
            &format!("{base}/manifests/{}", t.reference()),
            &[("Content-Type", &mt)],
            Some(&body),
        )?;
        Ok(digest)
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenges() {
        let c = parse_challenge(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#).unwrap();
        assert_eq!(c["realm"], "https://auth.docker.io/token");
        assert_eq!(c["service"], "registry.docker.io");
        assert_eq!(c["scope"], "repository:library/alpine:pull");
        let c = parse_challenge("Bearer realm=https://x/t,service=s").unwrap();
        assert_eq!(
            (c["realm"].as_str(), c["service"].as_str()),
            ("https://x/t", "s")
        );
        assert!(parse_challenge("Basic realm=\"x\"").is_none());
    }
}
