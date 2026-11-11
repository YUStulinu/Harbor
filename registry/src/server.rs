//! A small registry server over the store: the part of the Docker Registry HTTP API v2 /
//! OCI distribution spec that `docker pull`/`push`-style clients need.
//!
//!   GET  /v2/                                   API check
//!   GET  /v2/_catalog                           repositories
//!   GET  /v2/<name>/tags/list
//!   GET|HEAD /v2/<name>/manifests/<tag|digest>
//!   PUT  /v2/<name>/manifests/<tag>             (blobs must be there first)
//!   GET|HEAD /v2/<name>/blobs/<digest>
//!   POST /v2/<name>/blobs/uploads/              start an upload  -> 202, Location
//!   PATCH /v2/<name>/blobs/uploads/<id>         append a chunk
//!   PUT  /v2/<name>/blobs/uploads/<id>?digest=  finish (with an optional last chunk)
//!
//! Images pushed here are stored as `<host>/<name>:<tag>`. No authentication: it binds to
//! localhost by default and is meant for a single machine.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::manifest::{self, Manifest};
use crate::store::{Store, digest_of};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16) -> Response {
        Response {
            status,
            headers: vec![],
            body: vec![],
        }
    }
    fn json(status: u16, v: serde_json::Value) -> Response {
        let mut r = Response::new(status);
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = serde_json::to_vec(&v).unwrap();
        r
    }
    fn error(status: u16, code: &str, msg: &str) -> Response {
        Response::json(
            status,
            serde_json::json!({"errors": [{"code": code, "message": msg}]}),
        )
    }
    fn header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        _ => "Error",
    }
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const MAX_BODY: usize = 2 << 30;

/// Reads one HTTP/1.1 request (Content-Length or chunked body).
pub fn read_request(r: &mut impl BufRead) -> io::Result<Option<Request>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k), url_decode(v))
        })
        .collect();
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size = String::new();
            r.read_line(&mut size)?;
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if body.len() + n > MAX_BODY {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            let start = body.len();
            body.resize(start + n, 0);
            r.read_exact(&mut body[start..])?;
            let mut crlf = String::new();
            r.read_line(&mut crlf)?;
            if n == 0 {
                break;
            }
        }
    } else if let Some(n) = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        if n > MAX_BODY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    }
    Ok(Some(Request {
        method,
        path: url_decode(path),
        query,
        headers,
        body,
    }))
}

fn write_response(w: &mut impl Write, res: &Response, head_only: bool) -> io::Result<()> {
    write!(w, "HTTP/1.1 {} {}\r\n", res.status, reason(res.status))?;
    write!(w, "Docker-Distribution-API-Version: registry/2.0\r\n")?;
    for (k, v) in &res.headers {
        write!(w, "{k}: {v}\r\n")?;
    }
    write!(
        w,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        res.body.len()
    )?;
    if !head_only {
        w.write_all(&res.body)?;
    }
    w.flush()
}

pub struct Registry {
    store: Store,
    host: String,
    uploads: Mutex<HashMap<String, PathBuf>>,
    next_upload: AtomicU64,
}

impl Registry {
    /// `host` is how clients address this registry (e.g. `localhost:5000`), used to name the
    /// images pushed to it.
    pub fn new(store: Store, host: &str) -> Registry {
        Registry {
            store,
            host: host.to_string(),
            uploads: Mutex::new(HashMap::new()),
            next_upload: AtomicU64::new(1),
        }
    }

    fn repo_names(&self) -> BTreeSet<String> {
        let prefix = format!("{}/", self.host);
        self.store
            .refs()
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter_map(|r| r.rsplit_once(':').map(|(n, _)| n.to_string()))
            .collect()
    }

    fn manifest_for(&self, name: &str, reference: &str) -> Option<(String, Vec<u8>)> {
        let digest = if reference.starts_with("sha256:") {
            reference.to_string()
        } else {
            self.store
                .refs()
                .get(&format!("{}/{name}:{reference}", self.host))
                .cloned()?
        };
        let body = self.store.read_blob(&digest).ok()?;
        Some((digest, body))
    }

    pub fn handle(&self, req: Request) -> Response {
        let p = req.path.as_str();
        let m = req.method.as_str();
        if p == "/v2/" || p == "/v2" {
            return Response::json(200, serde_json::json!({}));
        }
        if p == "/v2/_catalog" {
            return Response::json(200, serde_json::json!({"repositories": self.repo_names()}));
        }
        let Some(rest) = p.strip_prefix("/v2/") else {
            return Response::error(404, "NOT_FOUND", "unknown path");
        };
        if let Some(name) = rest.strip_suffix("/tags/list") {
            let prefix = format!("{}/{name}:", self.host);
            let tags: Vec<String> = self
                .store
                .refs()
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
                .collect();
            if tags.is_empty() {
                return Response::error(404, "NAME_UNKNOWN", name);
            }
            return Response::json(200, serde_json::json!({"name": name, "tags": tags}));
        }
        if let Some((name, reference)) = rest.rsplit_once("/manifests/") {
            return match m {
                "GET" | "HEAD" => match self.manifest_for(name, reference) {
                    Some((digest, body)) => {
                        let mt = serde_json::from_slice::<serde_json::Value>(&body)
                            .ok()
                            .and_then(|v| {
                                v.get("mediaType")
                                    .and_then(|t| t.as_str())
                                    .map(String::from)
                            })
                            .unwrap_or_else(|| manifest::OCI_MANIFEST.into());
                        let mut r = Response::new(200)
                            .header("Content-Type", &mt)
                            .header("Docker-Content-Digest", &digest);
                        r.body = body;
                        r
                    }
                    None => Response::error(404, "MANIFEST_UNKNOWN", reference),
                },
                "PUT" => self.put_manifest(name, reference, &req.body),
                _ => Response::error(405, "UNSUPPORTED", m),
            };
        }
        if let Some((name, digest)) = rest.rsplit_once("/blobs/") {
            if digest == "uploads/" || digest == "uploads" {
                if m != "POST" {
                    return Response::error(405, "UNSUPPORTED", m);
                }
                let id = format!("u{}", self.next_upload.fetch_add(1, Ordering::SeqCst));
                let path = self.store.root().join(format!("upload-{id}"));
                if let Err(e) = fs::write(&path, &req.body) {
                    return Response::error(500, "UNKNOWN", &e.to_string());
                }
                self.uploads.lock().unwrap().insert(id.clone(), path);
                return Response::new(202)
                    .header("Location", &format!("/v2/{name}/blobs/uploads/{id}"))
                    .header("Docker-Upload-UUID", &id)
                    .header("Range", "0-0");
            }
            if let Some(id) = digest.strip_prefix("uploads/") {
                return self.upload(name, id, &req);
            }
            return match m {
                "GET" | "HEAD" => match self.store.read_blob(digest) {
                    Ok(body) => {
                        let mut r = Response::new(200)
                            .header("Content-Type", "application/octet-stream")
                            .header("Docker-Content-Digest", digest);
                        r.body = body;
                        r
                    }
                    Err(_) => Response::error(404, "BLOB_UNKNOWN", digest),
                },
                _ => Response::error(405, "UNSUPPORTED", m),
            };
        }
        Response::error(404, "NOT_FOUND", "unknown path")
    }

    fn upload(&self, name: &str, id: &str, req: &Request) -> Response {
        let Some(path) = self.uploads.lock().unwrap().get(id).cloned() else {
            return Response::error(404, "BLOB_UPLOAD_UNKNOWN", id);
        };
        let append = |data: &[u8]| -> io::Result<u64> {
            let mut f = fs::OpenOptions::new().append(true).open(&path)?;
            f.write_all(data)?;
            Ok(f.metadata()?.len())
        };
        match req.method.as_str() {
            "PATCH" => match append(&req.body) {
                Ok(n) => Response::new(202)
                    .header("Location", &format!("/v2/{name}/blobs/uploads/{id}"))
                    .header("Range", &format!("0-{}", n.saturating_sub(1))),
                Err(e) => Response::error(500, "UNKNOWN", &e.to_string()),
            },
            "PUT" => {
                let Some(digest) = req.query.get("digest") else {
                    return Response::error(400, "DIGEST_INVALID", "missing digest");
                };
                if let Err(e) = append(&req.body) {
                    return Response::error(500, "UNKNOWN", &e.to_string());
                }
                let res = fs::File::open(&path).and_then(|f| self.store.put_blob_from(digest, f));
                let _ = fs::remove_file(&path);
                self.uploads.lock().unwrap().remove(id);
                match res {
                    Ok(_) => Response::new(201)
                        .header("Location", &format!("/v2/{name}/blobs/{digest}"))
                        .header("Docker-Content-Digest", digest),
                    Err(e) => Response::error(400, "DIGEST_INVALID", &e.to_string()),
                }
            }
            m => Response::error(405, "UNSUPPORTED", m),
        }
    }

    fn put_manifest(&self, name: &str, reference: &str, body: &[u8]) -> Response {
        let m: Manifest = match serde_json::from_slice(body) {
            Ok(m) => m,
            Err(e) => return Response::error(400, "MANIFEST_INVALID", &e.to_string()),
        };
        for d in std::iter::once(&m.config).chain(m.layers.iter()) {
            if !self.store.has_blob(&d.digest) {
                return Response::error(400, "MANIFEST_BLOB_UNKNOWN", &d.digest);
            }
        }
        let digest = match self.store.put_blob(body) {
            Ok(d) => d,
            Err(e) => return Response::error(500, "UNKNOWN", &e.to_string()),
        };
        if reference.starts_with("sha256:") && reference != digest {
            return Response::error(400, "DIGEST_INVALID", reference);
        }
        if !reference.starts_with("sha256:")
            && let Err(e) = self
                .store
                .set_ref(&format!("{}/{name}:{reference}", self.host), &digest)
        {
            return Response::error(500, "UNKNOWN", &e.to_string());
        }
        debug_assert_eq!(digest, digest_of(body));
        Response::new(201)
            .header("Location", &format!("/v2/{name}/manifests/{digest}"))
            .header("Docker-Content-Digest", &digest)
    }

    fn serve_conn(&self, s: TcpStream) -> io::Result<()> {
        let mut r = BufReader::new(s.try_clone()?);
        let mut w = s;
        if let Some(req) = read_request(&mut r)? {
            let head = req.method == "HEAD";
            let res = self.handle(req);
            write_response(&mut w, &res, head)?;
        }
        Ok(())
    }

    /// Serves forever, one thread per connection.
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        for s in listener.incoming().flatten() {
            let me = self.clone();
            std::thread::spawn(move || {
                let _ = me.serve_conn(s);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, body: &[u8]) -> Request {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let query = q
            .split('&')
            .filter(|x| !x.is_empty())
            .map(|x| {
                let (k, v) = x.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        Request {
            method: method.into(),
            path: p.into(),
            query,
            headers: HashMap::new(),
            body: body.to_vec(),
        }
    }

    fn header<'a>(r: &'a Response, k: &str) -> &'a str {
        r.headers
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    #[test]
    fn push_and_pull_through_the_api() {
        let t = tempfile::tempdir().unwrap();
        let reg = Registry::new(Store::open(t.path()).unwrap(), "localhost:5000");
        assert_eq!(reg.handle(req("GET", "/v2/", b"")).status, 200);
        // Upload a blob in two pieces.
        let start = reg.handle(req("POST", "/v2/team/app/blobs/uploads/", b""));
        assert_eq!(start.status, 202);
        let loc = header(&start, "Location").to_string();
        assert_eq!(reg.handle(req("PATCH", &loc, b"layer-")).status, 202);
        let layer = digest_of(b"layer-data");
        let done = reg.handle(req("PUT", &format!("{loc}?digest={layer}"), b"data"));
        assert_eq!(done.status, 201, "{}", String::from_utf8_lossy(&done.body));
        // A wrong digest is refused.
        let s2 = reg.handle(req("POST", "/v2/team/app/blobs/uploads/", b""));
        let bad = reg.handle(req(
            "PUT",
            &format!("{}?digest={}", header(&s2, "Location"), digest_of(b"x")),
            b"y",
        ));
        assert_eq!(bad.status, 400);
        // Config + manifest.
        let cfg = reg
            .store
            .put_blob(br#"{"config":{"Cmd":["/bin/sh"]}}"#)
            .unwrap();
        let man = serde_json::json!({"schemaVersion":2,"mediaType":manifest::OCI_MANIFEST,
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":cfg,"size":1},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer,"size":10}]});
        let body = serde_json::to_vec(&man).unwrap();
        let put = reg.handle(req("PUT", "/v2/team/app/manifests/1.0", &body));
        assert_eq!(put.status, 201);
        let got = reg.handle(req("GET", "/v2/team/app/manifests/1.0", b""));
        assert_eq!(got.status, 200);
        assert_eq!(got.body, body);
        assert_eq!(header(&got, "Docker-Content-Digest"), digest_of(&body));
        assert_eq!(header(&got, "Content-Type"), manifest::OCI_MANIFEST);
        assert_eq!(
            reg.handle(req(
                "GET",
                &format!("/v2/team/app/manifests/{}", digest_of(&body)),
                b""
            ))
            .status,
            200
        );
        assert_eq!(
            reg.handle(req("GET", &format!("/v2/team/app/blobs/{layer}"), b""))
                .body,
            b"layer-data"
        );
        let tags: serde_json::Value =
            serde_json::from_slice(&reg.handle(req("GET", "/v2/team/app/tags/list", b"")).body)
                .unwrap();
        assert_eq!(tags["tags"], serde_json::json!(["1.0"]));
        let cat: serde_json::Value =
            serde_json::from_slice(&reg.handle(req("GET", "/v2/_catalog", b"")).body).unwrap();
        assert_eq!(cat["repositories"], serde_json::json!(["team/app"]));
        // Manifests that point at missing blobs are refused.
        let missing = serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"config":{"digest":digest_of(b"nope"),"size":1},"layers":[]})).unwrap();
        assert_eq!(
            reg.handle(req("PUT", "/v2/team/app/manifests/2.0", &missing))
                .status,
            400
        );
        assert_eq!(
            reg.handle(req("GET", "/v2/team/app/manifests/9.9", b""))
                .status,
            404
        );
    }

    #[test]
    fn parses_chunked_requests() {
        let raw = b"PUT /v2/x/blobs/uploads/u1?digest=sha256%3Aab HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let r = read_request(&mut &raw[..]).unwrap().unwrap();
        assert_eq!(r.method, "PUT");
        assert_eq!(r.body, b"abcde");
        assert_eq!(r.query["digest"], "sha256:ab");
    }
}
