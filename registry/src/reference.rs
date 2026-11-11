//! Image references: `alpine`, `python:3.12-slim`, `library/debian:bookworm`,
//! `localhost:5000/tools/x:1`, `alpine@sha256:...`.

use std::fmt;

pub const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Host (and port) of the registry; Docker Hub is `registry-1.docker.io`.
    pub registry: String,
    /// Repository path, e.g. `library/alpine`.
    pub repository: String,
    /// Tag, when the reference has one (`latest` if it has neither tag nor digest).
    pub tag: Option<String>,
    /// `sha256:<hex>`, when the reference pins a digest.
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty image reference".into());
        }
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                if !d.starts_with("sha256:")
                    || d.len() != 71
                    || !d[7..].bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(format!("bad digest in {s}"));
                }
                (r, Some(d.to_ascii_lowercase()))
            }
            None => (s, None),
        };
        // The first component is a registry host if it looks like one.
        let (registry, path) = match rest.split_once('/') {
            Some((first, more))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), more.to_string())
            }
            _ => (DOCKER_HUB.to_string(), rest.to_string()),
        };
        let registry = if registry == "docker.io" || registry == "index.docker.io" {
            DOCKER_HUB.to_string()
        } else {
            registry
        };
        // A tag is a ':' in the last path component.
        let last_slash = path.rfind('/').map(|i| i + 1).unwrap_or(0);
        let (mut repository, tag) = match path[last_slash..].rfind(':') {
            Some(i) => (
                path[..last_slash + i].to_string(),
                Some(path[last_slash + i + 1..].to_string()),
            ),
            None => (path.clone(), None),
        };
        if repository.is_empty() || repository.split('/').any(|c| c.is_empty()) {
            return Err(format!("bad repository in {s}"));
        }
        if !repository
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/".contains(&b))
        {
            return Err(format!(
                "repository names are lowercase letters, digits and ._-/: {s}"
            ));
        }
        if let Some(t) = &tag
            && (t.is_empty()
                || t.len() > 128
                || !t
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
        {
            return Err(format!("bad tag in {s}"));
        }
        if registry == DOCKER_HUB && !repository.contains('/') {
            repository = format!("library/{repository}");
        }
        let tag = if tag.is_none() && digest.is_none() {
            Some("latest".to_string())
        } else {
            tag
        };
        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// What to ask the registry for: the digest if pinned, else the tag.
    pub fn reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }

    /// Base URL of the registry API. Local registries are plain HTTP.
    pub fn base_url(&self) -> String {
        let host = self.registry.split(':').next().unwrap_or("");
        let plain = host == "localhost" || host == "127.0.0.1" || host == "::1";
        format!(
            "{}://{}",
            if plain { "http" } else { "https" },
            self.registry
        )
    }
}

impl fmt::Display for Reference {
    /// Canonical name: `docker.io/library/alpine:3.20`, `localhost:5000/x:1`, `...@sha256:..`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reg = if self.registry == DOCKER_HUB {
            "docker.io"
        } else {
            &self.registry
        };
        write!(f, "{}/{}", reg, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_short_names() {
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(r.registry, DOCKER_HUB);
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert_eq!(r.to_string(), "docker.io/library/alpine:latest");
        assert_eq!(r.base_url(), "https://registry-1.docker.io");
        let p = Reference::parse("python:3.12-slim").unwrap();
        assert_eq!(
            (p.repository.as_str(), p.reference()),
            ("library/python", "3.12-slim")
        );
        let u = Reference::parse("docker.io/someone/tool:v1").unwrap();
        assert_eq!(u.repository, "someone/tool");
    }

    #[test]
    fn registries_ports_and_digests() {
        let r = Reference::parse("localhost:5000/team/app:1.0").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "team/app");
        assert_eq!(r.base_url(), "http://localhost:5000");
        let d = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("alpine@{d}")).unwrap();
        assert_eq!(r.tag, None);
        assert_eq!(r.reference(), d);
        let both = Reference::parse(&format!("ghcr.io/o/r:t@{d}")).unwrap();
        assert_eq!(both.registry, "ghcr.io");
        assert_eq!(both.reference(), d);
    }

    #[test]
    fn rejects_bad_references() {
        for bad in [
            "",
            "Alpine",
            "alpine:",
            "alpine@sha256:xyz",
            "a//b",
            "alpine:bad tag",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }
}
