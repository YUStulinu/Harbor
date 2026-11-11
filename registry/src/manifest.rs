//! Image manifests, indexes and configs (OCI image spec and Docker schema 2, which have the
//! same shape for what we use).

use serde::{Deserialize, Serialize};

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The Accept header for manifest requests: everything we can read.
pub fn accept_header() -> String {
    [OCI_INDEX, OCI_MANIFEST, DOCKER_LIST, DOCKER_MANIFEST].join(", ")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Descriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// An image manifest (one platform).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// An index / manifest list (several platforms).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Index {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub manifests: Vec<Descriptor>,
}

impl Index {
    /// The manifest for linux/<arch>, ignoring attestation entries (which have os "unknown").
    pub fn pick(&self, arch: &str) -> Option<&Descriptor> {
        self.manifests.iter().find(|d| {
            d.platform
                .as_ref()
                .is_some_and(|p| p.os == "linux" && p.architecture == arch)
        })
    }
}

/// The image config blob; only the runtime part (`config`) matters here.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: Option<ImageConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ImageConfig {
    #[serde(rename = "Env", default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(
        rename = "Entrypoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(
        rename = "WorkingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    #[serde(rename = "User", default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Is this a list of manifests (by media type, or by shape when the type is missing)?
pub fn is_index(media_type: &str, body: &[u8]) -> bool {
    if media_type.starts_with(OCI_INDEX) || media_type.starts_with(DOCKER_LIST) {
        return true;
    }
    if media_type.starts_with(OCI_MANIFEST) || media_type.starts_with(DOCKER_MANIFEST) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .map(|v| v.get("manifests").is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_linux_amd64_and_skips_attestations() {
        let idx: Index = serde_json::from_str(
            r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}},
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":1,"platform":{"architecture":"unknown","os":"unknown"}},
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cc","size":1,"platform":{"architecture":"amd64","os":"linux"}}]}"#,
        )
        .unwrap();
        assert_eq!(idx.pick("amd64").unwrap().digest, "sha256:cc");
        assert!(idx.pick("s390x").is_none());
        assert!(is_index(OCI_INDEX, b"{}"));
        assert!(!is_index(DOCKER_MANIFEST, b"{}"));
        assert!(is_index("", br#"{"manifests":[]}"#));
    }

    #[test]
    fn reads_the_runtime_config() {
        let c: ConfigFile = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/bin"],"Cmd":["/bin/sh"],"WorkingDir":"/"},"rootfs":{}}"#,
        )
        .unwrap();
        let ic = c.config.unwrap();
        assert_eq!(ic.cmd.unwrap(), vec!["/bin/sh"]);
        assert_eq!(ic.env.unwrap(), vec!["PATH=/usr/bin"]);
        assert_eq!(ic.entrypoint, None);
    }
}
