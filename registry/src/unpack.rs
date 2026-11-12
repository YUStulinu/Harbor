//! Unpacking an image layer into a directory that overlayfs can use as a lower layer.
//!
//! Layer tarballs mark deletions with "whiteout" files (the OCI image spec, taken from AUFS):
//!   `dir/.wh.name`        `name` was deleted from the layers below
//!   `dir/.wh..wh..opq`    `dir` is opaque: nothing from the layers below shows through
//! overlayfs has its own encoding for the same things: a character device 0:0 named `name`,
//! and the extended attribute `trusted.overlay.opaque=y` on the directory. Both need root.

use flate2::read::GzDecoder;
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

/// Statistics of one unpacked layer.
#[derive(Debug, Default, PartialEq)]
pub struct Unpacked {
    pub entries: usize,
    pub whiteouts: usize,
    pub opaque_dirs: usize,
}

/// A path inside the layer, relative and without `..` (else None).
fn clean(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn make_whiteout(path: &Path) -> io::Result<()> {
    let c = cstr(path)?;
    // SAFETY: c is a valid NUL-terminated path; mknod does not keep it.
    let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR, libc::makedev(0, 0)) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn make_opaque(dir: &Path) -> io::Result<()> {
    let c = cstr(dir)?;
    let name = CString::new("trusted.overlay.opaque").unwrap();
    // SAFETY: valid C strings and a 1-byte value buffer.
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            name.as_ptr(),
            b"y".as_ptr() as *const libc::c_void,
            1,
            0,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Unpacks a layer blob (gzip or plain tar) into `dest`.
pub fn unpack_layer(blob: impl Read, media_type: &str, dest: &Path) -> io::Result<Unpacked> {
    let mut r = BufReader::new(blob);
    if media_type.contains("zstd") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zstd-compressed layers are not supported",
        ));
    }
    // Look at the magic number rather than trusting the media type.
    let gz = r.fill_buf()?.starts_with(&[0x1f, 0x8b]);
    if gz {
        unpack_tar(GzDecoder::new(r), dest)
    } else {
        unpack_tar(r, dest)
    }
}

pub fn unpack_tar(r: impl Read, dest: &Path) -> io::Result<Unpacked> {
    let mut ar = tar::Archive::new(r);
    // Ownership and xattrs are kept when we can (the image says who owns what): only root may
    // chown to other users or set trusted.* attributes, so an unprivileged pull keeps its own
    // uid. tar's unpack_in refuses paths that would leave `dest`.
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    ar.set_preserve_permissions(true);
    ar.set_preserve_ownerships(root);
    ar.set_preserve_mtime(true);
    ar.set_unpack_xattrs(root);
    ar.set_overwrite(true);
    let mut stats = Unpacked::default();
    for e in ar.entries()? {
        let mut e = e?;
        let raw = e.path()?.into_owned();
        let Some(path) = clean(&raw) else { continue };
        stats.entries += 1;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name == OPAQUE {
            let dir = dest.join(path.parent().unwrap_or(Path::new("")));
            fs::create_dir_all(&dir)?;
            make_opaque(&dir)?;
            stats.opaque_dirs += 1;
            continue;
        }
        if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
            let dir = dest.join(path.parent().unwrap_or(Path::new("")));
            fs::create_dir_all(&dir)?;
            let p = dir.join(target);
            if p.symlink_metadata().is_ok() {
                if p.is_dir() && !p.is_symlink() {
                    fs::remove_dir_all(&p)?
                } else {
                    fs::remove_file(&p)?
                }
            }
            make_whiteout(&p)?;
            stats.whiteouts += 1;
            continue;
        }
        e.unpack_in(dest)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    fn layer(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            match data {
                Some(d) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(d.len() as u64);
                    h.set_mode(0o644);
                    b.append_data(&mut h, path, *d).unwrap();
                }
                None => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(0o755);
                    b.append_data(&mut h, path, &[][..]).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn root() -> bool {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() == 0 }
    }

    #[test]
    fn files_and_gzip() {
        let t = tempfile::tempdir().unwrap();
        let tarball = layer(&[
            ("etc/", None),
            ("etc/os-release", Some(b"ID=test\n")),
            ("./bin/", None),
        ]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tarball).unwrap();
        let s = unpack_layer(
            &gz.finish().unwrap()[..],
            "application/vnd.oci.image.layer.v1.tar+gzip",
            t.path(),
        )
        .unwrap();
        assert_eq!(s.entries, 3);
        assert_eq!(
            fs::read(t.path().join("etc/os-release")).unwrap(),
            b"ID=test\n"
        );
        assert!(t.path().join("bin").is_dir());
    }

    #[test]
    fn whiteouts_become_overlay_whiteouts() {
        if !root() {
            eprintln!("skipped: needs root (mknod, trusted xattrs)");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let s = unpack_tar(
            &layer(&[
                ("etc/", None),
                ("etc/.wh.passwd", Some(b"")),
                ("var/cache/", None),
                ("var/cache/.wh..wh..opq", Some(b"")),
            ])[..],
            t.path(),
        )
        .unwrap();
        assert_eq!((s.whiteouts, s.opaque_dirs), (1, 1));
        let m = fs::symlink_metadata(t.path().join("etc/passwd")).unwrap();
        assert!(m.file_type().is_char_device());
        assert_eq!(m.rdev(), 0);
        let c = cstr(&t.path().join("var/cache")).unwrap();
        let name = CString::new("trusted.overlay.opaque").unwrap();
        let mut v = [0u8; 4];
        // SAFETY: valid strings and buffer.
        let n = unsafe {
            libc::getxattr(
                c.as_ptr(),
                name.as_ptr(),
                v.as_mut_ptr() as *mut libc::c_void,
                v.len(),
            )
        };
        assert_eq!((n, v[0]), (1, b'y'));
    }

    #[test]
    fn paths_leaving_the_layer_are_skipped() {
        assert_eq!(clean(Path::new("../etc/passwd")), None);
        assert_eq!(clean(Path::new("/etc/passwd")), None);
        assert_eq!(clean(Path::new("./a/./b")), Some(PathBuf::from("a/b")));
        let t = tempfile::tempdir().unwrap();
        let inner = t.path().join("layer");
        fs::create_dir(&inner).unwrap();
        // tar::Builder refuses to write "..", so build the header by hand.
        let mut h = tar::Header::new_old();
        h.as_old_mut().name[..9].copy_from_slice(b"../escape");
        h.set_size(1);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h.set_cksum();
        let mut data = h.as_bytes().to_vec();
        data.extend_from_slice(&[b'x'; 512]);
        data.extend_from_slice(&[0u8; 1024]);
        unpack_tar(&data[..], &inner).unwrap();
        assert!(!t.path().join("escape").exists());
    }
}
