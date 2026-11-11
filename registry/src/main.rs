//! harbor-registry CLI.
//!
//!   harbor-registry [--store DIR] pull IMAGE            download (linux/amd64) and unpack
//!   harbor-registry [--store DIR] images                list stored images
//!   harbor-registry [--store DIR] inspect IMAGE         JSON for the runtime: config + layer dirs
//!   harbor-registry [--store DIR] push IMAGE TARGET     e.g. push alpine localhost:5000/alpine:3
//!   harbor-registry [--store DIR] rm IMAGE              forget a name (blobs stay)
//!   harbor-registry [--store DIR] serve [--addr 127.0.0.1:5000]
//!
//! The store defaults to $HARBOR_STORE or /var/lib/harbor/images.

use harbor_registry::client::Client;
use harbor_registry::server::Registry;
use harbor_registry::store::Store;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn usage() -> ! {
    eprintln!(
        "usage: harbor-registry [--store DIR] pull IMAGE | images | inspect IMAGE | push IMAGE TARGET | rm IMAGE | serve [--addr HOST:PORT]"
    );
    std::process::exit(2)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut store_dir = PathBuf::from(
        std::env::var("HARBOR_STORE").unwrap_or_else(|_| "/var/lib/harbor/images".into()),
    );
    if args.first().map(String::as_str) == Some("--store") {
        if args.len() < 2 {
            usage();
        }
        store_dir = PathBuf::from(&args[1]);
        args.drain(..2);
    }
    let store = match Store::open(&store_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open store {}: {e}", store_dir.display());
            std::process::exit(1)
        }
    };
    let cmd = args.first().cloned().unwrap_or_else(|| usage());
    let res: Result<(), String> = match (cmd.as_str(), args.len()) {
        ("pull", 2) => {
            let t = Instant::now();
            let mut c = Client::new();
            c.log = true;
            c.pull(&store, &args[1], "amd64")
                .map(|r| {
                    println!(
                        "{} {} ({} layers, {} reused, {:.1} MB downloaded, {:.1}s)",
                        r.name,
                        r.digest,
                        r.layers,
                        r.reused_layers,
                        r.downloaded_bytes as f64 / 1e6,
                        t.elapsed().as_secs_f64()
                    )
                })
                .map_err(|e| e.to_string())
        }
        ("images", 1) => {
            for (name, digest) in store.refs() {
                let size = store
                    .manifest(&digest)
                    .map(|m| m.layers.iter().map(|l| l.size).sum::<u64>())
                    .unwrap_or(0);
                println!(
                    "{name}\t{}\t{:.1} MB",
                    &digest[..19.min(digest.len())],
                    size as f64 / 1e6
                );
            }
            Ok(())
        }
        ("inspect", 2) => store
            .info(&args[1])
            .map(|i| println!("{}", serde_json::to_string_pretty(&i).unwrap()))
            .map_err(|e| e.to_string()),
        ("push", 3) => Client::new()
            .push(&store, &args[1], &args[2])
            .map(|d| println!("pushed {} {d}", args[2]))
            .map_err(|e| e.to_string()),
        ("rm", 2) => match store.resolve(&args[1]) {
            Some((name, _)) => store
                .remove_ref(&name)
                .map(|_| println!("removed {name}"))
                .map_err(|e| e.to_string()),
            None => Err(format!("no image {}", args[1])),
        },
        ("serve", 1) | ("serve", 3) => {
            let addr = if args.len() == 3 && args[1] == "--addr" {
                args[2].clone()
            } else {
                "127.0.0.1:5000".into()
            };
            match TcpListener::bind(&addr) {
                Ok(l) => {
                    let host = if addr.starts_with("127.0.0.1:") {
                        addr.replacen("127.0.0.1", "localhost", 1)
                    } else {
                        addr.clone()
                    };
                    eprintln!("registry on http://{addr}/v2/ (images named {host}/...)");
                    Arc::new(Registry::new(store, &host)).serve(l);
                    Ok(())
                }
                Err(e) => Err(format!("cannot listen on {addr}: {e}")),
            }
        }
        _ => usage(),
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
