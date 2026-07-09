use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use cryptex::KeyRing;
use cryptex::encrypted_vfs::{ConnectionParams, EncryptedVfsKeyring};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, fs};

// Pre-derived 32-byte key as hex — bypasses Argon2id so we benchmark
// the VFS I/O and cipher, not the KDF.
const BENCH_KEY: &str = "key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

const VALUE: &[u8] = b"a_realistic_secret_value_padded_for_benchmarking_purposes_0123456789";

fn bench_dir(label: &str) -> PathBuf {
    let mut p = env::temp_dir();
    p.push(format!("cryptex-bench-{}-{}", label, std::process::id()));
    p
}

fn open(params: &ConnectionParams, path: &Path) -> EncryptedVfsKeyring {
    EncryptedVfsKeyring::with_params(params, Some(path.to_path_buf())).unwrap()
}

fn write_n(kr: &mut EncryptedVfsKeyring, n: usize) {
    for i in 0..n {
        kr.set_secret(format!("k{i:04}"), VALUE).unwrap();
    }
}

fn read_n(kr: &mut EncryptedVfsKeyring, n: usize) {
    for i in 0..n {
        kr.get_secret(format!("k{i:04}")).unwrap();
    }
}

fn bench_writes(c: &mut Criterion) {
    let counts = [10usize, 50, 200];
    let mut group = c.benchmark_group("writes");

    for &n in &counts {
        for cipher in ["chacha20poly1305", "aes256gcm"] {
            let path = bench_dir(&format!("w-{cipher}-{n}"));
            let _ = fs::remove_dir_all(&path);

            let params =
                ConnectionParams::from_str(&format!("{BENCH_KEY} cipher={cipher}")).unwrap();

            // Create DB once outside the timed loop.
            open(&params, &path);

            group.bench_with_input(BenchmarkId::new(cipher, n), &n, |b, &n| {
                b.iter(|| {
                    let mut kr = open(&params, &path);
                    write_n(&mut kr, n);
                });
            });

            let _ = fs::remove_dir_all(&path);
        }
    }

    group.finish();
}

fn bench_reads(c: &mut Criterion) {
    const N: usize = 50;
    let mut group = c.benchmark_group("reads");

    for cipher in ["chacha20poly1305", "aes256gcm"] {
        let path = bench_dir(&format!("r-{cipher}"));
        let _ = fs::remove_dir_all(&path);

        let params = ConnectionParams::from_str(&format!("{BENCH_KEY} cipher={cipher}")).unwrap();

        // Populate once.
        write_n(&mut open(&params, &path), N);

        group.bench_function(cipher, |b| {
            b.iter(|| {
                let mut kr = open(&params, &path);
                read_n(&mut kr, N);
            });
        });

        let _ = fs::remove_dir_all(&path);
    }

    group.finish();
}

criterion_group!(benches, bench_writes, bench_reads);
criterion_main!(benches);
