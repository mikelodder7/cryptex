#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
use std::time::Instant;

#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};

#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
fn main() -> Result<(), String> {
    let expected_default_memory_cost = cryptex::default_memory_cost();
    let expected_default_threads = cryptex::default_threads();
    let expected_default_parallel = cryptex::default_parallel();
    let hash_memory = argon2_param("CRYPTEX_ARGON2_MEMORY", expected_default_memory_cost)?;
    let hash_threads = argon2_param("CRYPTEX_ARGON2_THREADS", expected_default_threads)?;
    let hash_parallel = argon2_param("CRYPTEX_ARGON2_PARALLEL", expected_default_parallel)?;

    #[cfg(feature = "file")]
    {
        let params = cryptex::sqlcipher::ConnectionParams::default();
        assert_eq!(params.memory, expected_default_memory_cost);
        assert_eq!(params.threads, expected_default_threads);
        assert_eq!(params.parallel, expected_default_parallel);

        let parsed: cryptex::sqlcipher::ConnectionParams = "password=pw salt=saltsaltsaltsalt"
            .parse()
            .map_err(|e: cryptex::error::KeyRingError| e.to_string())?;
        assert_eq!(parsed.memory, expected_default_memory_cost);
        assert_eq!(parsed.threads, expected_default_threads);
        assert_eq!(parsed.parallel, expected_default_parallel);
        hash_password(
            "sqlcipher",
            hash_memory,
            hash_threads,
            hash_parallel,
            &parsed.password,
            &parsed.salt,
        )?;
    }

    #[cfg(feature = "encrypted-vfs")]
    {
        let params = cryptex::encrypted_vfs::ConnectionParams::default();
        assert_eq!(params.memory, expected_default_memory_cost);
        assert_eq!(params.threads, expected_default_threads);
        assert_eq!(params.parallel, expected_default_parallel);

        let parsed: cryptex::encrypted_vfs::ConnectionParams = "password=pw salt=saltsaltsaltsalt"
            .parse()
            .map_err(|e: cryptex::error::KeyRingError| e.to_string())?;
        assert_eq!(parsed.memory, expected_default_memory_cost);
        assert_eq!(parsed.threads, expected_default_threads);
        assert_eq!(parsed.parallel, expected_default_parallel);
        hash_password(
            "encrypted-vfs",
            hash_memory,
            hash_threads,
            hash_parallel,
            &parsed.password,
            &parsed.salt,
        )?;
    }

    Ok(())
}

#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
fn argon2_param(name: &str, default: u32) -> Result<u32, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|e| format!("invalid {name}={value}: {e}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(format!("invalid {name}: {e}")),
    }
}

#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
fn hash_password(
    backend: &str,
    memory: u32,
    threads: u32,
    parallel: u32,
    password: &[u8],
    salt: &[u8],
) -> Result<(), String> {
    let argon2_params = Argon2Params::new(
        memory,
        threads,
        parallel,
        Some(Argon2Params::DEFAULT_OUTPUT_LEN),
    )
    .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut okm = [0u8; 32];

    let started = Instant::now();
    argon2
        .hash_password_into(password, salt, &mut okm)
        .map_err(|e| e.to_string())?;
    let elapsed = started.elapsed();
    std::hint::black_box(okm);

    println!(
        "{backend}: memory={memory} KiB threads={threads} parallel={parallel} elapsed={elapsed:?}"
    );
    Ok(())
}

#[cfg(not(any(feature = "file", feature = "encrypted-vfs")))]
fn main() {}
