/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Page-level AEAD encryption shared by the SQLite encrypted VFS, the Turso
//! encrypted IO backend and the browser page stores.
//!
//! Every 4096-byte logical page is stored as
//! `[ciphertext(4096) | nonce(12) | tag(16)]`, with the page number bound as
//! associated data so pages cannot be swapped. The byte layout is identical
//! for every [`PageStore`], so a file written natively opens unchanged from
//! OPFS and the other way round.

use super::cipher::CipherAlgorithm;
use super::page_store::PageStore;
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use std::io;
use std::iter;

pub(crate) const LOGICAL_PAGE_SIZE: usize = 4096;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
/// Physical block on disk = [ciphertext(4096) | nonce(12) | tag(16)]
pub(crate) const PHYSICAL_PAGE_SIZE: usize = LOGICAL_PAGE_SIZE + NONCE_SIZE + TAG_SIZE; // 4124

// Internal dispatch — one variant per algorithm.  Both use 12-byte nonces and
// 16-byte tags so the physical page layout is identical regardless of choice.
pub(crate) enum ActiveCipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<Aes256Gcm>),
}

impl ActiveCipher {
    pub(crate) fn from_key(alg: CipherAlgorithm, key: &[u8; 32]) -> Self {
        match alg {
            CipherAlgorithm::ChaCha20Poly1305 => Self::ChaCha(ChaCha20Poly1305::new(key.into())),
            CipherAlgorithm::Aes256Gcm => Self::Aes(Box::new(Aes256Gcm::new(key.into()))),
        }
    }

    pub(crate) fn encrypt_page(
        &self,
        page_no: u64,
        plaintext: &[u8; LOGICAL_PAGE_SIZE],
    ) -> io::Result<[u8; PHYSICAL_PAGE_SIZE]> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(e.to_string()))?;

        let nonce = chacha20poly1305::Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| io::Error::other("invalid nonce length"))?;
        let aad = page_no.to_le_bytes();
        let payload = Payload {
            msg: plaintext.as_slice(),
            aad: &aad,
        };

        let ct = match self {
            Self::ChaCha(c) => c.encrypt(&nonce, payload),
            Self::Aes(c) => c.encrypt(&nonce, payload),
        }
        .map_err(|_| io::Error::other("encryption failed"))?;

        // Layout: [ciphertext(4096) | nonce(12) | tag(16)]
        let mut block = [0u8; PHYSICAL_PAGE_SIZE];
        block[..LOGICAL_PAGE_SIZE].copy_from_slice(&ct[..LOGICAL_PAGE_SIZE]);
        block[LOGICAL_PAGE_SIZE..LOGICAL_PAGE_SIZE + NONCE_SIZE].copy_from_slice(&nonce_bytes);
        block[LOGICAL_PAGE_SIZE + NONCE_SIZE..].copy_from_slice(&ct[LOGICAL_PAGE_SIZE..]);
        Ok(block)
    }

    pub(crate) fn decrypt_page(
        &self,
        page_no: u64,
        block: &[u8; PHYSICAL_PAGE_SIZE],
    ) -> io::Result<[u8; LOGICAL_PAGE_SIZE]> {
        let ciphertext_part = &block[..LOGICAL_PAGE_SIZE];
        let nonce_bytes = &block[LOGICAL_PAGE_SIZE..LOGICAL_PAGE_SIZE + NONCE_SIZE];
        let tag = &block[LOGICAL_PAGE_SIZE + NONCE_SIZE..];

        let mut ct_with_tag = Vec::with_capacity(LOGICAL_PAGE_SIZE + TAG_SIZE);
        ct_with_tag.extend_from_slice(ciphertext_part);
        ct_with_tag.extend_from_slice(tag);

        let nonce = chacha20poly1305::Nonce::try_from(nonce_bytes)
            .map_err(|_| io::Error::other("invalid nonce length"))?;
        let aad = page_no.to_le_bytes();
        let payload = Payload {
            msg: &ct_with_tag,
            aad: &aad,
        };

        let pt = match self {
            Self::ChaCha(c) => c.decrypt(&nonce, payload),
            Self::Aes(c) => c.decrypt(&nonce, payload),
        }
        .map_err(|_| io::Error::other("decryption failed"))?;

        let mut result = [0u8; LOGICAL_PAGE_SIZE];
        result.copy_from_slice(&pt);
        Ok(result)
    }

    /// Read and decrypt physical page `page_no`, or return zeros if it lies
    /// past the end of the file.
    fn load_page<S: PageStore>(
        &self,
        store: &mut S,
        page_no: usize,
    ) -> io::Result<[u8; LOGICAL_PAGE_SIZE]> {
        let physical_offset = (page_no * PHYSICAL_PAGE_SIZE) as u64;
        if physical_offset >= store.len()? {
            return Ok([0u8; LOGICAL_PAGE_SIZE]);
        }
        let mut block = [0u8; PHYSICAL_PAGE_SIZE];
        store.read_exact_at(physical_offset, &mut block)?;
        self.decrypt_page(page_no as u64, &block)
    }

    /// Read `data.len()` logical bytes starting at logical `offset`.
    /// Bytes past the end of the file read as zeros.
    pub(crate) fn read_at<S: PageStore>(
        &self,
        store: &mut S,
        offset: usize,
        data: &mut [u8],
    ) -> io::Result<usize> {
        for chunk in page_chunks(offset, data.len()) {
            let page = self.load_page(store, chunk.page_no)?;
            data[chunk.buf_pos..chunk.buf_pos + chunk.len]
                .copy_from_slice(&page[chunk.intra..chunk.intra + chunk.len]);
        }
        Ok(data.len())
    }

    /// Write `data` at logical `offset`, re-encrypting every touched page.
    pub(crate) fn write_at<S: PageStore>(
        &self,
        store: &mut S,
        offset: usize,
        data: &[u8],
    ) -> io::Result<usize> {
        for chunk in page_chunks(offset, data.len()) {
            let mut page = if chunk.len == LOGICAL_PAGE_SIZE {
                [0u8; LOGICAL_PAGE_SIZE]
            } else {
                self.load_page(store, chunk.page_no)?
            };
            page[chunk.intra..chunk.intra + chunk.len]
                .copy_from_slice(&data[chunk.buf_pos..chunk.buf_pos + chunk.len]);

            let block = self.encrypt_page(chunk.page_no as u64, &page)?;
            let physical_offset = (chunk.page_no * PHYSICAL_PAGE_SIZE) as u64;
            store.write_all_at(physical_offset, &block)?;
        }
        Ok(data.len())
    }
}

/// Logical size of an encrypted store: whole physical pages × logical page size.
pub(crate) fn logical_size<S: PageStore + ?Sized>(store: &S) -> io::Result<u64> {
    let phys = store.len()?;
    Ok((phys / PHYSICAL_PAGE_SIZE as u64) * LOGICAL_PAGE_SIZE as u64)
}

/// Truncate an encrypted store to hold `logical_size` bytes (rounded up to a page).
pub(crate) fn truncate<S: PageStore + ?Sized>(store: &mut S, logical_size: usize) -> io::Result<()> {
    let num_pages = logical_size.div_ceil(LOGICAL_PAGE_SIZE);
    store.set_len((num_pages * PHYSICAL_PAGE_SIZE) as u64)
}

/// The part of one logical page touched by a byte-range access.
struct PageChunk {
    page_no: usize,
    /// Offset within the page.
    intra: usize,
    /// Offset within the caller's buffer.
    buf_pos: usize,
    len: usize,
}

/// Split the logical range `[offset, offset + len)` into per-page chunks.
fn page_chunks(offset: usize, len: usize) -> impl Iterator<Item = PageChunk> {
    let mut buf_pos = 0usize;
    iter::from_fn(move || {
        if buf_pos >= len {
            return None;
        }
        let logical_off = offset + buf_pos;
        let intra = logical_off % LOGICAL_PAGE_SIZE;
        let take = (len - buf_pos).min(LOGICAL_PAGE_SIZE - intra);
        let chunk = PageChunk {
            page_no: logical_off / LOGICAL_PAGE_SIZE,
            intra,
            buf_pos,
            len: take,
        };
        buf_pos += take;
        Some(chunk)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::path::PathBuf;

    fn temp_file(name: &str) -> (PathBuf, File) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
        let _ = fs::remove_file(&path);
        let f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        (path, f)
    }

    #[test]
    fn page_chunks_split_on_boundaries() {
        let chunks: Vec<_> = page_chunks(4000, 5000)
            .map(|c| (c.page_no, c.intra, c.buf_pos, c.len))
            .collect();
        assert_eq!(
            chunks,
            vec![(0, 4000, 0, 96), (1, 0, 96, 4096), (2, 0, 4192, 808)]
        );
        assert_eq!(page_chunks(0, 0).count(), 0);
    }

    #[test]
    fn unaligned_round_trip_and_tamper_detection() {
        for alg in [
            CipherAlgorithm::ChaCha20Poly1305,
            CipherAlgorithm::Aes256Gcm,
        ] {
            let (path, mut f) = temp_file(&format!(".test-page-cipher-{:?}", alg));
            let cipher = ActiveCipher::from_key(alg, &[7u8; 32]);
            let data: Vec<u8> = (0..9000u32).map(|i| i as u8).collect();

            assert_eq!(cipher.write_at(&mut f, 100, &data).unwrap(), data.len());
            assert_eq!(logical_size(&f).unwrap(), 3 * LOGICAL_PAGE_SIZE as u64);

            let mut out = vec![0u8; data.len()];
            cipher.read_at(&mut f, 100, &mut out).unwrap();
            assert_eq!(out, data);

            // Past EOF reads as zeros.
            let mut tail = [1u8; 16];
            cipher
                .read_at(&mut f, 10 * LOGICAL_PAGE_SIZE, &mut tail)
                .unwrap();
            assert_eq!(tail, [0u8; 16]);

            // Wrong key cannot read.
            let wrong = ActiveCipher::from_key(alg, &[8u8; 32]);
            assert!(wrong.read_at(&mut f, 0, &mut out).is_err());

            truncate(&mut f, 1).unwrap();
            assert_eq!(logical_size(&f).unwrap(), LOGICAL_PAGE_SIZE as u64);

            drop(f);
            let _ = fs::remove_file(path);
        }
    }
}
