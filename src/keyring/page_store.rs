/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Byte-addressable storage behind an encrypted page file.
//!
//! The cipher in [`page_cipher`](super::page_cipher) works on pages; this
//! module supplies the bytes. Native keyrings use a file, browser keyrings a
//! buffer or an OPFS handle.

#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Byte-addressable storage behind an encrypted page file.
///
/// Implementations are a native file, an in-memory buffer and a browser OPFS
/// sync access handle. `len` and `set_len` work in physical bytes; the cipher
/// translates to logical pages.
pub(crate) trait PageStore {
    /// Physical size in bytes.
    fn len(&self) -> io::Result<u64>;
    /// Read exactly `buf.len()` bytes at `offset`, zero-filling past the end.
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Write all of `buf` at `offset`, growing the store if needed.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;
    /// Resize the store, zero-filling any gap.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
    /// Flush writes to durable storage. Buffers have nothing to flush.
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PageStore for File {
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset))?;
        self.write_all(buf)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        File::set_len(self, len)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

/// A [`PageStore`] held entirely in memory.
#[cfg(feature = "turso")]
#[derive(Default)]
pub(crate) struct MemPages(Vec<u8>);

#[cfg(feature = "turso")]
impl MemPages {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "turso")]
impl PageStore for MemPages {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        if start >= self.0.len() {
            buf.fill(0);
            return Ok(());
        }
        let available = self.0.len() - start;
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        buf[n..].fill(0);
        let _ = end;
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let start =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        self.0[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.0.resize(len, 0);
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}
