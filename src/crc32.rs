//! Helper module to compute a CRC32 checksum

use std::io;
use std::io::prelude::*;

use crc32fast::Hasher;

#[cold]
fn invalid_checksum() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid checksum")
}

/// Reader that validates the CRC32 when it reaches the EOF.
pub struct Crc32Reader<R> {
    inner: R,
    hasher: Hasher,
    check: u32,
    enabled: bool,
}

impl<R> Crc32Reader<R> {
    /// Get a new Crc32Reader which checks the inner reader against checksum.
    /// The check is disabled if `ae2_encrypted == true`.
    pub(crate) fn new(inner: R, checksum: u32, enabled: bool) -> Crc32Reader<R> {
        Crc32Reader {
            inner,
            hasher: Hasher::new(),
            check: checksum,
            enabled,
        }
    }

    fn check_matches(&self) -> bool {
        self.check == self.hasher.clone().finalize()
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Crc32Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;

        if self.enabled {
            self.hasher.update(&buf[..n]);
            if n == 0 && !buf.is_empty() && !self.check_matches() {
                return Err(invalid_checksum());
            }
        };

        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let start = buf.len();

        let n = self.inner.read_to_end(buf)?;

        if self.enabled {
            self.hasher.update(&buf[start..]);
            if !self.check_matches() {
                return Err(invalid_checksum());
            }
        }

        Ok(n)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        let start = buf.len();

        let n = self.inner.read_to_string(buf)?;

        if self.enabled {
            self.hasher.update(&buf.as_bytes()[start..]);
            if !self.check_matches() {
                return Err(invalid_checksum());
            }
        }

        Ok(n)
    }
}

pub struct Crc32Writer<W> {
    inner: W,
    hasher: Hasher,
}

impl<W> Crc32Writer<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
        }
    }

    pub fn finalize(&self) -> u32 {
        self.hasher.clone().finalize()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: io::Write> io::Write for Crc32Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_empty_reader() {
        let data: &[u8] = b"";
        let mut buf = [0; 1];

        let mut reader = Crc32Reader::new(data, 0, true);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);

        let mut reader = Crc32Reader::new(data, 1, true);
        assert!(reader
            .read(&mut buf)
            .unwrap_err()
            .to_string()
            .contains("invalid checksum"));
    }

    #[test]
    fn test_byte_by_byte() {
        let data: &[u8] = b"1234";
        let mut buf = [0; 1];

        let mut reader = Crc32Reader::new(data, 0x9be3e0a3, true);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        // Can keep reading 0 bytes after the end
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_zero_read() {
        let data: &[u8] = b"1234";
        let mut buf = [0; 5];

        let mut reader = Crc32Reader::new(data, 0x9be3e0a3, true);
        assert_eq!(reader.read(&mut buf[..0]).unwrap(), 0);
        assert_eq!(reader.read(&mut buf).unwrap(), 4);
    }
}
