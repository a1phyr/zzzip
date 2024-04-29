//! Possible ZIP compression methods.

use std::{fmt, io};

/// Identifies the storage format used to compress a file within a ZIP archive.
///
/// Each file's compression method is stored alongside it, allowing the
/// contents to be read without context.
///
/// When creating ZIP files, you may choose the method to use with
/// [`crate::write::FileOptions::compression_method`]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CompressionMethod(pub(crate) u16);

#[allow(missing_docs)]
/// All compression methods defined for the ZIP format
impl CompressionMethod {
    pub const STORE: Self = Self(0);
    pub const SHRINK: Self = Self(1);
    pub const REDUCE_1: Self = Self(2);
    pub const REDUCE_2: Self = Self(3);
    pub const REDUCE_3: Self = Self(4);
    pub const REDUCE_4: Self = Self(5);
    pub const IMPLODE: Self = Self(6);
    pub const DEFLATE: Self = Self(8);
    pub const DEFLATE64: Self = Self(9);
    pub const PKWARE_IMPLODE: Self = Self(10);
    pub const BZIP2: Self = Self(12);
    pub const LZMA: Self = Self(14);
    pub const IBM_ZOS_CMPSC: Self = Self(16);
    pub const IBM_TERSE: Self = Self(18);
    pub const ZSTD_DEPRECATED: Self = Self(20);
    pub const ZSTD: Self = Self(93);
    pub const MP3: Self = Self(94);
    pub const XZ: Self = Self(95);
    pub const JPEG: Self = Self(96);
    pub const WAVPACK: Self = Self(97);
    pub const PPMD: Self = Self(98);
    pub const AES: Self = Self(99);
}

impl CompressionMethod {
    pub fn is_supported(self) -> bool {
        SUPPORTED_COMPRESSION_METHODS.contains(&self)
    }

    pub fn decompress<R: io::BufRead>(self, reader: R) -> Decompressor<R> {
        let inner = match self {
            CompressionMethod::STORE => DecompressorInner::Store(reader),
            #[cfg(feature = "deflate-any")]
            CompressionMethod::DEFLATE => {
                DecompressorInner::Deflate(flate2::bufread::DeflateDecoder::new(reader))
            }
            #[cfg(feature = "bzip2")]
            CompressionMethod::BZIP2 => {
                DecompressorInner::Bzip2(bzip2::bufread::BzDecoder::new(reader))
            }
            #[cfg(feature = "lzma")]
            CompressionMethod::LZMA => {
                DecompressorInner::Lzma(xz2::bufread::XzDecoder::new(reader))
            }
            #[cfg(feature = "zstd")]
            CompressionMethod::ZSTD => {
                DecompressorInner::Zstd(zstd::Decoder::with_buffer(reader).unwrap())
            }
            _ => panic!("Compression method not supported"),
        };
        Decompressor { inner }
    }

    pub fn compress<W: io::Write>(self, writer: W, level: Option<u32>) -> Compressor<W> {
        let inner = match self {
            CompressionMethod::STORE => CompressorInner::Store(writer),
            #[cfg(feature = "deflate-any")]
            CompressionMethod::DEFLATE => {
                let level = match level {
                    Some(l) => flate2::Compression::new(l),
                    None => flate2::Compression::default(),
                };
                CompressorInner::Deflate(flate2::write::DeflateEncoder::new(writer, level))
            }
            #[cfg(feature = "bzip2")]
            CompressionMethod::BZIP2 => {
                let level = match level {
                    Some(l) => bzip2::Compression::new(l),
                    None => bzip2::Compression::default(),
                };
                CompressorInner::Bzip2(bzip2::write::BzEncoder::new(writer, level))
            }
            #[cfg(feature = "lzma")]
            CompressionMethod::LZMA => {
                let level = level.unwrap_or(6) as u32;
                CompressorInner::Lzma(xz2::write::XzEncoder::new(writer, level))
            }
            #[cfg(feature = "zstd")]
            CompressionMethod::ZSTD => {
                let level = level.unwrap_or(0) as i32;
                CompressorInner::Zstd(zstd::Encoder::new(writer, level).unwrap())
            }
            _ => panic!("Compression method not supported"),
        };
        Compressor { inner }
    }
}

impl From<u16> for CompressionMethod {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<CompressionMethod> for u16 {
    fn from(value: CompressionMethod) -> Self {
        value.0
    }
}

impl fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Just duplicate what the Debug format looks like, i.e, the enum key:
        write!(f, "{self:?}")
    }
}

/// The compression methods which have been implemented.
pub const SUPPORTED_COMPRESSION_METHODS: &[CompressionMethod] = &[
    CompressionMethod::STORE,
    #[cfg(feature = "deflate-any")]
    CompressionMethod::DEFLATE,
    #[cfg(feature = "bzip2")]
    CompressionMethod::BZIP2,
    #[cfg(feature = "lzma")]
    CompressionMethod::LZMA,
    #[cfg(feature = "zstd")]
    CompressionMethod::ZSTD,
];

pub struct Decompressor<R: io::BufRead> {
    inner: DecompressorInner<R>,
}

enum DecompressorInner<R: io::BufRead> {
    Store(R),
    #[cfg(feature = "deflate-any")]
    Deflate(flate2::bufread::DeflateDecoder<R>),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::bufread::BzDecoder<R>),
    #[cfg(feature = "lzma")]
    Lzma(xz2::bufread::XzDecoder<R>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::Decoder<'static, R>),
}

impl<R: io::BufRead> io::Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            DecompressorInner::Store(r) => r.read(buf),
            #[cfg(feature = "deflate-any")]
            DecompressorInner::Deflate(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            DecompressorInner::Bzip2(r) => r.read(buf),
            #[cfg(feature = "lzma")]
            DecompressorInner::Lzma(r) => r.read(buf),
            #[cfg(feature = "zstd")]
            DecompressorInner::Zstd(r) => r.read(buf),
        }
    }
}

impl<R: io::BufRead> Decompressor<R> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> R {
        match self.inner {
            DecompressorInner::Store(r) => r,
            #[cfg(feature = "deflate-any")]
            DecompressorInner::Deflate(r) => r.into_inner(),
            #[cfg(feature = "bzip2")]
            DecompressorInner::Bzip2(r) => r.into_inner(),
            #[cfg(feature = "lzma")]
            DecompressorInner::Lzma(r) => r.into_inner(),
            #[cfg(feature = "zstd")]
            DecompressorInner::Zstd(r) => r.finish(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match &mut self.inner {
            DecompressorInner::Store(r) => r,
            #[cfg(feature = "deflate-any")]
            DecompressorInner::Deflate(r) => r.get_mut(),
            #[cfg(feature = "bzip2")]
            DecompressorInner::Bzip2(r) => r.get_mut(),
            #[cfg(feature = "lzma")]
            DecompressorInner::Lzma(r) => r.get_mut(),
            #[cfg(feature = "zstd")]
            DecompressorInner::Zstd(r) => r.get_mut(),
        }
    }
}

pub struct Compressor<W: io::Write> {
    inner: CompressorInner<W>,
}

enum CompressorInner<W: io::Write> {
    Store(W),
    #[cfg(feature = "deflate-any")]
    Deflate(flate2::write::DeflateEncoder<W>),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::write::BzEncoder<W>),
    #[cfg(feature = "lzma")]
    Lzma(xz2::write::XzEncoder<W>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::Encoder<'static, W>),
}

impl<W: io::Write> Compressor<W> {
    pub fn try_finish(&mut self) -> io::Result<()> {
        match &mut self.inner {
            CompressorInner::Store(_) => Ok(()),
            #[cfg(feature = "deflate-any")]
            CompressorInner::Deflate(w) => w.try_finish(),
            #[cfg(feature = "bzip2")]
            CompressorInner::Bzip2(w) => w.try_finish(),
            #[cfg(feature = "lzma")]
            CompressorInner::Lzma(w) => w.try_finish(),
            #[cfg(feature = "zstd")]
            CompressorInner::Zstd(w) => w.do_finish(),
        }
    }

    pub fn finish(self) -> io::Result<W> {
        match self.inner {
            CompressorInner::Store(w) => Ok(w),
            #[cfg(feature = "deflate-any")]
            CompressorInner::Deflate(w) => w.finish(),
            #[cfg(feature = "bzip2")]
            CompressorInner::Bzip2(w) => w.finish(),
            #[cfg(feature = "lzma")]
            CompressorInner::Lzma(w) => w.finish(),
            #[cfg(feature = "zstd")]
            CompressorInner::Zstd(w) => w.finish(),
        }
    }
}

impl<W: io::Write> io::Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            CompressorInner::Store(w) => w.write(buf),
            #[cfg(feature = "deflate-any")]
            CompressorInner::Deflate(w) => w.write(buf),
            #[cfg(feature = "bzip2")]
            CompressorInner::Bzip2(w) => w.write(buf),
            #[cfg(feature = "lzma")]
            CompressorInner::Lzma(w) => w.write(buf),
            #[cfg(feature = "zstd")]
            CompressorInner::Zstd(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            CompressorInner::Store(w) => w.flush(),
            #[cfg(feature = "deflate-any")]
            CompressorInner::Deflate(w) => w.flush(),
            #[cfg(feature = "bzip2")]
            CompressorInner::Bzip2(w) => w.flush(),
            #[cfg(feature = "lzma")]
            CompressorInner::Lzma(w) => w.flush(),
            #[cfg(feature = "zstd")]
            CompressorInner::Zstd(w) => w.flush(),
        }
    }
}
