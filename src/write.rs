//! Types for creating ZIP archives

use crate::compression::{CompressionMethod, Compressor};
use crate::crc32::Crc32Writer;
use crate::read::{central_header_to_zip_file, ZipArchive, ZipFile};
use crate::result::{ZipError, ZipResult};
use crate::spec;
use crate::types::{AtomicU64, DateTime, RawZipFileMetadata, System, DEFAULT_VERSION};
use crate::utils::{ReadLE, WriteLE};
use crc32fast::Hasher;
use std::default::Default;
use std::io;
use std::io::prelude::*;

struct BytesCounter<W> {
    inner: W,
    count: u64,
    large: bool,
}

impl<W> BytesCounter<W> {
    fn new(inner: W, large: bool) -> Self {
        Self {
            inner,
            count: 0,
            large,
        }
    }
}

impl<W: io::Write> io::Write for BytesCounter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;

        self.count += n as u64;
        if !self.large && self.count > spec::ZIP64_BYTES_THR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Large file option has not been set",
            ));
        }

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// ZIP archive generator
///
/// Handles the bookkeeping involved in building an archive, and provides an
/// API to edit its contents.
///
/// ```
/// # fn doit() -> zip::result::ZipResult<()>
/// # {
/// # use zip::ZipWriter;
/// use std::io::Write;
/// use zip::write::FileOptions;
///
/// // We use a buffer here, though you'd normally use a `File`
/// let mut buf = [0; 65536];
/// let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf[..]));
///
/// let options = zip::write::FileOptions {
///     compression_method: zip::CompressionMethod::STORE,
///     ..Default::default()
/// };
/// let mut file = zip.start_file("hello_world.txt", options)?;
/// file.write(b"Hello, World!")?;
/// file.finish()?;
///
/// // Apply the changes you've made.
/// // Dropping the `ZipWriter` will have the same effect, but may silently fail
/// zip.finish()?;
///
/// # Ok(())
/// # }
/// # doit().unwrap();
/// ```
pub struct ZipWriter<W: io::Write + io::Seek> {
    writer: Option<W>,

    files: Vec<RawZipFileMetadata>,
    stats: ZipWriterStats,
    comment: Vec<u8>,

    writing_file: bool,
}

pub struct ExtraDataWriter<'a, W: io::Write> {
    writer: &'a mut W,
    data: &'a mut RawZipFileMetadata,
}

impl<'a, W: io::Write + io::Seek> ExtraDataWriter<'a, W> {
    pub fn original_data_start(&self) -> u64 {
        self.data.data_start.load()
    }

    /// End extra data and start file data.
    fn finish_raw(&mut self) -> io::Result<()> {
        validate_extra_data(&self.data)?;

        // Append extra data to local file header and keep it for central file header.
        self.writer.write_all(&self.data.extra_field)?;

        // Update final `data_start`.
        let header_end = self.data.data_start.load() + self.data.extra_field.len() as u64;
        self.data.data_start.store(header_end);

        // Update extra field length in local file header.
        let extra_field_length =
            if self.data.large_file { 20 } else { 0 } + self.data.extra_field.len() as u16;
        self.writer
            .seek(io::SeekFrom::Start(self.data.header_start + 28))?;
        self.writer.write_u16(extra_field_length)?;
        self.writer.seek(io::SeekFrom::Start(header_end))?;

        Ok(())
    }

    /// End extra data and start file data.
    pub fn finish(mut self) -> io::Result<ZipFileWriter<'a, W>> {
        self.finish_raw()?;

        Ok(ZipFileWriter::new(self.writer, self.data))
    }

    /// End local and start central extra data.
    pub fn write_central_extra_data(mut self) -> io::Result<CentralExtraDataWriter<'a, W>> {
        self.finish_raw()?;

        self.data.extra_field.clear();
        Ok(CentralExtraDataWriter {
            writer: self.writer,
            data: self.data,
        })
    }
}

impl<W: io::Write> io::Write for ExtraDataWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.extra_field.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct CentralExtraDataWriter<'a, W: io::Write> {
    writer: &'a mut W,
    data: &'a mut RawZipFileMetadata,
}

impl<'a, W: io::Write + io::Seek> CentralExtraDataWriter<'a, W> {
    pub fn data_start(&self) -> u64 {
        self.data.data_start.load()
    }

    pub fn finish(self) -> io::Result<ZipFileWriter<'a, W>> {
        validate_extra_data(&self.data)?;

        Ok(ZipFileWriter::new(self.writer, self.data))
    }
}

impl<W: io::Write> io::Write for CentralExtraDataWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.extra_field.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct ZipFileWriter<'a, W: io::Write> {
    writer: BytesCounter<Crc32Writer<Compressor<BytesCounter<&'a mut W>>>>,
    data: &'a mut RawZipFileMetadata,

    writing_raw: bool,
}

impl<'a, W: io::Write + io::Seek> ZipFileWriter<'a, W> {
    fn new(writer: &'a mut W, data: &'a mut RawZipFileMetadata) -> Self {
        let writer = data.compression_method.compress(
            BytesCounter::new(writer, data.large_file),
            data.compression_level,
        );
        let writer = BytesCounter::new(Crc32Writer::new(writer), data.large_file);

        Self {
            writer,
            data,
            writing_raw: false,
        }
    }

    pub fn finish(self) -> io::Result<()> {
        if !self.writing_raw {
            self.data.uncompressed_size = self.writer.count;
            self.data.crc32 = self.writer.inner.finalize();

            let mut writer = self.writer.inner.into_inner().finish()?;

            self.data.compressed_size = writer.count;

            let file_end = writer.inner.stream_position()?;
            update_local_file_header(&mut writer.inner, &self.data)?;
            writer.inner.seek(io::SeekFrom::Start(file_end))?;
        }

        Ok(())
    }
}

impl<W: io::Write> io::Write for ZipFileWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Default)]
struct ZipWriterStats {
    hasher: Hasher,
    start: u64,
    bytes_written: u64,
}

struct ZipRawValues {
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
}

/// Metadata for a file to be written
#[derive(Copy, Clone)]
pub struct FileOptions {
    /// Set the compression method for the new file
    ///
    /// The default is `CompressionMethod::Deflated`. If the deflate compression feature is
    /// disabled, `CompressionMethod::Stored` becomes the default.
    pub compression_method: CompressionMethod,

    /// Set the compression level for the new file
    ///
    /// `None` value specifies default compression level.
    ///
    /// Range of values depends on compression method:
    /// * `Deflated`: 0 - 9. Default is 6
    /// * `Bzip2`: 0 - 9. Default is 6
    /// * `Zstd`: 1 - 22, with zero being mapped to default level. Default is 3
    /// * others: only `None` is allowed
    pub compression_level: Option<u32>,

    /// Set the last modified time
    ///
    /// The default is the current timestamp if the 'time' feature is enabled, and 1980-01-01
    /// otherwise
    pub last_modified_time: DateTime,

    /// Set the permissions for the new file.
    ///
    /// The format is represented with unix-style permissions.
    /// The default is `0o644`, which represents `rw-r--r--` for files,
    /// and `0o755`, which represents `rwxr-xr-x` for directories.
    ///
    /// This method only preserves the file permissions bits (via a `& 0o777`) and discards
    /// higher file mode bits. So it cannot be used to denote an entry as a directory,
    /// symlink, or other special file type.
    pub permissions: Option<u32>,

    /// Set whether the new file's compressed and uncompressed size is less than 4 GiB.
    ///
    /// If set to `false` and the file exceeds the limit, an I/O error is thrown. If set to `true`,
    /// readers will require ZIP64 support and if the file does not exceed the limit, 20 B are
    /// wasted. The default is `false`.
    pub large_file: bool,
}

impl Default for FileOptions {
    /// Construct a new FileOptions object
    fn default() -> Self {
        let compression_method = if cfg!(feature = "deflate-any") {
            CompressionMethod::DEFLATE
        } else {
            CompressionMethod::STORE
        };

        Self {
            compression_method,
            compression_level: None,
            #[cfg(feature = "time")]
            last_modified_time: time::OffsetDateTime::now_utc()
                .try_into()
                .unwrap_or_default(),
            #[cfg(not(feature = "time"))]
            last_modified_time: DateTime::default(),
            permissions: None,
            large_file: false,
        }
    }
}

impl<A: Read + Write + io::Seek> ZipWriter<A> {
    /// Initializes the archive from an existing ZIP archive, making it ready for append.
    pub fn new_append(mut readwriter: A) -> ZipResult<ZipWriter<A>> {
        let (footer, cde_start_pos) = spec::CentralDirectoryEnd::find_and_parse(&mut readwriter)?;

        if footer.disk_number != footer.disk_with_central_directory {
            return Err(ZipError::UnsupportedArchive(
                "Support for multi-disk files is not implemented",
            ));
        }

        let (archive_offset, directory_start, number_of_files) = ZipArchive::get_directory_counts(
            &mut io::BufReader::new(&mut readwriter),
            &footer,
            cde_start_pos,
        )?;

        if readwriter
            .seek(io::SeekFrom::Start(directory_start))
            .is_err()
        {
            return Err(ZipError::InvalidArchive(
                "Could not seek to start of central directory",
            ));
        }

        let files = (0..number_of_files)
            .map(|_| central_header_to_zip_file(&mut readwriter, archive_offset))
            .collect::<Result<Vec<_>, _>>()?;

        let _ = readwriter.seek(io::SeekFrom::Start(directory_start)); // seek directory_start to overwrite it

        Ok(ZipWriter {
            writer: Some(readwriter),
            files,
            stats: Default::default(),
            comment: footer.zip_file_comment,

            writing_file: false,
        })
    }
}

impl<W: io::Write + io::Seek> ZipWriter<W> {
    /// Initializes the archive.
    ///
    /// Before writing to this object, the [`ZipWriter::start_file`] function should be called.
    pub fn new(writer: W) -> ZipWriter<W> {
        ZipWriter {
            writer: Some(writer),
            files: Vec::new(),
            stats: Default::default(),
            comment: Vec::new(),
            writing_file: false,
        }
    }

    /// Set ZIP archive comment.
    pub fn set_comment(&mut self, comment: String) {
        self.set_raw_comment(comment.into())
    }

    /// Set ZIP archive comment.
    ///
    /// This sets the raw bytes of the comment. The comment
    /// is typically expected to be encoded in UTF-8
    pub fn set_raw_comment(&mut self, comment: Vec<u8>) {
        self.comment = comment;
    }

    /// Start a new file for with the requested options.
    fn start_entry(
        &mut self,
        file_name: String,
        options: FileOptions,
        raw_values: Option<ZipRawValues>,
    ) -> io::Result<(&mut W, &mut RawZipFileMetadata)> {
        let writer = self.writer.as_mut().unwrap();

        let raw_values = raw_values.unwrap_or(ZipRawValues {
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
        });

        let header_start = writer.stream_position()?;

        let permissions = options.permissions.unwrap();
        let mut file = RawZipFileMetadata {
            system: System::Unix,
            version_made_by: DEFAULT_VERSION,
            encrypted: false,
            using_data_descriptor: false,
            compression_method: options.compression_method,
            compression_level: options.compression_level,
            last_modified_time: options.last_modified_time,
            crc32: raw_values.crc32,
            compressed_size: raw_values.compressed_size,
            uncompressed_size: raw_values.uncompressed_size,
            file_name,
            file_name_raw: Vec::new(), // Never used for saving
            extra_field: Vec::new(),
            file_comment: String::new(),
            header_start,
            data_start: AtomicU64::new(0),
            central_header_start: 0,
            external_attributes: permissions << 16,
            large_file: options.large_file,
            aes_mode: None,
        };
        write_local_file_header(writer, &file)?;

        let header_end = writer.stream_position()?;
        self.stats.start = header_end;
        *file.data_start.get_mut() = header_end;

        self.stats.bytes_written = 0;
        self.stats.hasher = Hasher::new();

        self.files.push(file);
        let data = self.files.last_mut().unwrap();

        Ok((writer, data))
    }

    /// Create a file in the archive and start writing its' contents.
    ///
    /// The data should be written using the [`io::Write`] implementation on this [`ZipWriter`]
    pub fn start_file<S>(
        &mut self,
        name: S,
        mut options: FileOptions,
    ) -> io::Result<ZipFileWriter<'_, W>>
    where
        S: Into<String>,
    {
        let perms = options.permissions.get_or_insert(0o644);
        *perms &= 0o777;
        *perms |= 0o100000;

        let (writer, data) = self.start_entry(name.into(), options, None)?;
        Ok(ZipFileWriter::new(writer, data))
    }

    /// Starts a file, taking a Path as argument.
    ///
    /// This function ensures that the '/' path separator is used. It also ignores all non 'Normal'
    /// Components, such as a starting '/' or '..' and '.'.
    #[deprecated(
        since = "0.5.7",
        note = "by stripping `..`s from the path, the meaning of paths can change. Use `start_file` instead."
    )]
    pub fn start_file_from_path(
        &mut self,
        path: &std::path::Path,
        options: FileOptions,
    ) -> io::Result<ZipFileWriter<'_, W>> {
        self.start_file(path_to_string(path), options)
    }

    /// Create an aligned file in the archive and start writing its' contents.
    ///
    /// Returns the number of padding bytes required to align the file.
    ///
    /// The data should be written using the [`io::Write`] implementation on this [`ZipWriter`]
    pub fn start_file_aligned<S>(
        &mut self,
        name: S,
        options: FileOptions,
        align: u16,
    ) -> io::Result<ZipFileWriter<'_, W>>
    where
        S: Into<String>,
    {
        let mut writer = self.start_file_with_extra_data(name, options)?;
        let data_start = writer.original_data_start();

        let align = align as u64;
        if align > 1 && data_start % align != 0 {
            let pad_length = (align - (data_start + 4) % align) % align;
            let pad = vec![0; pad_length as usize];
            writer.write_all(b"za")?; // 0x617a
            writer.write_u16(pad.len() as u16)?;
            writer.write_all(&pad)?;
        }

        let w = writer.finish()?;
        Ok(w)
    }

    /// Create a file in the archive and start writing its extra data first.
    ///
    /// Finish writing extra data and start writing file data with [`ZipWriter::end_extra_data`].
    /// Optionally, distinguish local from central extra data with
    /// [`ZipWriter::end_local_start_central_extra_data`].
    ///
    /// Returns the preliminary starting offset of the file data without any extra data allowing to
    /// align the file data by calculating a pad length to be prepended as part of the extra data.
    ///
    /// The data should be written using the [`io::Write`] implementation on this [`ZipWriter`]
    ///
    /// ```
    /// use byteorder::{LittleEndian, WriteBytesExt};
    /// use zip::{ZipArchive, ZipWriter, result::ZipResult};
    /// use zip::{write::FileOptions, CompressionMethod};
    /// use std::io::{Write, Cursor};
    ///
    /// # fn main() -> ZipResult<()> {
    /// let mut archive = Cursor::new(Vec::new());
    ///
    /// {
    ///     let mut zip = ZipWriter::new(&mut archive);
    ///     let options = FileOptions {
    ///         compression_method: CompressionMethod::STORE,
    ///         ..Default::default()
    ///     };
    ///
    ///     let mut extra = zip.start_file_with_extra_data("identical_extra_data.txt", options)?;
    ///     let extra_data = b"local and central extra data";
    ///     extra.write_u16::<LittleEndian>(0xbeef)?;
    ///     extra.write_u16::<LittleEndian>(extra_data.len() as u16)?;
    ///     extra.write_all(extra_data)?;
    ///     let mut file = extra.finish()?;
    ///     file.write_all(b"file data")?;
    ///     file.finish()?;
    ///
    ///     let mut local_extra = zip.start_file_with_extra_data("different_extra_data.txt", options)?;
    ///     let extra_data = b"local extra data";
    ///     local_extra.write_u16::<LittleEndian>(0xbeef)?;
    ///     local_extra.write_u16::<LittleEndian>(extra_data.len() as u16)?;
    ///     local_extra.write_all(extra_data)?;
    ///     let data_start = local_extra.original_data_start() as usize + 4 + extra_data.len() + 4;
    ///     let align = 64;
    ///     let pad_length = (align - data_start % align) % align;
    ///     assert_eq!(pad_length, 19);
    ///     local_extra.write_u16::<LittleEndian>(0xdead)?;
    ///     local_extra.write_u16::<LittleEndian>(pad_length as u16)?;
    ///     local_extra.write_all(&vec![0; pad_length])?;
    ///     let mut central_extra = local_extra.write_central_extra_data()?;
    ///     let data_start = central_extra.data_start();
    ///     assert_eq!(data_start as usize % align, 0);
    ///     let extra_data = b"central extra data";
    ///     central_extra.write_u16::<LittleEndian>(0xbeef)?;
    ///     central_extra.write_u16::<LittleEndian>(extra_data.len() as u16)?;
    ///     central_extra.write_all(extra_data)?;
    ///     let mut file = central_extra.finish()?;
    ///     file.write_all(b"file data")?;
    ///     file.finish()?;
    ///
    ///     zip.finish()?;
    /// }
    ///
    /// let mut zip = ZipArchive::new(archive)?;
    /// assert_eq!(&zip.by_index(0)?.extra_data()[4..], b"local and central extra data");
    /// assert_eq!(&zip.by_index(1)?.extra_data()[4..], b"central extra data");
    /// # Ok(())
    /// # }
    /// ```
    pub fn start_file_with_extra_data<S>(
        &mut self,
        name: S,
        mut options: FileOptions,
    ) -> io::Result<ExtraDataWriter<'_, W>>
    where
        S: Into<String>,
    {
        let perms = options.permissions.get_or_insert(0o644);
        *perms &= 0o777;
        *perms |= 0o100000;

        let (writer, data) = self.start_entry(name.into(), options, None)?;
        Ok(ExtraDataWriter { writer, data })
    }

    /// Add a new file using the already compressed data from a ZIP file being read and renames it, this
    /// allows faster copies of the `ZipFile` since there is no need to decompress and compress it again.
    /// Any `ZipFile` metadata is copied and not checked, for example the file CRC.

    /// ```no_run
    /// use std::fs::File;
    /// use std::io;
    /// use zip::{ZipArchive, ZipWriter};
    ///
    /// fn copy_rename<R, W>(
    ///     src: &mut ZipArchive<R>,
    ///     dst: &mut ZipWriter<W>,
    /// ) -> io::Result<()>
    /// where
    ///     R: io::BufRead + io::Seek,
    ///     W: io::Write + io::Seek,
    /// {
    ///     // Retrieve file entry by name
    ///     let file = src.by_name("src_file.txt")?;
    ///
    ///     // Copy and rename the previously obtained file entry to the destination zip archive
    ///     dst.raw_copy_file_rename(file, "new_name.txt")?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn raw_copy_file_rename<S>(
        &mut self,
        file: ZipFile<impl BufRead + Seek>,
        name: S,
    ) -> io::Result<()>
    where
        S: Into<String>,
    {
        let data = file.metadata();

        let options = FileOptions {
            large_file: data.compressed_size().max(data.size()) > spec::ZIP64_BYTES_THR,
            last_modified_time: data.last_modified(),
            compression_method: data.compression_method(),
            permissions: data.unix_mode(),
            compression_level: None,
        };

        let raw_values = ZipRawValues {
            crc32: data.crc32(),
            compressed_size: data.compressed_size(),
            uncompressed_size: data.size(),
        };

        let (writer, _) = self.start_entry(name.into(), options, Some(raw_values))?;
        io::copy(&mut file.raw_reader(), writer)?;

        Ok(())
    }

    /// Add a new file using the already compressed data from a ZIP file being read, this allows faster
    /// copies of the `ZipFile` since there is no need to decompress and compress it again. Any `ZipFile`
    /// metadata is copied and not checked, for example the file CRC.
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io;
    /// use zip::{ZipArchive, ZipWriter};
    ///
    /// fn copy<R, W>(src: &mut ZipArchive<R>, dst: &mut ZipWriter<W>) -> io::Result<()>
    /// where
    ///     R: io::BufRead + io::Seek,
    ///     W: io::Write + io::Seek,
    /// {
    ///     // Retrieve file entry by name
    ///     let file = src.by_name("src_file.txt")?;
    ///
    ///     // Copy the previously obtained file entry to the destination zip archive
    ///     dst.raw_copy_file(file)?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn raw_copy_file(&mut self, file: ZipFile<impl BufRead + Seek>) -> io::Result<()> {
        let name = file.metadata().name().to_owned();
        self.raw_copy_file_rename(file, name)
    }

    /// Add a directory entry.
    ///
    /// As directories have no content, you must not call [`ZipWriter::write`] before adding a new file.
    pub fn add_directory<S>(&mut self, name: S, mut options: FileOptions) -> io::Result<()>
    where
        S: Into<String>,
    {
        let perms = options.permissions.get_or_insert(0o755);
        *perms &= 0o777;
        *perms |= 0o40000;

        options.compression_method = CompressionMethod::STORE;

        let name_as_string = name.into();
        // Append a slash to the filename if it does not end with it.
        let name_with_slash = match name_as_string.chars().last() {
            Some('/') | Some('\\') => name_as_string,
            _ => name_as_string + "/",
        };

        self.start_entry(name_with_slash, options, None)?;
        Ok(())
    }

    /// Add a directory entry, taking a Path as argument.
    ///
    /// This function ensures that the '/' path separator is used. It also ignores all non 'Normal'
    /// Components, such as a starting '/' or '..' and '.'.
    #[deprecated(
        since = "0.5.7",
        note = "by stripping `..`s from the path, the meaning of paths can change. Use `add_directory` instead."
    )]
    pub fn add_directory_from_path(
        &mut self,
        path: &std::path::Path,
        options: FileOptions,
    ) -> io::Result<()> {
        self.add_directory(path_to_string(path), options)
    }

    /// Add a symlink entry.
    ///
    /// The zip archive will contain an entry for path `name` which is a symlink to `target`.
    ///
    /// No validation or normalization of the paths is performed. For best results,
    /// callers should normalize `\` to `/` and ensure symlinks are relative to other
    /// paths within the zip archive.
    ///
    /// WARNING: not all zip implementations preserve symlinks on extract. Some zip
    /// implementations may materialize a symlink as a regular file, possibly with the
    /// content incorrectly set to the symlink target. For maximum portability, consider
    /// storing a regular file instead.
    pub fn add_symlink<N, T>(
        &mut self,
        name: N,
        target: T,
        mut options: FileOptions,
    ) -> io::Result<()>
    where
        N: Into<String>,
        T: AsRef<str>,
    {
        let perms = options.permissions.get_or_insert(0o777);
        *perms &= 0o777;
        *perms |= 0o120000;

        // The symlink target is stored as file content. And compressing the target path
        // likely wastes space. So always store.
        options.compression_method = CompressionMethod::STORE;

        let (writer, data) = self.start_entry(name.into(), options, None)?;

        let mut writer = ZipFileWriter::new(writer, data);
        writer.write_all(target.as_ref().as_bytes())?;
        writer.finish()?;

        Ok(())
    }

    fn finalize(&mut self) -> io::Result<()> {
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };

        let central_start = writer.stream_position()?;
        for file in &self.files {
            write_central_directory_header(writer, file)?;
        }
        let central_size = writer.stream_position()? - central_start;

        if self.files.len() > spec::ZIP64_ENTRY_THR
            || central_size.max(central_start) > spec::ZIP64_BYTES_THR
        {
            let zip64_footer = spec::Zip64CentralDirectoryEnd {
                version_made_by: DEFAULT_VERSION as u16,
                version_needed_to_extract: DEFAULT_VERSION as u16,
                disk_number: 0,
                disk_with_central_directory: 0,
                number_of_files_on_this_disk: self.files.len() as u64,
                number_of_files: self.files.len() as u64,
                central_directory_size: central_size,
                central_directory_offset: central_start,
            };

            zip64_footer.write_to(writer)?;

            let zip64_footer = spec::Zip64CentralDirectoryEndLocator {
                disk_with_central_directory: 0,
                end_of_central_directory_offset: central_start + central_size,
                number_of_disks: 1,
            };

            zip64_footer.write_to(writer)?;
        }

        let number_of_files = self.files.len().min(spec::ZIP64_ENTRY_THR) as u16;
        let footer = spec::CentralDirectoryEnd {
            disk_number: 0,
            disk_with_central_directory: 0,
            zip_file_comment: self.comment.clone(),
            number_of_files_on_this_disk: number_of_files,
            number_of_files,
            central_directory_size: central_size.min(spec::ZIP64_BYTES_THR) as u32,
            central_directory_offset: central_start.min(spec::ZIP64_BYTES_THR) as u32,
        };

        footer.write_to(writer)?;

        writer.flush()?;

        Ok(())
    }

    /// Finish the last file and write all other zip-structures
    ///
    /// This will return the writer, but one should normally not append any data to the end of the file.
    /// Note that the zipfile will also be finished on drop.
    pub fn finish(mut self) -> io::Result<W> {
        self.finalize()?;
        Ok(self.writer.take().unwrap())
    }
}

impl<W: io::Write + io::Seek> Drop for ZipWriter<W> {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

fn write_local_file_header<W: io::Write>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<()> {
    // local file header signature
    writer.write_u32(spec::LOCAL_FILE_HEADER_SIGNATURE)?;
    // version needed to extract
    writer.write_u16(file.version_needed())?;
    // general purpose bit flag
    let flag = if !file.file_name.is_ascii() {
        1u16 << 11
    } else {
        0
    } | if file.encrypted { 1u16 << 0 } else { 0 };
    writer.write_u16(flag)?;
    // Compression method
    writer.write_u16(file.compression_method.0)?;
    // last mod file time and last mod file date
    writer.write_u16(file.last_modified_time.timepart())?;
    writer.write_u16(file.last_modified_time.datepart())?;
    // crc-32
    writer.write_u32(file.crc32)?;
    // compressed size and uncompressed size
    if file.large_file {
        writer.write_u32(spec::ZIP64_BYTES_THR as u32)?;
        writer.write_u32(spec::ZIP64_BYTES_THR as u32)?;
    } else {
        writer.write_u32(file.compressed_size as u32)?;
        writer.write_u32(file.uncompressed_size as u32)?;
    }
    // file name length
    writer.write_u16(file.file_name.as_bytes().len() as u16)?;
    // extra field length
    let extra_field_length = if file.large_file { 20 } else { 0 } + file.extra_field.len() as u16;
    writer.write_u16(extra_field_length)?;
    // file name
    writer.write_all(file.file_name.as_bytes())?;
    // zip64 extra field
    if file.large_file {
        write_local_zip64_extra_field(writer, file)?;
    }

    Ok(())
}

fn update_local_file_header<W: io::Write + io::Seek>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<()> {
    const CRC32_OFFSET: u64 = 14;
    writer.seek(io::SeekFrom::Start(file.header_start + CRC32_OFFSET))?;
    writer.write_u32(file.crc32)?;
    if file.large_file {
        update_local_zip64_extra_field(writer, file)?;
    } else {
        // check compressed size as well as it can also be slightly larger than uncompressed size
        if file.compressed_size > spec::ZIP64_BYTES_THR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Large file option has not been set",
            ));
        }
        writer.write_u32(file.compressed_size as u32)?;
        // uncompressed size is already checked on write to catch it as soon as possible
        writer.write_u32(file.uncompressed_size as u32)?;
    }
    Ok(())
}

fn write_central_directory_header<W: io::Write>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<()> {
    // buffer zip64 extra field to determine its variable length
    let mut zip64_extra_field = [0; 28];
    let zip64_extra_field_length =
        write_central_zip64_extra_field(&mut zip64_extra_field.as_mut(), file)?;

    // central file header signature
    writer.write_u32(spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE)?;
    // version made by
    let version_made_by = (file.system as u16) << 8 | (file.version_made_by as u16);
    writer.write_u16(version_made_by)?;
    // version needed to extract
    writer.write_u16(file.version_needed())?;
    // general puprose bit flag
    let flag = if !file.file_name.is_ascii() {
        1u16 << 11
    } else {
        0
    } | if file.encrypted { 1u16 << 0 } else { 0 };
    writer.write_u16(flag)?;
    // compression method
    writer.write_u16(file.compression_method.0)?;
    // last mod file time + date
    writer.write_u16(file.last_modified_time.timepart())?;
    writer.write_u16(file.last_modified_time.datepart())?;
    // crc-32
    writer.write_u32(file.crc32)?;
    // compressed size
    writer.write_u32(file.compressed_size.min(spec::ZIP64_BYTES_THR) as u32)?;
    // uncompressed size
    writer.write_u32(file.uncompressed_size.min(spec::ZIP64_BYTES_THR) as u32)?;
    // file name length
    writer.write_u16(file.file_name.as_bytes().len() as u16)?;
    // extra field length
    writer.write_u16(zip64_extra_field_length + file.extra_field.len() as u16)?;
    // file comment length
    writer.write_u16(0)?;
    // disk number start
    writer.write_u16(0)?;
    // internal file attribytes
    writer.write_u16(0)?;
    // external file attributes
    writer.write_u32(file.external_attributes)?;
    // relative offset of local header
    writer.write_u32(file.header_start.min(spec::ZIP64_BYTES_THR) as u32)?;
    // file name
    writer.write_all(file.file_name.as_bytes())?;
    // zip64 extra field
    writer.write_all(&zip64_extra_field[..zip64_extra_field_length as usize])?;
    // extra field
    writer.write_all(&file.extra_field)?;
    // file comment
    // <none>

    Ok(())
}

fn validate_extra_data(file: &RawZipFileMetadata) -> io::Result<()> {
    let mut data = file.extra_field.as_slice();

    if data.len() > spec::ZIP64_ENTRY_THR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Extra data exceeds extra field",
        ));
    }

    while !data.is_empty() {
        let left = data.len();
        if left < 4 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Incomplete extra data header",
            ));
        }
        let kind = data.read_u16()?;
        let size = data.read_u16()? as usize;
        let left = left - 4;

        if kind == 0x0001 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No custom ZIP64 extra data allowed",
            ));
        }

        #[cfg(not(feature = "unreserved"))]
        {
            if kind <= 31 || EXTRA_FIELD_MAPPING.iter().any(|&mapped| mapped == kind) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Extra data header ID {kind:#06} requires crate feature \"unreserved\"",
                    ),
                ));
            }
        }

        if size > left {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Extra data size exceeds extra field",
            ));
        }

        data = &data[size..];
    }

    Ok(())
}

fn write_local_zip64_extra_field<W: io::Write>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<()> {
    // This entry in the Local header MUST include BOTH original
    // and compressed file size fields.
    writer.write_u16(0x0001)?;
    writer.write_u16(16)?;
    writer.write_u64(file.uncompressed_size)?;
    writer.write_u64(file.compressed_size)?;
    // Excluded fields:
    // u32: disk start number
    Ok(())
}

fn update_local_zip64_extra_field<W: io::Write + io::Seek>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<()> {
    let zip64_extra_field = file.header_start + 30 + file.file_name.as_bytes().len() as u64;
    writer.seek(io::SeekFrom::Start(zip64_extra_field + 4))?;
    writer.write_u64(file.uncompressed_size)?;
    writer.write_u64(file.compressed_size)?;
    // Excluded fields:
    // u32: disk start number
    Ok(())
}

fn write_central_zip64_extra_field<W: io::Write>(
    writer: &mut W,
    file: &RawZipFileMetadata,
) -> io::Result<u16> {
    // The order of the fields in the zip64 extended
    // information record is fixed, but the fields MUST
    // only appear if the corresponding Local or Central
    // directory record field is set to 0xFFFF or 0xFFFFFFFF.
    let mut size = 0;
    let uncompressed_size = file.uncompressed_size > spec::ZIP64_BYTES_THR;
    let compressed_size = file.compressed_size > spec::ZIP64_BYTES_THR;
    let header_start = file.header_start > spec::ZIP64_BYTES_THR;
    if uncompressed_size {
        size += 8;
    }
    if compressed_size {
        size += 8;
    }
    if header_start {
        size += 8;
    }
    if size > 0 {
        writer.write_u16(0x0001)?;
        writer.write_u16(size)?;
        size += 4;

        if uncompressed_size {
            writer.write_u64(file.uncompressed_size)?;
        }
        if compressed_size {
            writer.write_u64(file.compressed_size)?;
        }
        if header_start {
            writer.write_u64(file.header_start)?;
        }
        // Excluded fields:
        // u32: disk start number
    }
    Ok(size)
}

fn path_to_string(path: &std::path::Path) -> String {
    let mut path_str = String::new();
    for component in path.components() {
        if let std::path::Component::Normal(os_str) = component {
            if !path_str.is_empty() {
                path_str.push('/');
            }
            path_str.push_str(&os_str.to_string_lossy());
        }
    }
    path_str
}

#[cfg(test)]
mod test {
    use super::{FileOptions, ZipWriter};
    use crate::compression::CompressionMethod;
    use crate::types::DateTime;
    use std::io;
    use std::io::Write;

    #[test]
    fn write_empty_zip() {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        writer.set_comment("ZIP".into());
        let result = writer.finish().unwrap();
        assert_eq!(result.get_ref().len(), 25);
        assert_eq!(
            *result.get_ref(),
            [80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 90, 73, 80]
        );
    }

    #[test]
    fn write_zip_dir() {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        writer
            .add_directory(
                "test",
                FileOptions {
                    last_modified_time: DateTime::from_date_and_time(2018, 8, 15, 20, 45, 6)
                        .unwrap(),
                    ..FileOptions::default()
                },
            )
            .unwrap();

        let result = writer.finish().unwrap();
        assert_eq!(result.get_ref().len(), 108);
        assert_eq!(
            *result.get_ref(),
            &[
                80u8, 75, 3, 4, 20, 0, 0, 0, 0, 0, 163, 165, 15, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 5, 0, 0, 0, 116, 101, 115, 116, 47, 80, 75, 1, 2, 46, 3, 20, 0, 0, 0, 0, 0,
                163, 165, 15, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 237, 65, 0, 0, 0, 0, 116, 101, 115, 116, 47, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0,
                1, 0, 51, 0, 0, 0, 35, 0, 0, 0, 0, 0,
            ] as &[u8]
        );
    }

    #[test]
    fn write_symlink_simple() {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "name",
                "target",
                FileOptions {
                    last_modified_time: DateTime::from_date_and_time(2018, 8, 15, 20, 45, 6)
                        .unwrap(),
                    ..FileOptions::default()
                },
            )
            .unwrap();

        let result = writer.finish().unwrap();
        assert_eq!(result.get_ref().len(), 112);
        assert_eq!(
            *result.get_ref(),
            &[
                80u8, 75, 3, 4, 20, 0, 0, 0, 0, 0, 163, 165, 15, 77, 252, 47, 111, 70, 6, 0, 0, 0,
                6, 0, 0, 0, 4, 0, 0, 0, 110, 97, 109, 101, 116, 97, 114, 103, 101, 116, 80, 75, 1,
                2, 46, 3, 20, 0, 0, 0, 0, 0, 163, 165, 15, 77, 252, 47, 111, 70, 6, 0, 0, 0, 6, 0,
                0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 161, 0, 0, 0, 0, 110, 97, 109, 101,
                80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 50, 0, 0, 0, 40, 0, 0, 0, 0, 0
            ] as &[u8],
        );
    }

    #[test]
    fn write_symlink_wonky_paths() {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "directory\\link",
                "/absolute/symlink\\with\\mixed/slashes",
                FileOptions {
                    last_modified_time: DateTime::from_date_and_time(2018, 8, 15, 20, 45, 6)
                        .unwrap(),
                    ..FileOptions::default()
                },
            )
            .unwrap();

        let result = writer.finish().unwrap();
        assert_eq!(result.get_ref().len(), 162);
        assert_eq!(
            *result.get_ref(),
            &[
                80u8, 75, 3, 4, 20, 0, 0, 0, 0, 0, 163, 165, 15, 77, 95, 41, 81, 245, 36, 0, 0, 0,
                36, 0, 0, 0, 14, 0, 0, 0, 100, 105, 114, 101, 99, 116, 111, 114, 121, 92, 108, 105,
                110, 107, 47, 97, 98, 115, 111, 108, 117, 116, 101, 47, 115, 121, 109, 108, 105,
                110, 107, 92, 119, 105, 116, 104, 92, 109, 105, 120, 101, 100, 47, 115, 108, 97,
                115, 104, 101, 115, 80, 75, 1, 2, 46, 3, 20, 0, 0, 0, 0, 0, 163, 165, 15, 77, 95,
                41, 81, 245, 36, 0, 0, 0, 36, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255,
                161, 0, 0, 0, 0, 100, 105, 114, 101, 99, 116, 111, 114, 121, 92, 108, 105, 110,
                107, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 60, 0, 0, 0, 80, 0, 0, 0, 0, 0
            ] as &[u8],
        );
    }

    #[test]
    fn write_mimetype_zip() {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = FileOptions {
            compression_method: CompressionMethod::STORE,
            compression_level: None,
            last_modified_time: DateTime::default(),
            permissions: Some(33188),
            large_file: false,
        };
        let mut w = writer.start_file("mimetype", options).unwrap();
        w.write_all(b"application/vnd.oasis.opendocument.text")
            .unwrap();
        w.finish().unwrap();
        let result = writer.finish().unwrap();

        assert_eq!(result.get_ref().len(), 153);
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        assert_eq!(result.get_ref(), &v);
    }

    #[test]
    fn path_to_string() {
        let mut path = std::path::PathBuf::new();
        #[cfg(windows)]
        path.push(r"C:\");
        #[cfg(unix)]
        path.push("/");
        path.push("windows");
        path.push("..");
        path.push(".");
        path.push("system32");
        let path_str = super::path_to_string(&path);
        assert_eq!(path_str, "windows/system32");
    }
}

#[cfg(not(feature = "unreserved"))]
const EXTRA_FIELD_MAPPING: [u16; 49] = [
    0x0001, 0x0007, 0x0008, 0x0009, 0x000a, 0x000c, 0x000d, 0x000e, 0x000f, 0x0014, 0x0015, 0x0016,
    0x0017, 0x0018, 0x0019, 0x0020, 0x0021, 0x0022, 0x0023, 0x0065, 0x0066, 0x4690, 0x07c8, 0x2605,
    0x2705, 0x2805, 0x334d, 0x4341, 0x4453, 0x4704, 0x470f, 0x4b46, 0x4c41, 0x4d49, 0x4f4c, 0x5356,
    0x5455, 0x554e, 0x5855, 0x6375, 0x6542, 0x7075, 0x756e, 0x7855, 0xa11e, 0xa220, 0xfd4a, 0x9901,
    0x9902,
];
