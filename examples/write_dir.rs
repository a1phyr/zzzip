use std::fs::File;
use std::io::{Seek, Write};
use std::iter::Iterator;
use std::path::Path;
use std::process::ExitCode;
use walkdir::{DirEntry, WalkDir};
use zip::result::ZipError;
use zip::write::FileOptions;

const METHOD_STORED: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::STORE);

#[cfg(feature = "deflate-any")]
const METHOD_DEFLATED: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::DEFLATE);

#[cfg(not(feature = "deflate-any"))]
const METHOD_DEFLATED: Option<zip::CompressionMethod> = None;

#[cfg(feature = "bzip2")]
const METHOD_BZIP2: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::BZIP2);
#[cfg(not(feature = "bzip2"))]
const METHOD_BZIP2: Option<zip::CompressionMethod> = None;

#[cfg(feature = "zstd")]
const METHOD_ZSTD: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::ZSTD);
#[cfg(not(feature = "zstd"))]
const METHOD_ZSTD: Option<zip::CompressionMethod> = None;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        println!(
            "Usage: {} <source_directory> <destination_zipfile>",
            args[0]
        );
        return ExitCode::FAILURE;
    }

    let src_dir = &*args[1];
    let dst_file = &*args[2];
    for &method in [METHOD_STORED, METHOD_DEFLATED, METHOD_BZIP2, METHOD_ZSTD].iter() {
        if method.is_none() {
            continue;
        }
        match doit(src_dir, dst_file, method.unwrap()) {
            Ok(_) => println!("done: {src_dir} written to {dst_file}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    ExitCode::SUCCESS
}

fn zip_dir<T>(
    it: &mut dyn Iterator<Item = DirEntry>,
    prefix: &str,
    writer: T,
    compression_method: zip::CompressionMethod,
) -> zip::result::ZipResult<()>
where
    T: Write + Seek,
{
    let mut zip = zip::ZipWriter::new(writer);
    let options = FileOptions {
        compression_method,
        permissions: Some(0o755),
        ..Default::default()
    };

    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(prefix)).unwrap();

        // Write file or directory explicitly
        // Some unzip tools unzip files with directory paths correctly, some do not!
        if path.is_file() {
            println!("adding file {path:?} as {name:?} ...");
            #[allow(deprecated)]
            let mut file_writer = zip.start_file_from_path(name, options)?;

            let mut file = File::open(path)?;
            std::io::copy(&mut file, &mut file_writer)?;
            file_writer.finish()?;
        } else if !name.as_os_str().is_empty() {
            // Only if not root! Avoids path spec / warning
            // and mapname conversion failed error on unzip
            println!("adding dir {path:?} as {name:?} ...");
            #[allow(deprecated)]
            zip.add_directory_from_path(name, options)?;
        }
    }
    zip.finish()?;
    Ok(())
}

fn doit(
    src_dir: &str,
    dst_file: &str,
    method: zip::CompressionMethod,
) -> zip::result::ZipResult<()> {
    if !Path::new(src_dir).is_dir() {
        return Err(ZipError::FileNotFound);
    }

    let path = Path::new(dst_file);
    let file = File::create(path).unwrap();

    let walkdir = WalkDir::new(src_dir);
    let it = walkdir.into_iter();

    zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method)?;

    Ok(())
}
