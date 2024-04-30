use bencher::{benchmark_group, benchmark_main};

use std::io::{Cursor, Write};

use bencher::Bencher;
use zip::{ZipArchive, ZipWriter};

const FILE_COUNT: usize = 15_000;
const FILE_SIZE: usize = 1024;

fn generate_random_archive(count_files: usize, file_size: usize) -> Vec<u8> {
    let data = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(data));
    let options = zip::write::FileOptions {
        compression_method: zip::CompressionMethod::STORE,
        ..Default::default()
    };

    let bytes = vec![0u8; file_size];

    for i in 0..count_files {
        let name = format!("file_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_{i}.dat");
        let mut file = writer.start_file(name, options).unwrap();
        file.write_all(&bytes).unwrap();
        file.finish().unwrap();
    }

    writer.finish().unwrap().into_inner()
}

fn read_metadata(bench: &mut Bencher) {
    let bytes = generate_random_archive(FILE_COUNT, FILE_SIZE);

    bench.iter(|| {
        let archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        archive.len()
    });
}

benchmark_group!(benches, read_metadata);
benchmark_main!(benches);
