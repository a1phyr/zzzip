use std::{
    io::{self, Read},
    process::ExitCode,
};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut stdin_handle = stdin.lock();
    let mut buf = [0u8; 16];

    loop {
        match zip::read::read_zipfile_from_stream(&mut stdin_handle) {
            Ok(Some(mut file)) => {
                // println!(
                //     "{}: {} bytes ({} bytes packed)",
                //     file.name(),
                //     file.size(),
                //     file.compressed_size()
                // );
                match file.read(&mut buf) {
                    Ok(n) => println!("The first {} bytes are: {:?}", n, &buf[0..n]),
                    Err(e) => println!("Could not read the file: {e:?}"),
                };
            }
            Ok(None) => break,
            Err(e) => {
                println!("Error encountered while reading zip: {e:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
