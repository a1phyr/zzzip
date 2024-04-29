use std::{io, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <filename>", args[0]);
        return ExitCode::FAILURE;
    }
    let fname = std::path::Path::new(&*args[1]);
    let zipfile = io::BufReader::new(std::fs::File::open(fname).unwrap());

    let mut archive = zip::ZipArchive::new(zipfile).unwrap();

    let file = match archive.by_name("test/lorem_ipsum.txt") {
        Ok(file) => file,
        Err(..) => {
            println!("File test/lorem_ipsum.txt not found");
            return ExitCode::FAILURE;
        }
    };

    let contents = io::read_to_string(file.reader().unwrap()).unwrap();
    println!("{contents}");

    ExitCode::SUCCESS
}
