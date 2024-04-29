#![cfg(feature = "aes-crypto")]

use std::io::{self, Read};
use zip::ZipArchive;

const SECRET_CONTENT: &str = "Lorem ipsum dolor sit amet";

const PASSWORD: &[u8] = b"helloworld";

#[test]
fn aes256_encrypted_uncompressed_file() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/aes_archive.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).unwrap();

    let file = archive.by_name("secret_data_256_uncompressed").unwrap();
    assert_eq!("secret_data_256_uncompressed", file.name());

    let mut file = file.decrypt(PASSWORD).unwrap();

    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(SECRET_CONTENT, content);
}

#[test]
fn aes256_encrypted_file() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/aes_archive.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).unwrap();

    let file = archive.by_name("secret_data_256").unwrap();
    assert_eq!("secret_data_256", file.name());

    let mut file = file.decrypt(PASSWORD).unwrap();

    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(SECRET_CONTENT, content);
}

#[test]
fn aes192_encrypted_file() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/aes_archive.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).unwrap();

    let file = archive.by_name("secret_data_192").unwrap();

    assert_eq!("secret_data_192", file.name());

    let mut file = file.decrypt(PASSWORD).unwrap();

    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(SECRET_CONTENT, content);
}

#[test]
fn aes128_encrypted_file() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/aes_archive.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).unwrap();

    let file = archive.by_name("secret_data_128").unwrap();
    assert_eq!("secret_data_128", file.name());

    let mut file = file.decrypt(PASSWORD).unwrap();

    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(SECRET_CONTENT, content);
}
