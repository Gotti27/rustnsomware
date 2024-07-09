use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::Rng;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use filenamify::filenamify;

use crate::utils::get_file_as_byte_vec;

pub fn generate_keys() {
    println!("generating keys");
    let _rng = rand::thread_rng();
    let bits = 2048;
    let rsa = Rsa::generate(bits).expect("failed to generate a key");

    let priv_key = rsa.private_key_to_pem().unwrap();
    let pub_key = rsa.public_key_to_pem_pkcs1().unwrap();

    fs::create_dir_all("keys").expect("ERR");
    let mut key_name = Default::default();
    print!("Input key name: ");
    io::stdout().flush().expect("msg");
    io::stdin().read_line(&mut key_name).expect("ERR");
    let priv_key_filename = filenamify(key_name[..key_name.len() - 1].to_owned() + ".pem");

    fs::File::create(String::from("keys/".to_owned() + &priv_key_filename))
        .unwrap()
        .write_all(&priv_key)
        .unwrap();

    let pub_key_filename = filenamify(key_name[..key_name.len() - 1].to_owned() + ".pem.pub");
    fs::File::create(String::from("keys/".to_owned() + &pub_key_filename))
        .unwrap()
        .write_all(&pub_key)
        .unwrap();

    println!("keys generated");
}

pub fn encrypt_file(public_key: Rsa<Public>, path: &Path) {
    let data = get_file_as_byte_vec(&path.to_str().expect("Invalid path").to_string());

    let mut aes_key = [0u8; 32];
    rand::thread_rng().fill(&mut aes_key);
    let cipher = Cipher::aes_256_gcm();

    let mut buf = vec![0; public_key.size() as usize];
    public_key
        .public_encrypt(&aes_key, &mut buf, Padding::PKCS1)
        .expect("Failed to encrypt AES key");

    let iv = rand::thread_rng().gen::<[u8; 12]>(); // 12-bytes nonce
    let ciphertext = encrypt(cipher, &aes_key, Some(&iv), &data).expect("Failed to encrypt data");

    // let mut out_file = File::create(&path).expect("Unable to create file");
    let mut out_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    out_file
        .write_all(&buf)
        .expect("Unable to write encrypted key");
    out_file.write_all(&iv).expect("Unable to write IV");
    out_file
        .write_all(&ciphertext)
        .expect("Unable to write encrypted data");

    fs::rename(path, String::from(path.to_str().unwrap()) + ".locked")
        .expect("Error while renaming file");
}

pub fn decrypt_file(private_key: Rsa<Private>, path: &Path) {
    let file_path = path.to_str().expect("Invalid path").to_string();
    let mut file = File::open(&file_path).expect("Unable to open file");

    let mut enc_sym_key = vec![0u8; private_key.size() as usize];
    file.read_exact(&mut enc_sym_key)
        .expect("Failed to read RSA encrypted symmetric key");

    let mut aes_key = vec![0; private_key.size() as usize];
    private_key
        .private_decrypt(&enc_sym_key, &mut aes_key, Padding::PKCS1)
        .expect("Failed to decrypt symmetric key");
    let aes_key = aes_key.iter().take(32).cloned().collect::<Vec<u8>>();

    let mut iv = [0u8; 12];
    file.read_exact(&mut iv).expect("Failed to read IV");

    let mut enc_data = Vec::new();
    file.read_to_end(&mut enc_data)
        .expect("Failed to read encrypted data");

    let cipher = Cipher::aes_256_gcm();
    let dec_data = decrypt(cipher, &aes_key, Some(&iv), &enc_data).expect("Failed to decrypt data");

    let mut out_file = File::create(&file_path).expect("Unable to create file");
    out_file
        .write_all(&dec_data)
        .expect("Unable to write decrypted data");

    fs::rename(path, path.with_extension("")) // String::from(path.to_str().unwrap())
        .expect("Error while renaming file");
}
