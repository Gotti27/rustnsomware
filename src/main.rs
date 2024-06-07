use clap::Parser;
use std::borrow::Borrow;
use std::collections::LinkedList;
use std::fs::{self};
use std::env;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// > Rustnsomware: encrypt and decrypt filesystems
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    key: String,

    #[clap(value_parser, num_args = 1.., value_delimiter = ' ')]
    paths: Vec<String>,

    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    let mut files: LinkedList<String> = LinkedList::new();

	let program_name = env::current_exe().expect("WTF??");
	dbg!(program_name);
	dbg!(args.key);
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

        if metadata.is_dir() {
            fs::read_dir(current_file).unwrap().for_each(|f| {
                files.push_back(String::from(f.unwrap().path().canonicalize().unwrap().to_string_lossy()));
            });
        } else if metadata.is_file() {
            println!("{}", current_file);
        }
    }

    std::process::exit(0);
}
