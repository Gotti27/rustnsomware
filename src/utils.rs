use std::{fs, io::Read};

pub fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    dbg!(filename);
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&filename)
        .unwrap();
    // let mut f = fs::File::open(&filename).expect("no file found");
    let _metadata = fs::metadata(&filename).expect("unable to read metadata");
    // let mut buffer = vec![0; metadata.len() as usize];
    // f.read_to_end(&mut buffer).expect("buffer overflow");

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("Unable to read file");

    // dbg!(&buffer);

    buffer
}
