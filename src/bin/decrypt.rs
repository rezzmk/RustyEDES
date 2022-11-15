//! Enhanced DES (Data Encryption Standard) Decryption app
//!
//! Author: Marcos Caramalho
extern crate atty;

use clap::Parser;
use sha2::{Sha256, Digest};
use std::io::{self, Read, Write};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
   #[arg(short, long)]
   input_file: Option<std::path::PathBuf>,

   #[arg(short, long)]
   output_file: Option<std::path::PathBuf>,

   #[arg(short, long)]
   key: String
}

fn main() {
    let args = Cli::parse();

    // Initialize 
    let mut sha256 = Sha256::new();
    sha256.update(args.key);
    let key = sha256.finalize().to_vec();

    let context = enhanced_des::edes::EdesContext::new(key);

    // Data to be encrypted, as a dynamic buffer
    let mut data: Vec<u8> = Vec::new();

    // Try to read data from provided file path (--input-file), otherwise fallback to stdin redirection
    if atty::is(atty::Stream::Stdin) {
        if args.input_file.is_none() {
            println!("Please provide a file to read with --input-file, or use stdin redirection (< file)");
            return;
        }

        let input_file = args.input_file.as_deref().unwrap();
        println!("Decrypting file: {}", input_file.display());

        data = std::fs::read(input_file).unwrap();
    }
    else {
        let num_read = io::stdin().read_to_end(&mut data).unwrap();
        println!("Decrypting input from stdin, number of bytes read: {:?}", num_read);
    }

    // Decrypt the data
    let result = enhanced_des::edes::decrypt(data, &context);

    // If no output file path is provided, try to print everyting to stdout.
    // There's a limit of 256 chars to ease of read, in which case it saved everything to dec.out
    if args.output_file.is_none() {
        let len = result.len();
        if len > 256 {
            println!("Output greater than 256B at {:?}, printing the top 256B. The entire result is stored in dec.out", len);
            io::stdout().write_all(&result[..256]).unwrap();
            std::fs::write("dec.out", result).unwrap();
        }
        else {
            io::stdout().write_all(&result).unwrap();
        }
    }
    else {
        std::fs::write(args.output_file.as_deref().unwrap(), result).unwrap();
    }
} 