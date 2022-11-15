//! Enhanced DES (Data Encryption Standard) Encryption app
//!
//! Author: Marcos Caramalho
extern crate rand;

use sha2::{Sha256, Digest};
use std::time::{SystemTime};

fn main() {
    let number_iters = 100000;
    println!("Running 100k iterations of encryption and decryption");

    println!("Generating random buffer of 4096B (rand::random::<u8>)");
    let data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();

    println!("Each iteration will generate a new key of 32B (rand::random::<u8>)");
    println!("Benchmark approach:");
    println!("\t1) Initialize new context with iteration key");
    println!("\t2) Start timer");
    println!("\t3) Encrypt and Decrypt pre-generated 4096B buffer");
    println!("\t4) Stop timer");
    println!("\t* This measures Wall-Time, not CPU time, external factors will impact the measurements");
    println!("\t* After the 100k iterations, an average of the best 10k is taken");

    let mut results: Vec<f64> = Vec::new();
    for _ in 0..number_iters {
        let ikey: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let mut sha256 = Sha256::new();
        sha256.update(ikey);
        let key = sha256.finalize().to_vec();
        let context = enhanced_des::edes::EdesContext::new(key);

        let round_data = data.clone();

        let start = SystemTime::now();

        let enc_result = enhanced_des::edes::encrypt(round_data, &context);
        let _ = enhanced_des::edes::decrypt(enc_result, &context);

        let end = SystemTime::now();

        let difference = end.duration_since(start).unwrap();
        let r = difference.as_secs_f64();
        results.push(r);
    };

    results.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mut final_result: f64 = 0.0;
    for i in 0..10000 {
        final_result = final_result + results[i as usize];
    }

    println!(
        "\nFinished: Each iteration took on average {:?} ms, Min: {:?} ms, Max: {:?} ms", 
        (final_result / number_iters as f64) * 1000.0, 
        results[0] * 1000.0, 
        results[results.len() - 1] * 1000.0
    );
} 