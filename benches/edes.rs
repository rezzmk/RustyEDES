#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
extern crate rand;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, BatchSize};
use sha2::{Sha256, Digest};
use enhanced_des::edes::{EdesContext};
use std::{ptr, slice};

/// Benchmarks multiple rounds of Encryption/Decryption of Enhanced-DES, comparing a C version against a Rust one.
/// For the C version testing, some bindings over a wrapper had to be made (automatically), and compilation has the required libraries linked
pub fn enhanced_des_benchmark(c: &mut Criterion) {
    // Sampling group setup
    let mut group = c.benchmark_group("bench");

    // Sampling mode Flat allows us to have larger running times, i.e. when encrypting large amounts of data
    group.sampling_mode(SamplingMode::Flat);

    // Set up the buffer to encrypt (4KiB of random data). 
    // Note: Internally, rand::random::<u8> will fetch from sources such as /dev/urandom
    let mut data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();

    // Test the C version. For this, we need to take advantage of unsafe code, to deal with pointers directly
    group.bench_function("C Enc/Dec 4k Buffer (E-DES)", |b| b.iter_batched_ref(|| {
        let mut key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        unsafe { CAENC_CTX_new(0, key.as_mut_ptr()); }
    },
    |_| {
        unsafe {
            let result: *mut ENCRYPTION_RESULT = encrypt(data.as_mut_ptr(), 4096);
            let _: *mut ENCRYPTION_RESULT = decrypt((*result).result, 4096 + 8);
        }
    }, BatchSize::SmallInput));

    // Test the C version of legacy DES. For this, we need to take advantage of unsafe code, to deal with pointers directly
    group.bench_function("C Enc/Dec 4k Buffer (DES)", |b| b.iter_batched_ref(|| {
        let mut key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        unsafe { 
            CAENC_CTX_new(1, key.as_mut_ptr()); 
        }
    },
    |_| {
        unsafe {
            let result: *mut ENCRYPTION_RESULT = encrypt(data.as_mut_ptr(), 4096);
            let _: *mut ENCRYPTION_RESULT = decrypt((*result).result, 4096 + 8);
        }
    }, BatchSize::SmallInput));

    // Test the Rust version
    group.bench_function("RUST Enc/Dec 4k Buffer (E-DES)", |b| b.iter_batched_ref(|| -> EdesContext {
        let mut sha256 = Sha256::new();
        let ikey: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        sha256.update(ikey);
        let key = sha256.finalize().to_vec();
        let c = EdesContext::new(key);
        c
    },
    |c| {
        let enc_result = enhanced_des::edes::encrypt(data.to_owned(), &c);
        let _dec_result = enhanced_des::edes::decrypt(enc_result, &c);
    }, BatchSize::SmallInput));

    group.finish();
}

criterion_group!(benches, enhanced_des_benchmark);
criterion_main!(benches);