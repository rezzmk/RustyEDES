#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
extern crate rand;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, BatchSize};
use sha2::{Sha256, Digest};
use enhanced_des::edes::{EdesContext};
use std::{ptr, slice};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    group.sampling_mode(SamplingMode::Flat);

    let data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();
    let mut buf: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();

    group.bench_function("C Enc/Dec 4k Buffer", |b| b.iter_batched_ref(|| {
        let mut key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        unsafe { CAENC_CTX_new(0, key.as_mut_ptr()); }
    },
    |_| {
        unsafe {
            let result: *mut ENCRYPTION_RESULT = encrypt(buf.as_mut_ptr(), 4096);
            let _: *mut ENCRYPTION_RESULT = decrypt((*result).result, 4096 + 8);
        }
    }, BatchSize::SmallInput));

    group.bench_function("RUST Enc/Dec 4k Buffer", |b| b.iter_batched_ref(|| -> EdesContext {
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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);