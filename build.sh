#!/bin/bash

cargo build --release --bin speed
cargo build --release --bin encrypt
cargo build --release --bin decrypt

cp ./target/release/speed ../binaries/Rust/speed
cp ./target/release/encrypt ../binaries/Rust/encrypt
cp ./target/release/decrypt ../binaries/Rust/decrypt
