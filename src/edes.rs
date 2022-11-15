//! Enhanced DES (Data Encryption Standard) Implementation
//!
//! Author: Marcos Caramalho
const BLOCK_SIZE: u8 = 8;
const SBOX_SIZE: u16 = 256;
const NUM_SBOXES: u8 = 16;

/// Enhanced DES Context
#[derive(Debug)]
pub struct EdesContext {
    pub sha256_key: Vec<u8>,
    sboxes: Vec<Vec<u8>>
}

/// EDES CTOR will initialize the sboxes given a key. Assumes a 32B key (256 bits)
impl EdesContext {
    pub fn new(sha256_key: Vec<u8>) -> EdesContext {
        EdesContext {
            sha256_key: sha256_key.clone(),
            sboxes: gen_sboxes(sha256_key.clone().to_vec())
        }
    }
}

pub fn encrypt(message: Vec<u8>, context: &EdesContext) -> Vec<u8> {
    let mut result = message.clone();

    // We begin by padding the input using PKCS#7
    pkcs7_pad(&mut result);

    // Process each block individually (ECB - Electronic Code Book)
    let num_blocks = result.len() / BLOCK_SIZE as usize;
    for block_id in 0..num_blocks {
        let offset = block_id * 8 as usize;

        let mut output: [u8; 4] = [0; 4];
        let mut left_tmp: [u8; 4] = [0; 4];
        let mut left: [u8; 4] = [result[offset], result[offset + 1], result[offset + 2], result[offset + 3]];
        let mut right: [u8; 4] = [result[offset + 4], result[offset + 5], result[offset + 6], result[offset + 7]];

        for i in 0..16 {
            for j in 0..4 {
                left_tmp[j as usize] = left[j as usize];
                left[j as usize] = right[j as usize];
                output[j] = 0;
            }

            let mut index: u16 = right[0] as u16; 
            output[3] = context.sboxes[i][index as usize];
            index = (index + right[1] as u16) % 256;
            output[2] = context.sboxes[i][index as usize];
            index = (index + right[2] as u16) % 256;
            output[1] = context.sboxes[i][index as usize];
            index = (index + right[3] as u16) % 256;
            output[0] = context.sboxes[i][index as usize];

            for i in 0..4 {
                right[i as usize] = left_tmp[i as usize] ^ output[i as usize];
            }

            for i in 0..8 {
                result[offset + i as usize] = if i < 4 { left[i as usize] } else { right[i as usize - 4] };
            }
        }
    }

    return result;
}

pub fn decrypt(ciphertext: Vec<u8>, context: &EdesContext) -> Vec<u8> {
    let mut result = ciphertext.clone();

    // Process each block individually (ECB - Electronic Code Book)
    let num_blocks = result.len() / BLOCK_SIZE as usize;
    for block_id in 0..num_blocks {
        let offset = block_id * 8;

        let mut output: [u8; 4] = [0; 4];
        let mut right_tmp: [u8; 4] = [0; 4];
        let mut left: [u8; 4] = [result[offset], result[offset + 1], result[offset + 2], result[offset + 3]];
        let mut right: [u8; 4] = [result[offset + 4], result[offset + 5], result[offset + 6], result[offset + 7]];

        for i in (0..16).rev() {
            for j in 0..4 {
                right_tmp[j as usize] = right[j as usize];
                right[j as usize] = left[j as usize];
                output[j] = 0;
            }

            let mut index: u16 = left[0] as u16;
            output[3] = context.sboxes[i][index as usize];
            index = (index + left[1] as u16) % 256;
            output[2] = context.sboxes[i][index as usize];
            index = (index + left[2] as u16) % 256;
            output[1] = context.sboxes[i][index as usize];
            index = (index + left[3] as u16) % 256;
            output[0] = context.sboxes[i][index as usize];

            for i in 0..4 {
                left[i as usize] = right_tmp[i as usize] ^ output[i as usize];
            }

            for i in 0..8 {
                result[offset + i as usize] = if i < 4 { left[i as usize] } else { right[i as usize - 4] };
            }
        }
    }

    // Uses PKCS#7 to unpad the plaintext, since on encryption, it gets padded with at most 1 block (8 bytes)
    pkcs7_unpad(&mut result);

    return result;
}

fn gen_sboxes(mut sha256_key: Vec<u8>) -> Vec<Vec<u8>> {
    let mut sboxes = vec![vec![0; SBOX_SIZE as usize]; NUM_SBOXES as usize];

    for i in 0..NUM_SBOXES {
        sboxes[i as usize] = create_sbox(&mut sha256_key, i as u8);
    }

    return sboxes;
}

fn pkcs7_pad(payload: &mut Vec<u8>) {
    let padding_value: usize;
    let payload_len = payload.len();

    // The amount of padding depends on how much bytes are left for a block size multiple
    // At most we'll have 8 bytes of padding, e.g. input has 8 bytes, we add a new block with the value 8.
    // If we have 1 byte left for a block size multiple, we'll fill that with the value 1, and so on...
    if payload_len % 8 == 0 {
        padding_value = 8
    }
    else {
        padding_value = 8 - (payload_len % 8);
    }

    let mut pad = vec![padding_value as u8; padding_value];
    payload.append(&mut pad);
}

fn pkcs7_unpad(payload: &mut Vec<u8>) {
    let padding_value = payload[payload.len() - 1];

    // Knowing the padding value, we truncate the vector here, getting the original size
    payload.truncate(payload.len() - padding_value as usize);
}

/// Creation of S-Box inspired by the work of Kazys KAZLAUSKAS, Gytis VAICEKAUSKAS, Robertas SMALIUKAS,
/// on the paper "An Algorith for Key-Dependent S-Box Generation in Block Cipher System" (DOI: https://informatica.vu.lt/journal/INFORMATICA/article/753/info)
fn create_sbox(sha256_key: &mut Vec<u8>, sbox_index: u8) -> Vec<u8> {
    let mut sbox : Vec<u8> = (0..=255).map(|x| x).collect();

    if sbox_index > 0 {
        for i in 0..31 {
            sha256_key[i] = sha256_key[i + 1] ^ sbox_index;
        }
    }

    let mut j: u16 = 0;
    for i in 0..32 {
        j = (j + (sha256_key[i as usize] as u16)) % 256;
    }

    let mut k: u8;
    let mut p: u8;
    for i in 0..256 {
        k = (sbox[i as usize] + sbox[j as usize]) % 32;
        j = (j + (sha256_key[k as usize] as u16)) % 256;
        p = sbox[i as usize];
        sbox[i as usize] = sbox[j as usize];
        sbox[j as usize] = p;
    }

    return sbox;
}