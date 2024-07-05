use k256::{
    ecdsa::SigningKey,
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use hex::encode;
use rayon::prelude::*;

// use mutex
use std::sync::{Arc, Mutex};

pub fn generate_private_key() -> [u8; 32] {
    let secret_key = SecretKey::random(&mut OsRng);
    secret_key.to_bytes().into()
}

pub fn generate_public_key(private_key: &[u8; 32]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(private_key.into()).expect("Invalid private key");
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    encoded_point.as_bytes().to_vec()
}

pub fn generate_ethereum_address(public_key: &[u8]) -> String {
    // Skip the first byte (0x04) which indicates that the public key is uncompressed
    let public_key = &public_key[1..];
    // Compute the Keccak-256 hash of the public key
    let mut hasher = Keccak256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    // Take the last 20 bytes of the hash to form the address
    let address = &hash[hash.len() - 20..];
    // Convert the address to a hexadecimal string
    format!("0x{}", encode(address))
}

fn main() {
    let private_key = generate_private_key();
    println!("Private Key: 0x{}", hex::encode(private_key));
    let public_key = generate_public_key(&private_key);
    println!("Public Key: 0x{}", hex::encode(&public_key));
    let ethereum_address = generate_ethereum_address(&public_key);
    println!("Ethereum Address: {}", ethereum_address);

    // make best_address string mutex
    let best_address = Arc::new(Mutex::new(ethereum_address));

    (0..1_000_000_000).into_par_iter().for_each(|_| {

        // count the leading 0s in the best address
        let count = best_address.lock().expect("bad").replace("0x", "").chars().take_while(|&c| c == '0').count();

        let private_key = generate_private_key();
        let public_key = generate_public_key(&private_key);
        let ethereum_address = generate_ethereum_address(&public_key);

        // compare the count of leading 0s in the best address with the current address

        let current_count = ethereum_address.replace("0x", "").chars().take_while(|&c| c == '0').count();

        if current_count > count {
            *best_address.lock().expect("bad") = ethereum_address.clone();
            println!("Private Key: 0x{}", hex::encode(private_key));
            println!("Public Key: 0x{}", hex::encode(&public_key));
            println!("Ethereum Address: {}", ethereum_address);
        }
    });
}
