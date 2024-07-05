use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint};
use rand::{thread_rng, RngCore};

pub fn generate_private_key() -> [u8; 32] {
    let mut rng = thread_rng();
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    private_key
}

pub fn generate_public_key(private_key: &[u8; 32]) -> Vec<u8> {
    // Create a SigningKey from the private key
    let signing_key = SigningKey::from_bytes(private_key).expect("Invalid private key");

    // Get the VerifyingKey (public key) corresponding to the private key
    let verifying_key = signing_key.verifying_key();

    // Convert the public key to its encoded form (compressed or uncompressed)
    let encoded_point = verifying_key.to_encoded_point(false);

    // Return the public key as bytes
    encoded_point.as_bytes().to_vec()
}
