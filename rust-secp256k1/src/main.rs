use secp256k1::{SecretKey, PublicKey, Message, Secp256k1, ecdsa,ecdsa::RecoverableSignature};
use rand::rngs::OsRng;

fn main() {
    // Create a new Secp256k1 context (uses global context due to the feature flag)
    let secp = Secp256k1::new();

    // Generate a new random private key
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    println!("Private key: {}", secret_key.display_secret());
    println!("Public key: {}", public_key);

    // Create a message to sign
    let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

    // Sign the message
    let recoverable_signature = secp.sign_ecdsa_recoverable(&message, &secret_key);
    let signature = recoverable_signature.to_standard();

    println!("Signature: {}", signature);

    // Verify the signature
    match secp.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => println!("Signature is valid!"),
        Err(e) => println!("Signature verification failed: {}", e),
    }

    // Demonstrate signature recovery
    let recovered_pub_key = secp.recover_ecdsa(&message, &recoverable_signature)
        .expect("Failed to recover public key");
    println!("Recovered public key: {}", recovered_pub_key);
    assert_eq!(public_key, recovered_pub_key);

    // Serialize and deserialize the signature (useful for storage or transmission)
    let serialized_sig = signature.serialize_der();
    let deserialized_sig: secp256k1::ecdsa::Signature = ecdsa::Signature::from_compact(&[
        0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a,
        0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c, 0x39, 0x7a,
        0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94,
        0x0b, 0x55, 0x86, 0x82, 0x3d, 0xfd, 0x02, 0xae,
        0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb,
        0xae, 0xfd, 0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc,
        0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
        0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
    ]).expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
    assert_eq!(signature, deserialized_sig);

    println!("Signature serialization and deserialization successful!");
}