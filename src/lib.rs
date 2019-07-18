use base64;
use rand::{thread_rng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub fn trial(prefix: &str, within: usize) -> bool {
    let mut rng = thread_rng();
    let mut private = [0u8; 32];
    rng.try_fill_bytes(&mut private).unwrap();
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519(private, X25519_BASEPOINT_BYTES);
    let public_b64 = base64::encode(&public);
    //if public_b64.starts_with(&prefix) {
    if public_b64[..within].to_ascii_lowercase().contains(&prefix) {
        println!(
            "private {}  public {}",
            base64::encode(&private),
            &public_b64
        );
        true
    } else {
        false
    }
}
