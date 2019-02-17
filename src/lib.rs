use base64;
use rand::thread_rng;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn trial(prefix: &str, within: usize) -> bool {
    let mut rng = thread_rng();
    let private = StaticSecret::new(&mut rng);
    let public = PublicKey::from(&private);
    let public_b64 = base64::encode(public.as_bytes());
    //if public_b64.starts_with(&prefix) {
    if public_b64[..within].to_ascii_lowercase().contains(&prefix) {
        println!(
            "private {}  public {}",
            base64::encode(&private.to_bytes()),
            &public_b64
        );
        true
    } else {
        false
    }
}
