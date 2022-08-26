use base64;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn trial(prefix: &str, start: usize, end: usize, case: bool) -> Option<(String, String)> {
    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private);
    let public_b64 = base64::encode(public.as_bytes());
    let mut start = public_b64[start..end].to_string();
    if !case {
        start.make_ascii_lowercase()
    }
    if start.contains(&prefix)
    {
        let private_b64 = base64::encode(&private.to_bytes());
        Some((private_b64, public_b64))
    } else {
        None
    }
}
