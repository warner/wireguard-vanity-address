use base64;
use rand_core::OsRng;
use std::borrow::Cow;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn trial(prefix: &str, end: usize, case_sensitive: bool) -> Option<(String, String)> {
    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private);

    let public_b64 = base64::encode(public.as_bytes());

    let b64_prefix = if case_sensitive {
        Cow::Borrowed(&public_b64[..end])
    } else {
        Cow::Owned(public_b64[..end].to_ascii_lowercase())
    };

    if b64_prefix.contains(prefix)
    {
        let private_b64 = base64::encode(&private.to_bytes());
        Some((private_b64, public_b64))
    } else {
        None
    }
}
