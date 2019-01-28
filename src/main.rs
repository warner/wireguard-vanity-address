extern crate base64;
extern crate rand;
extern crate rayon;
extern crate x25519_dalek;

use rand::{thread_rng, RngCore};
use rayon::prelude::*;
use std::env;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

fn main() {
    let prefix = env::args().nth(1).unwrap().to_ascii_lowercase();
    let len = prefix.len() as u64;
    const WITHIN: usize = 10;
    let offsets: u64 = (WITHIN as u64) - len;
    let expected: u64 = 2u64.pow(5).pow(len as u32) / offsets;
    println!(
        "prefix: {}, expect {} trials, Ctrl-C to stop",
        prefix, expected
    );

    // 1M trials takes about 10s on my laptop, so let it run for 1000s
    let _: Vec<bool> = (0..100_000_000)
        .into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            let mut private = [0u8; 32];
            rng.try_fill_bytes(&mut private).unwrap();
            let public = x25519(private, X25519_BASEPOINT_BYTES);
            let public_b64 = base64::encode(&public);
            //if public_b64.starts_with(&prefix) {
            if public_b64[..WITHIN].to_ascii_lowercase().contains(&prefix) {
                println!(
                    "private {}  public {}",
                    base64::encode(&private),
                    &public_b64
                );
                true
            } else {
                false
            }
        })
        .filter(|good| *good)
        .collect();
}
