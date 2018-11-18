extern crate rayon;
extern crate base64;
extern crate rand;
extern crate x25519_dalek;

use std::env;
use rayon::prelude::*;
use rand::thread_rng;
use x25519_dalek as x25519;

fn main() {
    let prefix = env::args().nth(1).unwrap().to_ascii_lowercase();
    let len = prefix.len() as u64;
    const WITHIN: usize = 10;
    let offsets: u64 = (WITHIN as u64) - len;
    let expected: u64 = 2u64.pow(5).pow(len as u32) / offsets;
    let trials = expected * 10;
    println!("prefix: {}, expect {} trials", prefix, expected);

    (0..trials).into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            let private = x25519::generate_secret(&mut rng);
            let public = x25519::generate_public(&private).to_bytes();
            let public_b64 = base64::encode(&public);
            //if public_b64.starts_with(&prefix) {
            if public_b64[..WITHIN].to_ascii_lowercase().contains(&prefix) {
                println!("private {}, public {}",
                         base64::encode(&private), &public_b64);
                return true;
            }
            return false;
        })
        .any(|good| good);
}
