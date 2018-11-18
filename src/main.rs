extern crate base64;
extern crate rand;
extern crate x25519_dalek;

use std::env;
use rand::rngs::OsRng;
use x25519_dalek as x25519;

fn main() {
    let prefix = env::args().nth(1).unwrap().to_ascii_lowercase();
    let len = prefix.len() as u64;
    let within: usize = 10;
    let offsets: u64 = (within as u64) - len;
    let expected: u64 = 2u64.pow(5).pow(len as u32) / offsets;
    println!("prefix: {}, expect {} trials", prefix, expected);
    let mut rng = OsRng::new().unwrap();
    let mut count = 1u64;
    loop {
        let private = x25519::generate_secret(&mut rng);
        let public = x25519::generate_public(&private).to_bytes();
        let public_b64 = base64::encode(&public);
        //if public_b64.starts_with(&prefix) {
        if public_b64[..within].to_ascii_lowercase().contains(&prefix) {
            println!("{} private {}, public {}", count,
                     base64::encode(&private), &public_b64);
            break;
        }
        count += 1;
        if count % 1000 == 0 {
            println!("tried {} keys", count);
        }
    }
}
