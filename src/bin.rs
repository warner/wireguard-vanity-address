use rayon::prelude::*;
use std::env;
use std::io::{self, Write};
use wireguard_vanity_lib::trial;

fn print(res: (String, String)) -> Result<(), io::Error> {
    let (private_b64, public_b64) = res;
    writeln!(
        io::stdout(),
        "private {}  public {}",
        &private_b64,
        &public_b64
    )
}

fn main() -> Result<(), io::Error> {
    let prefix = env::args().nth(1).unwrap().to_ascii_lowercase();
    let len = prefix.len() as u64;
    let within = len + 10;
    let offsets: u64 = (within as u64) - len;
    let expected: u64 = 2u64.pow(5).pow(len as u32) / offsets;
    println!(
        "prefix: {}, expect {} trials, Ctrl-C to stop",
        prefix, expected
    );
    //let mut stdout = io::stdout;

    // 1M trials takes about 10s on my laptop, so let it run for 1000s
    (0..100_000_000)
        .into_par_iter()
        .map(|_| trial(&prefix, within as usize))
        .filter_map(|r| r)
        .try_for_each(print)
}
