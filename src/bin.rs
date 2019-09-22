use clap::{App, AppSettings, Arg};
use rayon::prelude::*;
use std::error::Error;
use std::fmt;
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

#[derive(Debug)]
struct ParseError(String);
impl Error for ParseError {}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("wireguard-vanity-address")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("0.3.1")
        .author("Brian Warner <warner@lothar.com>")
        .about("finds Wireguard keypairs with a given string prefix")
        .arg(
            Arg::with_name("RANGE")
                .long("in")
                .takes_value(true)
                .help("NAME must be found within first RANGE chars of pubkey (default: 10)"),
        )
        .arg(
            Arg::with_name("NAME")
                .required(true)
                .help("string to find near the start of the pubkey"),
        )
        .get_matches();
    let prefix = matches.value_of("NAME").unwrap();
    let len = prefix.len();
    let end: usize = match matches.value_of("RANGE") {
        Some(range) => range.parse()?,
        None => {
            if len <= 10 {
                10
            } else {
                len + 10
            }
        }
    };
    if end < len {
        Err(ParseError(format!(
            "range {} is too short for len={}",
            end, len
        )))?
    }

    let offsets = (1 + end - len) as u64;
    // todo: this is an approximation, it assumes all match chars are letters
    let expected: u64 = 2u64.pow(5).pow(len as u32) / offsets;
    println!(
        "searching for '{}' in pubkey[0..{}], one of every {} keys should match",
        &prefix, end, expected
    );
    println!("hit Ctrl-C to stop");

    // 1M trials takes about 10s on my laptop, so let it run for 1000s
    (0..100_000_000)
        .into_par_iter()
        .map(|_| trial(&prefix, 0, end))
        .filter_map(|r| r)
        .try_for_each(print)?;
    Ok(())
}
