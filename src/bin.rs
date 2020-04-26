use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use clap::{App, AppSettings, Arg};
use num_cpus;
use rayon::prelude::*;
use wireguard_vanity_lib::trial;

fn estimate_one_trial(prefix: &str, end: usize, case_sensitive: bool) -> Duration {
    let start = SystemTime::now();
    const COUNT: u32 = 100;
    (0..COUNT).for_each(|_| {
        trial(&prefix, end, case_sensitive);
    });
    let elapsed = start.elapsed().unwrap();
    elapsed.checked_div(COUNT).unwrap()
}

fn duration_to_f64(d: Duration) -> f64 {
    (d.as_secs() as f64) + (f64::from(d.subsec_nanos()) * 1e-9)
}

fn format_time(t: f64) -> String {
    if t > 3600.0 {
        format!("{:.2} hours", t / 3600.0)
    } else if t > 60.0 {
        format!("{:.1} minutes", t / 60.0)
    } else if t > 1.0 {
        format!("{:.1} seconds", t)
    } else if t > 1e-3 {
        format!("{:.1} ms", t * 1e3)
    } else if t > 1e-6 {
        format!("{:.1} us", t * 1e6)
    } else if t > 1e-9 {
        format!("{:.1} ns", t * 1e9)
    } else {
        format!("{:.3} ps", t * 1e12)
    }
}

fn format_rate(rate: f64) -> String {
    if rate > 1e9 {
        format!("{:.2}e9 keys/s", rate / 1e9)
    } else if rate > 1e6 {
        format!("{:.2}e6 keys/s", rate / 1e6)
    } else if rate > 1e3 {
        format!("{:.2}e3 keys/s", rate / 1e3)
    } else if rate > 1e0 {
        format!("{:.2} keys/s", rate)
    } else if rate > 1e-3 {
        format!("{:.2}e-3 keys/s", rate * 1e3)
    } else if rate > 1e-6 {
        format!("{:.2}e-6 keys/s", rate * 1e6)
    } else if rate > 1e-9 {
        format!("{:.2}e-9 keys/s", rate * 1e9)
    } else {
        format!("{:.3}e-12 keys/s", rate * 1e12)
    }
}

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
            Arg::with_name("CASE")
                .long("case-sensitive")
                .help("Use case-sensitive matching"),
        )
        .arg(
            Arg::with_name("RANGE")
                .long("in")
                .takes_value(true)
                .help("NAME must be found within first RANGE chars of pubkey (default: 10, 0 means actual prefix)"),
        )
        .arg(
            Arg::with_name("NAME")
                .required(true)
                .help("string to find near the start of the pubkey"),
        )
        .get_matches();
    let case_sensitive = matches.is_present("CASE");
    let prefix = matches.value_of("NAME").unwrap().to_ascii_lowercase();
    let len = prefix.len();
    let end: usize = 44.min(match matches.value_of("RANGE") {
        Some(range) => range.parse()?,
        None => {
            if len <= 10 {
                10
            } else {
                len + 10
            }
        }
    });
    let end = if end == 0 { len } else { end };
    if end < len {
        return Err(ParseError(format!("range {} is too short for len={}", end, len)).into());
    }

    let offsets: u64 = 44.min((1 + end - len) as u64);
    // todo: this is an approximation, offsets=2 != double the chances
    let mut num = offsets;
    let mut denom = 1u64;
    prefix.chars().for_each(|c| {
        if !case_sensitive && c.is_ascii_alphabetic() {
            num *= 2; // letters can match both uppercase and lowercase
        }
        denom *= 64; // base64
    });
    let trials_per_key = denom / num;

    println!(
        "searching for '{}' in pubkey[0..{}], one of every {} keys should match",
        &prefix, end, trials_per_key
    );

    // todo: dividing by num_cpus will overestimate performance when the
    // cores aren't actually distinct (hyperthreading?). My Core-i7 seems to
    // run at half the speed that this predicts.

    if trials_per_key < 2u64.pow(32) {
        let est = estimate_one_trial(&prefix, end, case_sensitive);
        println!(
            "one trial takes {}, CPU cores available: {}",
            format_time(duration_to_f64(est)),
            num_cpus::get()
        );
        let spk = duration_to_f64(
            est // sec/trial on one core
                .checked_div(num_cpus::get() as u32) // sec/trial with all cores
                .unwrap()
                .checked_mul(trials_per_key as u32) // sec/key (Duration)
                .unwrap(),
        );
        let kps = 1.0 / spk;
        println!(
            "est yield: {} per key, {}",
            format_time(spk),
            format_rate(kps)
        );
    }

    println!("hit Ctrl-C to stop");

    // 1M trials takes about 10s on my laptop, so let it run for 1000s
    (0..100_000_000)
        .into_par_iter()
        .map(|_| trial(&prefix, end, case_sensitive))
        .filter_map(|r| r)
        .try_for_each(print)?;
    Ok(())
}
