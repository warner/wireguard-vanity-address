use base64;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar};
use rand_core::OsRng;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn trial(prefix: &str, start: usize, end: usize) -> Option<(String, String)> {
    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private);
    let public_b64 = base64::encode(public.as_bytes());
    if public_b64[start..end]
        .to_ascii_lowercase()
        .contains(&prefix)
    {
        let private_b64 = base64::encode(&private.to_bytes());
        Some((private_b64, public_b64))
    } else {
        None
    }
}

// To perform a fast search, our basic algorithm is:
// loop {
//  let base_privkey = new random scalar;
//  let add_privkey = 8;
//  let add_pubkey = scalarmult(8);
//
//  let mut offset = 0;
//  let mut trial_pubkey = scalarmult(base_privkey);
//  while !encoding(trial_pubkey).meets_target() {
//     offset += add_privkey
//     trial_pubkey += add_pubkey
//  }
//  privkey = base_privkey + offset
//  yield (privkey, trial_pubkey)
// }

// We reset to a new random base_privkey after each matching keypair,
// otherwise someone who learns one privkey can easily find the others.
// We offset by 8 to make sure that each new privkey will meet the same
// clamping criteria: we assume the keyspace is large enough that we're
// unlikely to wrap around.

// To implement this in curve25519, we have to dance around two different
// representations of scalars.

// x25519 private keys are scalars in the large prime-order subgroup of
// the points on Curve25519. The order of this subgroup is named "l",
// which is a number somewhat larger than 2^252. For convenience later,
// we'll define this number as "big+small", where big=2^252 and small is
// the remainder ("small" is a bit larger than 2^128). The hex
// representation of "small" ends in 0xD3ED, so "l"%8 is 5.

// The x25519-dalek implementation (StaticSecret or EphemeralSecret)
// represents these as 256-bit integers with 5 bits "clamped" in various
// ways: the high-order two bits are set to 0b01, and the low-order three
// bits are set to 0b000. Therefore the integers "s" are in the range
// 2^254 to 2^255-1, and s%8==0. These "clamped" keys can represent
// slightly fewer than half of the possible private keys (2^251 out of
// "l").

// Why clamp? The 2^255 bit is cleared to make sure that "add" won't
// overflow a 256-bit container. The 2^254 bit is set for the sake of an
// unwise montgomery ladder implementation whose runtime reveals the
// number of leading zero bits: all private keys have the same such
// number (one), thus the attacker doesn't learn anything new. The low
// three bits are clamped for the sake of an unwise/faster verifier which
// doesn't check that the received point is a member of the right group,
// enabling a small-subgroup attack that reveals the private key mod 8
// (the curve group's cofactor). By setting those bits to a fixed value,
// the attacker has nothing to learn. (I'm not exactly sure what they
// *do* learn: I suspect it's ((p%l)%8), and the fact that (p%8)==0
// doesn't necessarily mean that ((p%l)%8) is a fixed number: they might
// learn the top three bits of p instead).

// Curve25519::Scalar values don't do much clamping, but *are* always
// reduced mod "l". Three constructors ("from_bytes_mod_order",
// "from_bytes_mod_order_wide", and "from_canonical_bytes") can only
// produce reduced scalars. The remaining one ("from_bits") can produce
// non-reduced scalars: the high bit is still cleared to make sure that
// "add" won't overflow, but the other bits are left alone. However the
// "add" method (and others) always reduce modulo "l" before returning a
// result, so it's not possible to keep things unreduced for very long.

// Converting from an x25519-dalek StaticSecret representation to a
// curve25519-dalek Scalar is easy:
// Scalar::from_bytes_mod_order(ss.to_bytes()). But how can we map in the
// opposite direction? When we call StaticSecret::from_bits(), it's going
// to clamp both ends, and if that clamping actually changes any bits,
// the numerical value of the private key will be wrong. So we must
// ensure that both ends are pre-clamped before handing it over.

// Since "l" is about 2^252, and a StaticSecret holds 255 bits, each
// Scalar "s" (in the range 0.."l") has roughly 8 aliases: eight
// different 255-bit numbers which are equivalent (mod "l"), whose values
// are s+kl (k=0..7). The four high-order bits of a reduced scalar are
// usually 0b0000. With vanishingly small probability ("small"/"l", ~=
// 2^-124), the scalar might be larger than 2^252, but we can effectively
// ignore this. The aliases (with high probability) have distinct
// high-order bits: 0b0001, 0b0010, etc. We want one of the four aliases
// whose high-order bits are 0b01xx: these bits will survive the high-end
// clamping unchanged. These are where k=[4..7].

// The three low-order bits will be some number N. Each alias adds l%8 to
// this low end. So the first alias (k=1) will end in N+5, the second
// (k=2) will end in N+2 (since (5+5)%8 == 2). Our k=4..7 yields
// N+4,N+1,N+6,N+3. One of these values might be all zeros. That alias
// will survive the low-end clamping unchanged.

// We can't use Scalars to add "l" and produce the aliases: any addition
// we do on the Scalar will be reduced immediately. But we can add
// "small", and then manually adjust the high-end byte, to produce an
// array of bytes whose value is s+kl, and hand it over to
// StaticSecret::from(bytes) to get an x25519 private key. The private
// key will be in the same equivalence class as our original Scalar, but
// its binary representation will be different.

// This conversion from Scalar to clamping-compatible bytes is the last
// thing we do, both to emit a wireguard-suitable private key string, and
// to double-check that our keypair actually works. We also do this
// conversion at the very beginning, to make sure that the random
// starting point is actually going to work.

// the resulting algorithm is:
// loop {
//  let x = StaticSecret::new(&mut OsRng);
//  let base_scalar = Scalar::from_bytes_mod_order(x.to_bytes());
//  if x.to_bytes() != convert(base_scalar) { break; } // try again
//  let add_privkey = Scalar::from_bytes_mod_order(to_array(8));
//  let add_pubkey = add_privkey * ED25519_BASEPOINT_POINT;
//
//  let mut current_offset = Scalar::from_bytes_mod_order(to_array(0));
//  let mut trial_pubkey = base_scalar * ED25519_BASEPOINT_POINT;
//  while !encoding(trial_pubkey).meets_target() {
//     current_offset += add_privkey;
//     trial_pubkey += add_pubkey;
//  }
//  privkey = convert(base_scalar + offset)
//  yield (privkey, trial_pubkey)
// }

// where encoding() converts to Montgomery form, then to bytes, then to
// base64, then applies the vanity prefix check

fn add_big(input: [u8; 32], multiple: usize) -> [u8; 32] {
    let mut out = input;
    for _ in 0..multiple {
        out[31] += 0b0001_0000;
    }
    out
}

fn survives_clamping(input: &[u8; 32]) -> bool {
    *input == StaticSecret::from(*input).to_bytes()
}

fn print_bytes(name: &str, b: &[u8; 32]) {
    println!("{} 0x{:02x} {:?} 0x{:02x}", name, b[0], b, b[31]);
}

fn congruent_to(s: Scalar, b: &[u8; 32]) -> bool {
    let s2 = Scalar::from_bytes_mod_order(*b);
    s == s2
}

#[cfg(off)]
fn display_scalar(s: Scalar) -> String {
    let mut st = String::new();
    for b in s.to_bytes().iter().rev() {
        st.push_str(format!("{:02x}", b).as_str());
    }
    st
}

fn convert_scalar_to_privkey(s: Scalar) -> StaticSecret {
    // L:     0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    // big:   0x1000000000000000000000000000000000000000000000000000000000000000
    // small: 0x0000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

    let zero = Scalar::from_bytes_mod_order([0u8; 32]);
    let mut big_bytes = [0u8; 32];
    big_bytes[31] = 0b0001_0000;
    let big = Scalar::from_bytes_mod_order(big_bytes);
    let small: Scalar = zero - big;
    //println!("small: {}", display_scalar(small));

    let alias4_small = s + small + small + small + small;
    let alias4_bytes = add_big(alias4_small.to_bytes(), 4);

    let alias5_small = alias4_small + small;
    let alias5_bytes = add_big(alias5_small.to_bytes(), 5);

    let alias6_small = alias5_small + small;
    let alias6_bytes = add_big(alias6_small.to_bytes(), 6);

    let alias7_small = alias6_small + small;
    let alias7_bytes = add_big(alias7_small.to_bytes(), 7);

    if false {
        print_bytes("orig s", &s.to_bytes());
        print_bytes("alias4", &alias4_bytes);
        print_bytes("alias5", &alias5_bytes);
        print_bytes("alias6", &alias6_bytes);
        print_bytes("alias7", &alias7_bytes);

        println!(
            "alias4 {} {}",
            survives_clamping(&alias4_bytes),
            congruent_to(s, &alias4_bytes)
        );
        println!(
            "alias5 {} {}",
            survives_clamping(&alias5_bytes),
            congruent_to(s, &alias5_bytes)
        );
        println!(
            "alias6 {} {}",
            survives_clamping(&alias6_bytes),
            congruent_to(s, &alias6_bytes)
        );
        println!(
            "alias7 {} {}",
            survives_clamping(&alias7_bytes),
            congruent_to(s, &alias7_bytes)
        );
    }

    // this panics rather than returning an Option because we should
    // always be starting from a well-behaved scalar, and should never
    // get into the situation where we can't convert it
    let alias_bytes = match s.to_bytes()[0] & 0b0111 {
        4 => alias4_bytes,
        7 => alias5_bytes,
        2 => alias6_bytes,
        5 => alias7_bytes,
        _ => panic!("unable to convert scalar"),
    };
    let privkey = StaticSecret::from(alias_bytes);
    assert_eq!(alias_bytes, privkey.to_bytes());
    privkey
}

fn integer_to_scalar(int: u64) -> Scalar {
    let bytes = int.to_le_bytes();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..8].clone_from_slice(&bytes[..8]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub struct Seed {
    base_scalar: Scalar,
}

pub struct Scan {
    add_count: u64,
    add_pubkey: EdwardsPoint,
    count: u64,
    current_pubkey: EdwardsPoint,
}

pub struct ScanProgress {
    add_count: u64,
    add_pubkey: EdwardsPoint,
    count: u64,
    current_pubkey: EdwardsPoint,
    update_interval: Duration,
    last_update: Instant,
    last_count: u64,
}

impl Seed {
    pub fn generate() -> Seed {
        let x = StaticSecret::new(&mut OsRng);
        let base_scalar = Scalar::from_bytes_mod_order(x.to_bytes());
        if x.to_bytes() != convert_scalar_to_privkey(base_scalar).to_bytes() {
            panic!("shouldn't happen");
            // but if for some reason we can't avoid it, we could just re-roll
            // return None;
        }
        Seed { base_scalar }
    }

    /// Returns an iterator that yields (count, points). The point can be
    /// converted into a public key (and filtered for suitability). The count
    /// can be combined with the base scalar and converted into the
    /// corresponding private key.
    pub fn scan(&self) -> Scan {
        Scan {
            add_count: 8,
            add_pubkey: integer_to_scalar(8) * ED25519_BASEPOINT_POINT,
            count: 0,
            current_pubkey: self.base_scalar * ED25519_BASEPOINT_POINT,
        }
    }

    pub fn scan_progress(&self) -> ScanProgress {
        ScanProgress {
            add_count: 8,
            add_pubkey: integer_to_scalar(8) * ED25519_BASEPOINT_POINT,
            count: 0,
            current_pubkey: self.base_scalar * ED25519_BASEPOINT_POINT,
            update_interval: Duration::new(1, 0),
            last_update: Instant::now(),
            last_count: 0,
        }
    }

    pub fn convert_count_to_privkey(&self, count: u64) -> StaticSecret {
        let winning_scalar = self.base_scalar + integer_to_scalar(count);
        convert_scalar_to_privkey(winning_scalar)
    }

    pub fn convert_both(&self, both: (u64, EdwardsPoint)) -> (StaticSecret, PublicKey) {
        let (count, point) = both;
        let privkey = self.convert_count_to_privkey(count);
        let pubkey_bytes = point.to_montgomery().to_bytes();
        let pubkey = PublicKey::from(pubkey_bytes);
        assert_eq!(PublicKey::from(&privkey).as_bytes(), pubkey.as_bytes());
        (privkey, pubkey)
    }
}

impl Iterator for Scan {
    type Item = (u64, EdwardsPoint);
    fn next(&mut self) -> Option<(u64, EdwardsPoint)> {
        // We try up to 2^64/8 steps from each starting Seed. At roughly
        // 4us/step, this will take ~250k years to wrap. So this check could
        // arguably be removed.
        if self.count >= 0xffff_ffff_ffff_fff0 {
            return None;
        }
        self.count += self.add_count;
        self.current_pubkey += self.add_pubkey;
        Some((self.count, self.current_pubkey))
    }
}

pub enum ScanResults {
    Trial(u64, EdwardsPoint),
    Progress(u64, f64), // total trials, total seconds
}

impl ScanResults {
    fn get_rate(&self) -> Option<f64> {
        match self {
            ScanResults::Progress(trials, seconds) => Some((*trials as f64) / *seconds),
            _ => None,
        }
    }
}

impl Iterator for ScanProgress {
    type Item = ScanResults;
    fn next(&mut self) -> Option<ScanResults> {
        use ScanResults::*;
        if self.count & 1024 == 0 {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_update);
            if elapsed > self.update_interval {
                let counted = self.count - self.last_count;
                self.last_count = self.count;
                self.last_update = now;
                return Some(Progress(counted, elapsed.as_secs_f64()));
            }
        }
        // We try up to 2^64/8 steps from each starting Seed. At roughly
        // 4us/step, this will take ~250k years to wrap. So this check could
        // arguably be removed.
        if self.count >= 0xffff_ffff_ffff_fff0 {
            return None;
        }
        self.count += self.add_count;
        self.current_pubkey += self.add_pubkey;
        Some(Trial(self.count, self.current_pubkey))
    }
}

pub fn make_check_predicate(
    prefix: &str,
    start: usize,
    end: usize,
) -> impl Fn(&EdwardsPoint) -> bool {
    let prefix = String::from(prefix);
    move |point| {
        let public_b64 = base64::encode(point.to_montgomery().as_bytes());
        //println!("trial: {}", public_b64);
        public_b64[start..end]
            .to_ascii_lowercase()
            .contains(&prefix)
    }
}

pub fn search<T>(check: T) -> (StaticSecret, PublicKey)
where
    T: Fn(&EdwardsPoint) -> bool,
{
    let seed = Seed::generate();
    let both = seed.scan().find(|(_, point)| check(&point)).unwrap();
    seed.convert_both(both)
}

pub fn search_for_prefix(prefix: &str, start: usize, end: usize) -> (StaticSecret, PublicKey) {
    let check = make_check_predicate(prefix, start, end);
    let seed = Seed::generate();
    let both = seed.scan().find(|(_, point)| check(&point)).unwrap();
    seed.convert_both(both)
}

/// returns checks per second
pub fn measure_rate() -> f64 {
    use ScanResults::*;
    // prefix with characters that will never match
    let check = make_check_predicate("****", 0, 10);
    Seed::generate()
        .scan_progress()
        .map(|res| {
            // timing includes the work of checking the pubkey
            if let Trial(_count, point) = res {
                check(&point);
            };
            res
        })
        .find_map(|res| res.get_rate())
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_search() {
        let check = make_check_predicate("aaa", 0, 10);
        let (privkey, pubkey) = search(check);
        println!(
            "priv: {}, pub: {}",
            base64::encode(&privkey.to_bytes()),
            base64::encode(&pubkey.as_bytes())
        );
    }

    #[test]
    fn test_rate() {
        let speed = measure_rate();
        println!("speed: {:.3e} keys per second", speed);
    }
}
