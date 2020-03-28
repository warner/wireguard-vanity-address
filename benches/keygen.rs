use criterion::{black_box, criterion_group, criterion_main, Criterion};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, montgomery::MontgomeryPoint,
    scalar::Scalar,
};
use rand_core::OsRng;

use wireguard_vanity_lib::{make_check_predicate, Seed};

fn b1_point_generation(c: &mut Criterion) {
    let seed = Seed::generate();
    let mut scan = seed.scan();
    c.bench_function("b1_point_generation", |b| b.iter(|| scan.next()));
}

fn b2a_point_conversion(c: &mut Criterion) {
    let ed_point: EdwardsPoint = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
    c.bench_function("b2a_point_conversion", |b| {
        b.iter(|| ed_point.to_montgomery())
    });
}

fn b2b_point_to_bytes(c: &mut Criterion) {
    let ed_point: EdwardsPoint = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
    let mt_point: MontgomeryPoint = ed_point.to_montgomery();
    c.bench_function("b2b_point_to_bytes", |b| b.iter(|| mt_point.as_bytes()));
}

fn b2c_bytes_to_base64(c: &mut Criterion) {
    let ed_point: EdwardsPoint = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
    let mt_point: MontgomeryPoint = ed_point.to_montgomery();
    let bytes = mt_point.as_bytes();
    c.bench_function("b2c_bytes_to_base64", |b| {
        b.iter(|| base64::encode(black_box(&bytes)))
    });
}

fn b2d_base64_contains(c: &mut Criterion) {
    let ed_point: EdwardsPoint = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
    let mt_point: MontgomeryPoint = ed_point.to_montgomery();
    let bytes = mt_point.as_bytes();
    let public_b64 = base64::encode(bytes);
    c.bench_function("b2d_base64_contains", |b| {
        b.iter(|| public_b64[0..10].to_ascii_lowercase().contains("****"))
    });
}

fn b2e_total_point_checking(c: &mut Criterion) {
    let check = make_check_predicate("****", 0, 10);
    let seed = Seed::generate();
    let mut scan = seed.scan();
    let (_count, point) = scan.next().unwrap();
    c.bench_function("b2e_total_point_checking", |b| {
        b.iter(|| check(black_box(&point)))
    });
}

fn b3_point_generation_and_checking(c: &mut Criterion) {
    let check = make_check_predicate("****", 0, 10);
    let seed = Seed::generate();
    let mut scan = seed.scan();
    c.bench_function("b3_point_generation_and_checking", |b| {
        b.iter(|| {
            let (_count, point) = scan.next().unwrap();
            check(&point)
        })
    });
}

criterion_group!(
    benches,
    b1_point_generation,
    b2a_point_conversion,
    b2b_point_to_bytes,
    b2c_bytes_to_base64,
    b2d_base64_contains,
    b2e_total_point_checking,
    b3_point_generation_and_checking,
);
criterion_main!(benches);
