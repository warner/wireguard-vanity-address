use bencher::Bencher;
use bencher::{benchmark_group, benchmark_main};

use wireguard_vanity_lib::trial;

fn bench_trial(bench: &mut Bencher) {
    let prefix: &str = "gratuitously long prefix that will never be found";
    let within = 10;
    bench.iter(|| {
        trial(&prefix, within);
    })
}

benchmark_group!(benches, bench_trial,);
benchmark_main!(benches);
