//! dudect-bencher binary. Classes: Left = tag wrong only in the last byte,
//! Right = tag wrong in the first byte. Both are rejected by every verifier.
//! Sample count per bench: env `CTV_N` (default 100000).

use ct_verify_jwt::*;
use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main_with_seeds, BenchRng, Class, CtRunner};

fn n_samples() -> usize {
    std::env::var("CTV_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}

fn classes(rng: &mut BenchRng) -> Vec<(Class, Flip, String)> {
    (0..n_samples())
        .map(|i| {
            let sub = format!("user-{i}-{}", rng.random::<u32>());
            if rng.random::<bool>() {
                (Class::Left, Flip::Last, sub)
            } else {
                (Class::Right, Flip::First, sub)
            }
        })
        .collect()
}

fn jwt_bench(runner: &mut CtRunner, rng: &mut BenchRng, f: fn(&str) -> bool) {
    let inputs: Vec<(Class, String)> = classes(rng)
        .into_iter()
        .map(|(c, fl, sub)| (c, token(&sub, fl)))
        .collect();
    for (c, t) in inputs {
        runner.run_one(c, || f(&t));
    }
}

fn raw_bench(runner: &mut CtRunner, rng: &mut BenchRng, f: fn(&[u8], &[u8]) -> bool) {
    let inputs: Vec<(Class, [u8; 32], [u8; 32])> = classes(rng)
        .into_iter()
        .map(|(c, fl, sub)| {
            let t = tag(sub.as_bytes());
            (c, t, flip(t, fl))
        })
        .collect();
    for (c, a, b) in inputs {
        runner.run_one(c, || f(&a, &b));
    }
}

fn slice_eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

fn crate_jsonwebtoken(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_jsonwebtoken)
}
fn crate_jwt_simple(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_jwt_simple)
}
fn crate_jwt(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_jwt)
}
fn ctrl_jwt_pos_naive_eq(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_ctrl_naive_eq)
}
fn ctrl_jwt_pos_early_exit(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_ctrl_early_exit)
}
fn ctrl_jwt_neg_subtle(r: &mut CtRunner, g: &mut BenchRng) {
    jwt_bench(r, g, verify_ctrl_subtle)
}
fn ctrl_raw_pos_naive_eq(r: &mut CtRunner, g: &mut BenchRng) {
    raw_bench(r, g, slice_eq)
}
fn ctrl_raw_pos_early_exit(r: &mut CtRunner, g: &mut BenchRng) {
    raw_bench(r, g, early_exit_eq)
}
fn ctrl_raw_neg_subtle(r: &mut CtRunner, g: &mut BenchRng) {
    raw_bench(r, g, subtle_eq)
}

ctbench_main_with_seeds!(
    (crate_jsonwebtoken, Some(0x1001)),
    (crate_jwt_simple, Some(0x1002)),
    (crate_jwt, Some(0x1003)),
    (ctrl_jwt_pos_naive_eq, Some(0x2001)),
    (ctrl_jwt_pos_early_exit, Some(0x2002)),
    (ctrl_jwt_neg_subtle, Some(0x2003)),
    (ctrl_raw_pos_naive_eq, Some(0x3001)),
    (ctrl_raw_pos_early_exit, Some(0x3002)),
    (ctrl_raw_neg_subtle, Some(0x3003))
);
