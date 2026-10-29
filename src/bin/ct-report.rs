//! Reads dudect-bencher output on stdin, prints a CSV and checks the
//! pre-registered control expectations. Exit 1 if a control misbehaves
//! (with `--check`), so CI fails visibly.

use ct_verify_jwt::{leaks, parse_dudect, T_THRESHOLD};
use std::io::Read;

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("stdin");
    let rs = parse_dudect(&s);
    println!("bench,n,max_t,max_tau,leak_|t|>{T_THRESHOLD}");
    for r in &rs {
        println!(
            "{},{:.0},{:.3},{:.5},{}",
            r.name,
            r.n,
            r.max_t,
            r.max_tau,
            leaks(r)
        );
    }
    let get = |n: &str| rs.iter().find(|r| r.name == n);
    let mut fails = Vec::new();
    if rs.len() != 9 {
        fails.push(format!("expected 9 bench lines, got {}", rs.len()));
    }
    for n in ["ctrl_raw_pos_early_exit", "ctrl_jwt_pos_early_exit"] {
        match get(n) {
            Some(r) if leaks(r) => {}
            _ => fails.push(format!(
                "positive control {n} did not show |t|>{T_THRESHOLD}"
            )),
        }
    }
    for n in ["ctrl_raw_neg_subtle", "ctrl_jwt_neg_subtle"] {
        match get(n) {
            Some(r) if !leaks(r) => {}
            _ => fails.push(format!(
                "negative control {n} showed |t|>{T_THRESHOLD} or is missing"
            )),
        }
    }
    for f in &fails {
        eprintln!("CONTROL FAIL: {f}");
    }
    if check && !fails.is_empty() {
        std::process::exit(1);
    }
}
