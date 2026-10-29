use ct_verify_jwt::*;

type V = fn(&str) -> bool;
const ALL: [(&str, V); 6] = [
    ("jsonwebtoken", verify_jsonwebtoken),
    ("jwt-simple", verify_jwt_simple),
    ("jwt", verify_jwt),
    ("ctrl_naive_eq", verify_ctrl_naive_eq),
    ("ctrl_early_exit", verify_ctrl_early_exit),
    ("ctrl_subtle", verify_ctrl_subtle),
];

#[test]
fn valid_token_accepted_by_all() {
    let t = token("alice", Flip::None);
    for (n, f) in ALL {
        assert!(f(&t), "{n} rejected a valid token");
    }
}

#[test]
fn both_timing_classes_rejected_by_all() {
    // The two dudect classes must take the same (reject) path.
    for f_kind in [Flip::First, Flip::Last] {
        let t = token("alice", f_kind);
        for (n, f) in ALL {
            assert!(!f(&t), "{n} accepted a token with {f_kind:?} byte altered");
        }
    }
}

#[test]
fn wrong_key_rejected_by_all() {
    // Token signed with a different key (hand-built).
    use base64::Engine;
    use hmac::Mac;
    let si = signing_input("alice");
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"another key").unwrap();
    m.update(si.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(m.finalize().into_bytes());
    let t = format!("{si}.{sig}");
    for (n, f) in ALL {
        assert!(!f(&t), "{n} accepted a token signed with another key");
    }
}

#[test]
fn flip_changes_exactly_one_byte() {
    let si = signing_input("bob");
    let t = tag(si.as_bytes());
    let a = flip(t, Flip::First);
    let b = flip(t, Flip::Last);
    assert_eq!(t.iter().zip(a.iter()).filter(|(x, y)| x != y).count(), 1);
    assert_eq!(t.iter().zip(b.iter()).filter(|(x, y)| x != y).count(), 1);
    assert_ne!(a[0], t[0]);
    assert_ne!(b[31], t[31]);
}

#[test]
fn early_exit_eq_is_correct() {
    assert!(early_exit_eq(b"abc", b"abc"));
    assert!(!early_exit_eq(b"abc", b"abd"));
    assert!(!early_exit_eq(b"abc", b"ab"));
}

#[test]
fn parse_dudect_line() {
    let out = "running 2 benchmarks\nbench a seeded with 0x0000000000001001\nbench a ... : n == +0.100M, max t = -61.61472, max tau = -0.28863, (5/tau)^2 = 300\nbench b ... : n == +0.050M, max t = +1.20000, max tau = +0.00500, (5/tau)^2 = 1000000\n";
    let r = parse_dudect(out);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].name, "a");
    assert!((r[0].n - 100_000.0).abs() < 1.0);
    assert!((r[0].max_t + 61.61472).abs() < 1e-9);
    assert!(leaks(&r[0]));
    assert!(!leaks(&r[1]));
}
