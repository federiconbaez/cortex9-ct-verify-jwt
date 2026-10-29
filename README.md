# ct-verify-jwt

Test estadístico de tiempo constante ([dudect-bencher](https://crates.io/crates/dudect-bencher) 0.7) sobre la verificación HS256 de JWT en tres crates de Rust: `jsonwebtoken`, `jwt-simple` y `jwt`, con controles positivos y negativos.

Statistical constant-time test (dudect-bencher 0.7) of HS256 JWT verification in three Rust crates: `jsonwebtoken`, `jwt-simple` and `jwt`, with positive and negative controls.

> **ES** primero · **EN** abajo. Nivel de verificación: **B** (ver abajo).

---

## ES

### Qué hay

| Pieza | Qué hace |
|---|---|
| `src/lib.rs` | Arma tokens HS256 con un byte del tag alterado y envuelve la verificación de cada crate. |
| `src/bin/ctbench.rs` | 9 benches de dudect-bencher con semilla fija. Clase Left: tag con sólo el último byte mal. Clase Right: tag con el primer byte mal. Las dos se rechazan por el mismo camino. |
| `src/bin/ct-report.rs` | Pasa la salida a CSV y con `--check` sale con 1 si un control falla. |
| `tests/verifiers.rs` | Token válido aceptado, las dos clases y otra clave rechazadas en los 6 verificadores; parser. |

Crates bajo prueba: `jsonwebtoken` 11.1.0 (feature `rust_crypto`), `jwt-simple` 0.15.0 (feature `pure-rust`), `jwt` 0.16.0.

### Medición

Prerregistrada en [`PREREGISTRO.md`](PREREGISTRO.md) (commit anterior a la corrida). Umbral: `|max t| > 4.5` = fuga.

```sh
cargo build --release
CTV_N=200000 ./target/release/ctbench > results/run1.txt
./target/release/ct-report --check < results/run1.txt
```

| Bench | Rol | max t corrida 1 | max t corrida 2 | Fuga |
|---|---|---|---|---|
| `crate_jsonwebtoken` | crate | +1.94 | +1.72 | no detectada |
| `crate_jwt_simple` | crate | +1.99 | +1.64 | no detectada |
| `crate_jwt` | crate | +2.57 | +1.93 | no detectada |
| `ctrl_raw_pos_early_exit` | control +, bucle con salida temprana, 32 bytes | +464.45 | +643.82 | **sí** |
| `ctrl_jwt_pos_early_exit` | control +, mismo bucle con parse + HMAC | +127.89 | +227.28 | **sí** |
| `ctrl_raw_pos_naive_eq` | `==` de slices, 32 bytes | +2.13 | +1.69 | no detectada |
| `ctrl_jwt_pos_naive_eq` | `==` de slices con parse + HMAC | +2.16 | +2.42 | no detectada |
| `ctrl_raw_neg_subtle` | control −, `subtle::ConstantTimeEq` | −0.97 | −2.01 | no |
| `ctrl_jwt_neg_subtle` | control −, con parse + HMAC | −2.13 | +2.12 | no |

Salida cruda y CSV en [`results/`](results/).

Lectura:
- Los tres crates no muestran fuga con estas clases. Coincide con su código fuente: `jsonwebtoken` y `jwt` llaman a `Mac::verify_slice` del crate `hmac`, y `jwt-simple` usa `ct_codecs::verify`.
- El detector funciona en esta máquina: el bucle con salida temprana da |t| entre 128 y 644, y `subtle` queda por debajo de 2.2.
- **El control positivo pedido (`==`) no mostró fuga.** `==` sobre `[u8]` baja a `memcmp`/`bcmp`, y para 32 bytes no se observó salida temprana. Eso no hace seguro a `==`: depende de la libc, el largo y la CPU. Por eso el control positivo efectivo es el bucle explícito.

### Tests

`cargo test`: 6/6. Ningún test se saltea.

### Nivel de verificación

**B**: el mecanismo está medido, con controles positivos y negativos y dos corridas. No es B+ porque no hay una línea base que superar, y no es C porque no se probó un ataque remoto real.

### Límites

- Máquina virtual compartida, sin aislar CPU. El CI vuelve a correr con `CTV_N=100000` y sólo exige que los controles se comporten.
- dudect no prueba tiempo constante. |t| ≤ 4.5 sólo dice que no se detectó fuga con estas clases y este n.
- Sólo HS256 y sólo la comparación del tag. No mide ES256/EdDSA, parseo de base64/JSON, ni DPoP.
- `n` en el CSV es el tamaño de la sub-muestra recortada que dio el max t, no el total (200000).

### Fuentes leídas

- README y `src/` de `dudect-bencher` 0.7.0 (formato de salida y semillas).
- Código de comparación de `jsonwebtoken` 11.1.0 (`src/crypto/rust_crypto/hmac.rs`), `jwt-simple` 0.15.0 (`src/algorithms/hmac.rs`) y `jwt` 0.16.0 (`src/algorithm/rust_crypto.rs`).
- API de crates.io para versiones y repositorios: `https://crates.io/api/v1/crates/<nombre>`.

---

## EN

### What is here

A library that builds HS256 tokens with one tag byte altered and wraps each crate's verifier; a 9-bench dudect-bencher binary (Left: only the last tag byte wrong; Right: the first byte wrong; both rejected by the same path); a reporter that emits CSV and, with `--check`, exits 1 if a control misbehaves.

### Measurement

Pre-registered in `PREREGISTRO.md`. Threshold `|max t| > 4.5`. Two runs of 200000 samples per bench (table above): none of the three crates shows a leak; the early-exit loop control shows |t| 128–644; `subtle` stays below 2.2. **The requested `==` positive control did not leak**: slice `==` lowers to `memcmp`/`bcmp`, which showed no observable early exit at 32 bytes. That does not make `==` safe; the effective positive control is the explicit loop.

### Verification level

**B**: mechanism measured with positive and negative controls and two runs. Not B+ (no baseline to beat), not C (no real remote attack).

### Limits

Shared VM, no CPU isolation; dudect cannot prove constant time; HS256 tag comparison only; CSV `n` is the cropped sub-sample behind max t.

## License

Apache-2.0.
