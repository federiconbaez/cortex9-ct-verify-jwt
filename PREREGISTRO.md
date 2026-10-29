# Prerregistro de la medición / Measurement pre-registration

Escrito y commiteado antes de la corrida de medición.
Written and committed before the measurement run.

**Divulgación / disclosure:** antes de este commit se hizo una sola corrida de humo con `CTV_N=2000` para comprobar que el binario corre. Sus números no se usan. / Before this commit a single smoke run with `CTV_N=2000` was made to check the binary runs. Its numbers are not used.

Comando / command (dos corridas independientes / two independent runs):

```sh
cargo build --release
CTV_N=200000 ./target/release/ctbench > results/run1.txt
CTV_N=200000 ./target/release/ctbench > results/run2.txt
./target/release/ct-report --check < results/run1.txt > results/run1.csv
./target/release/ct-report --check < results/run2.txt > results/run2.csv
```

Clases / classes: Left = tag HS256 con sólo el último byte (31) alterado; Right = tag con el primer byte (0) alterado. Ambas se rechazan por el mismo camino (test `both_timing_classes_rejected_by_all`). Una comparación con salida temprana tarda más en Left.

Umbral / threshold: `|max t| > 4.5` = fuga / leak.

| Bench | Rol / role | Esperado / expected | Criterio / pass if |
|---|---|---|---|
| `ctrl_raw_pos_early_exit` | control positivo, bucle con salida temprana sobre 32 bytes | fuga | \|t\| > 4.5 en ambas corridas |
| `ctrl_jwt_pos_early_exit` | control positivo, mismo bucle dentro de parse + HMAC | fuga | \|t\| > 4.5 en ambas corridas |
| `ctrl_raw_neg_subtle` | control negativo, `subtle::ConstantTimeEq` | sin fuga | \|t\| ≤ 4.5 en ambas corridas |
| `ctrl_jwt_neg_subtle` | control negativo dentro de parse + HMAC | sin fuga | \|t\| ≤ 4.5 en ambas corridas |
| `ctrl_raw_pos_naive_eq`, `ctrl_jwt_pos_naive_eq` | `==` de slices (control positivo pedido) | **abierto**: `==` de `[u8]` baja a `memcmp`/`bcmp`, que para 32 bytes puede no tener salida temprana observable | se reporta tal cual; si no muestra fuga, se dice |
| `crate_jsonwebtoken`, `crate_jwt_simple`, `crate_jwt` | crates bajo prueba | sin fuga (los tres usan comparación de tiempo constante según su código fuente) | fuga sólo si \|t\| > 4.5 en ambas corridas; una sola = inconcluso |

Si un control positivo `early_exit` no muestra fuga o un control negativo sí, la medición se declara inválida en esta máquina. / If an early-exit positive control shows no leak, or a negative control does, the measurement is declared invalid on this machine.

Límites conocidos antes de medir / known limits before measuring:
- Máquina compartida y virtualizada, sin aislar CPU ni fijar frecuencia. / Shared VM, no CPU isolation or frequency pinning.
- dudect no prueba tiempo constante: \|t\| ≤ 4.5 sólo dice que no se detectó fuga con estas clases y este n. / dudect cannot prove constant time.
- Sólo HS256 y sólo la comparación del tag; no se miden parseo de base64 ni JSON con entradas secretas. / HS256 tag comparison only.
