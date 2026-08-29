# webTOS performance dashboard

- Source commit: `1abe0130d2c805567cddd576b15fda04506ca93c`
- Runtime SHA-256: `8491ee0580a8d8d4498fed9c714c0d43b167289e71f4e186baf625685ef76f08`
- Measured: `2026-08-29T15:41:42Z`

| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |
|---|---|---:|---:|---:|---:|---:|
| Native x86_64-linux | — | 262 ms | 3.43 s | 15.7 M inst/s | — | — |
| chromium | 151.0.7922.34 | 135 ms | 5.05 s | 10.7 M inst/s | 463 M iter/s | 3892 MiB |
| firefox | 153.0 | 1118 ms | 33.88 s | 1.6 M inst/s | 86 M iter/s | 3892 MiB |
| webkit | 26.5 | 135 ms | 4.47 s | 12.2 M inst/s | 461 M iter/s | 3892 MiB |

The adjacent JSON is the machine-readable authority. The verifier requires
all four hosts, exact cross-host guest instruction counts, the control module,
browser versions, the memory ceiling, and the measured runtime digest. Wall
times are evidence, not pass/fail thresholds.
