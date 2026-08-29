# webTOS performance dashboard

- Source commit: `170cc6cc08c0dcd6b10dbce71b789238f3c23d8f`
- Runtime SHA-256: `4fcedd62386cc4dde2b5fe1011df84a15bceed753ffe46c5b826b3f9e15288fc`
- Measured: `2026-08-29T12:50:31Z`

| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |
|---|---|---:|---:|---:|---:|---:|
| Native x86_64-linux | — | 261 ms | 3.43 s | 16.3 M inst/s | — | — |
| chromium | 151.0.7922.34 | 174 ms | 4.96 s | 11.0 M inst/s | 445 M iter/s | 3888 MiB |
| firefox | 153.0 | 1141 ms | 37.83 s | 1.4 M inst/s | 187 M iter/s | 3888 MiB |
| webkit | 26.5 | 165 ms | 5.19 s | 10.6 M inst/s | 473 M iter/s | 3888 MiB |

The adjacent JSON is the machine-readable authority. The verifier requires
all four hosts, exact cross-host guest instruction counts, the control module,
browser versions, the memory ceiling, and the measured runtime digest. Wall
times are evidence, not pass/fail thresholds.
