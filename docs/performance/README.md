# webTOS performance dashboard

- Source commit: `f4d5d59282b2bfe5f0258947e7e988ddb7f260ff`
- Runtime SHA-256: `ebb8b7c28bc346149014db43ef1d7a294af36596d8b3de234e5b3092a67e2f53`
- Measured: `2026-08-29T14:16:06Z`

| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |
|---|---|---:|---:|---:|---:|---:|
| Native x86_64-linux | — | 274 ms | 3.44 s | 16.2 M inst/s | — | — |
| chromium | 151.0.7922.34 | 172 ms | 5.27 s | 10.3 M inst/s | 445 M iter/s | 3892 MiB |
| firefox | 153.0 | 1131 ms | 38.19 s | 1.4 M inst/s | 195 M iter/s | 3892 MiB |
| webkit | 26.5 | 163 ms | 5.15 s | 10.6 M inst/s | 473 M iter/s | 3892 MiB |

The adjacent JSON is the machine-readable authority. The verifier requires
all four hosts, exact cross-host guest instruction counts, the control module,
browser versions, the memory ceiling, and the measured runtime digest. Wall
times are evidence, not pass/fail thresholds.
