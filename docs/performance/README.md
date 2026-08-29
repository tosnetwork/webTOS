# webTOS performance dashboard

- Source commit: `a44f5817d3edbeddac1dbcdce51cf3d054da5594`
- Runtime SHA-256: `c2f606b9aa6c19a7078fb7bd6d175dadd613aa83d0f92250493b88dbf1d97296`
- Measured: `2026-08-29T11:07:47Z`

| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |
|---|---|---:|---:|---:|---:|---:|
| Native x86_64-linux | — | 262 ms | 3.68 s | 15.5 M inst/s | — | — |
| chromium | 151.0.7922.34 | 174 ms | 5.40 s | 10.9 M inst/s | 445 M iter/s | 3888 MiB |
| firefox | 153.0 | 1126 ms | 37.97 s | 1.4 M inst/s | 191 M iter/s | 3888 MiB |
| webkit | 26.5 | 168 ms | 5.20 s | 10.5 M inst/s | 472 M iter/s | 3888 MiB |

The adjacent JSON is the machine-readable authority. The verifier requires
all four hosts, exact cross-host guest instruction counts, the control module,
browser versions, the memory ceiling, and the measured runtime digest. Wall
times are evidence, not pass/fail thresholds.
