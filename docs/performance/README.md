# webTOS performance dashboard

- Source commit: `bdeb88653720f84e7d0c4d9d28bd69c5eefdc6f1`
- Runtime SHA-256: `2d06f1e272eed21432ebf051f646f36a49bb742813593060aaeb3beaf5f9ad10`
- Measured: `2026-08-29T15:21:36Z`

| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |
|---|---|---:|---:|---:|---:|---:|
| Native x86_64-linux | — | 262 ms | 3.43 s | 15.7 M inst/s | — | — |
| chromium | 151.0.7922.34 | 134 ms | 5.05 s | 10.7 M inst/s | 464 M iter/s | 3892 MiB |
| firefox | 153.0 | 1114 ms | 33.22 s | 1.6 M inst/s | 86 M iter/s | 3892 MiB |
| webkit | 26.5 | 133 ms | 4.34 s | 12.5 M inst/s | 460 M iter/s | 3892 MiB |

The adjacent JSON is the machine-readable authority. The verifier requires
all four hosts, exact cross-host guest instruction counts, the control module,
browser versions, the memory ceiling, and the measured runtime digest. Wall
times are evidence, not pass/fail thresholds.
