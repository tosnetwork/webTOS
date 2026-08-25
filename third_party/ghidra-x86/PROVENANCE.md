# Vendored: Ghidra x86 SLEIGH language definitions

- Upstream: https://github.com/icicle-emu/ghidra (icicle-emu fork of
  https://github.com/NationalSecurityAgency/ghidra)
- Commit: `50230050fa58bd40d5a96cab9c167fc55bc92a76`
- License: Apache-2.0 (see `LICENSE`)
- Contents: `Ghidra/Processors/x86/data/languages/` only.

The icicle-emu fork is required: the vendored `sleigh-compile` crate cannot
parse the current upstream NSA specifications. The `x64-engine` crate compiles
`languages/x86.ldefs` (language id `x86:LE:64:default`) at startup; this takes
roughly 120 ms.
