# Known Limitations

## Engine vs Runner Limitations

Wasbi distinguishes between engine limitations (in the interpreter itself)
and runner limitations (in the spec test runner or embedding tools).

### Engine Limitations

- No cross-module instance linking (re-exported function references across module boundaries)
- Rec group type canonicalization is not implemented (structurally identical rec groups are treated as distinct)
- Subtype validation does not check structural compatibility within rec groups

### Runner Limitations (not engine bugs)

- The spec test runner skips 82 legacy `assert_exception` directives (legacy EH proposal)
- The spec test runner uses synthetic host function stubs, not real syscalls

### Resource Limits

All limits are configurable via `Config`. Modules exceeding limits are
rejected at decode or instantiation time, never at runtime (except fuel).

### Determinism

- `ProofGrade` mode provides strict determinism: no floats, no SIMD, no threads
- `ReplayGrade` mode allows floats/SIMD but no threads
- `BestEffort` mode enables all features with no determinism guarantees
