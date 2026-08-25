# Security Policy

## Scope

Wasbi is a WebAssembly interpreter. Security-relevant concerns include:

- **Memory safety**: out-of-bounds reads/writes in linear memory, tables, or the GC heap
- **Stack safety**: operand stack and call stack overflow/underflow
- **Denial of service**: unbounded resource consumption (memory, fuel, recursion depth)
- **Logic bugs**: incorrect validation allowing malformed modules to execute

## Guarantees

- Zero `unsafe` blocks in the engine
- All memory, table, and stack accesses are bounds-checked
- Fuel-based execution metering prevents unbounded computation
- Configurable resource limits via `Config`

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue.
2. Email a description of the vulnerability, steps to reproduce, and any
   relevant WASM test case.
3. We will acknowledge receipt within 48 hours and provide an estimated
   timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
