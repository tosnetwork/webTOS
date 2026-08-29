# Execution Record V1

Execution Record V1 is the smallest portable evidence envelope for one
webTOS run. It binds the runtime build, workload manifest, explicit input
artifacts, policy, before and after filesystem snapshots, network recording
and classified network receipts, terminal output and result, retired
instruction count, and the architectural trace artifact plus its trace root.

The JSON contract has `record_type = "webtos.execution.v1"` and
`schema_version = 1`. Every external artifact is represented by a contained
relative path, byte length and SHA-256. `record_sha256` is SHA-256 over the
canonical JSON document without that field (sorted keys, compact separators,
one trailing newline). The source build is identified by a full Git commit.

Network receipts contain `protocol`, guest-visible `peer`, `bytes_sent`,
`bytes_received`, and `outcome`; the recording artifact remains the replayable
event authority. A snapshot may be `null` when the run deliberately has no
before or after state. `inputs` is an array (empty when the workload has no
external input). `result.output` is required. `trace.artifact` binds the
portable trace bytes and `trace.root_sha256` binds the runtime's trace-chain
root; both are mandatory even for a failed or budget-exhausted run.

Build and verify a record from a descriptor whose paths are relative to the
descriptor directory. The output record stays in that same artifact directory:

```bash
python3 tools/execution_record.py build descriptor.json execution.json
python3 tools/execution_record.py verify execution.json
```

Verification fails on a changed record, changed artifact, missing build or
workload identity, malformed receipt, or a path that escapes the record
directory. This is an integrity and replay binding, not an attestation: V1
does not claim who ran the workload or that a trusted platform executed it.
