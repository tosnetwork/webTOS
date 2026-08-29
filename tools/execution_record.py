#!/usr/bin/env python3
"""Build and verify webTOS Execution Record V1 documents."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


RECORD_TYPE = "webtos.execution.v1"
ARTIFACT_FIELDS = {"path", "sha256", "size"}


def canonical(document: dict) -> bytes:
    return (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode()


def safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"artifact path is not relative and contained: {value!r}")
    return path


def contained_file(base: Path, value: str) -> tuple[PurePosixPath, Path]:
    relative = safe_path(value)
    resolved_base = base.resolve()
    resolved = (resolved_base / Path(relative)).resolve(strict=True)
    try:
        resolved.relative_to(resolved_base)
    except ValueError as error:
        raise ValueError(f"artifact path escapes through a symlink: {value!r}") from error
    if not resolved.is_file():
        raise ValueError(f"execution artifact is not a file: {value!r}")
    return relative, resolved


def artifact(base: Path, value: str) -> dict:
    relative, resolved = contained_file(base, value)
    payload = resolved.read_bytes()
    return {
        "path": str(relative),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def validate_receipts(receipts: object) -> list[dict]:
    if not isinstance(receipts, list):
        raise ValueError("network receipts must be an array")
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise ValueError("network receipt must be an object")
        if receipt.get("protocol") not in {"tcp", "udp"}:
            raise ValueError("network receipt has invalid protocol")
        if not isinstance(receipt.get("outcome"), str) or not receipt["outcome"]:
            raise ValueError("network receipt has no outcome")
        if receipt.get("peer") is not None and not isinstance(receipt.get("peer"), str):
            raise ValueError("network receipt peer is invalid")
        for field in ("bytes_sent", "bytes_received"):
            if type(receipt.get(field)) is not int or receipt[field] < 0:
                raise ValueError(f"network receipt has invalid {field}")
    return receipts


def validate_result(result: object) -> dict:
    if not isinstance(result, dict):
        raise ValueError("execution result must be an object")
    if result.get("status") not in {"halted", "failed", "budget_exhausted"}:
        raise ValueError("execution record has invalid result status")
    if type(result.get("exit_code")) is not int or not -(2**31) <= result["exit_code"] < 2**31:
        raise ValueError("execution record has invalid exit code")
    if type(result.get("instruction_count")) is not int or result["instruction_count"] < 0:
        raise ValueError("execution record has invalid instruction count")
    return result


def validate_envelope(envelope: object) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != ARTIFACT_FIELDS:
        raise ValueError("execution artifact envelope is incomplete or has unknown fields")
    if type(envelope.get("size")) is not int or envelope["size"] < 0:
        raise ValueError("execution artifact size is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", envelope.get("sha256", "")):
        raise ValueError("execution artifact digest is malformed")
    safe_path(envelope.get("path", ""))
    return envelope


def build(descriptor_path: Path) -> dict:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    base = descriptor_path.parent
    source_commit = descriptor.get("source_commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("descriptor needs a full lowercase source commit")
    workload = descriptor.get("workload", {})
    result = validate_result(descriptor.get("result"))
    if not workload.get("id") or not workload.get("version"):
        raise ValueError("descriptor needs workload id and version")
    inputs = descriptor.get("inputs")
    if not isinstance(inputs, list):
        raise ValueError("descriptor inputs must be an array")
    trace = descriptor.get("trace", {})
    trace_root = trace.get("root_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", trace_root):
        raise ValueError("descriptor needs a lowercase SHA-256 trace root")

    snapshots = descriptor.get("snapshots", {})
    record = {
        "build": {
            "runtime": artifact(base, descriptor["runtime"]),
            "source_commit": source_commit,
        },
        "inputs": [artifact(base, value) for value in inputs],
        "network": {
            "receipts": validate_receipts(descriptor.get("network", {}).get("receipts")),
            "recording": artifact(base, descriptor["network"]["recording"]),
        },
        "policy": artifact(base, descriptor["policy"]),
        "record_type": RECORD_TYPE,
        "result": {
            **result,
            "output": artifact(base, result["output"]),
        },
        "schema_version": 1,
        "snapshots": {
            name: None if snapshots.get(name) is None else artifact(base, snapshots[name])
            for name in ("before", "after")
        },
        "trace": {
            "artifact": artifact(base, trace["artifact"]),
            "root_sha256": trace_root,
        },
        "workload": {
            "id": workload["id"],
            "manifest": artifact(base, workload["manifest"]),
            "version": workload["version"],
        },
    }
    record["record_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    return record


def verify(record_path: Path) -> dict:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("schema_version") != 1 or record.get("record_type") != RECORD_TYPE:
        raise ValueError("not an Execution Record V1 document")
    claimed = record.get("record_sha256", "")
    unsigned = dict(record)
    unsigned.pop("record_sha256", None)
    if hashlib.sha256(canonical(unsigned)).hexdigest() != claimed:
        raise ValueError("execution record digest does not match its contents")
    if not re.fullmatch(r"[0-9a-f]{40}", record.get("build", {}).get("source_commit", "")):
        raise ValueError("execution record has no source commit")
    validate_receipts(record.get("network", {}).get("receipts"))
    workload = record.get("workload", {})
    result = validate_result(record.get("result"))
    if not workload.get("id") or not workload.get("version"):
        raise ValueError("execution record has no workload identity")
    if not isinstance(record.get("inputs"), list):
        raise ValueError("execution record inputs are invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", record.get("trace", {}).get("root_sha256", "")):
        raise ValueError("execution record trace root is invalid")

    envelopes = [
        record["build"]["runtime"],
        *record["inputs"],
        record["workload"]["manifest"],
        record["network"]["recording"],
        record["policy"],
        record["result"]["output"],
        record["trace"]["artifact"],
        record["snapshots"].get("before"),
        record["snapshots"].get("after"),
    ]
    for envelope in (item for item in envelopes if item is not None):
        validate_envelope(envelope)
        relative, resolved = contained_file(record_path.parent, envelope.get("path", ""))
        payload = resolved.read_bytes()
        if envelope.get("size") != len(payload):
            raise ValueError(f"execution artifact size differs: {relative}")
        if envelope.get("sha256") != hashlib.sha256(payload).hexdigest():
            raise ValueError(f"execution artifact digest differs: {relative}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    builder = subparsers.add_parser("build")
    builder.add_argument("descriptor", type=Path)
    builder.add_argument("output", type=Path)
    verifier = subparsers.add_parser("verify")
    verifier.add_argument("record", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        if args.output.resolve().parent != args.descriptor.resolve().parent:
            raise SystemExit("descriptor and output must be in the same artifact directory")
        document = build(args.descriptor.resolve())
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"built-execution-record {document['record_sha256']}")
    else:
        document = verify(args.record.resolve())
        print(f"verified-execution-record {document['record_sha256']}")


if __name__ == "__main__":
    main()
