#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Independent BilateralReceipt verifier (FREEZE-VWE F3, R3-0 condition b).

NO SDK IMPORT. Dependencies: Python stdlib (json, hashlib, sys, pathlib) plus
PyNaCl for Ed25519. This script re-derives the signable bytes of a golden
BilateralReceipt carrying aud and action_ref from first principles and checks
both co-signatures, so the byte layout the TypeScript SDK signs is pinned by a
second, independent implementation.

RFC 8785 (JCS) canonicalization steps implemented here:
  1. Parse the receipt object from JSON.
  2. Remove exactly the three signature fields from the top level:
     requestingAgentSignature, servingAgentSignature, gatewaySignature.
     Everything else is the signed body.
  3. Serialize recursively:
     a. Object members sorted by key, comparing keys as sequences of UTF-16
        code units (Python sorts str by code point; for keys that contain no
        surrogate-pair characters, code-point order and UTF-16 code-unit
        order coincide; this vector's keys are ASCII).
     b. Strings serialized with the JCS minimal-escape rules: backslash and
        double quote escaped; control characters U+0000..U+001F escaped as
        \b \t \n \f \r where those shorthands exist, else \\u00XX; every other
        character emitted literally (UTF-8 on output).
     c. Arrays in element order.
     d. Literals true/false/null per JSON.
     e. Numbers per ECMAScript shortest round-trip. THIS SCRIPT REFUSES
        non-integer numbers: the golden vector deliberately contains no
        numbers at all, so the number branch is integers-only and any float
        aborts rather than risking a divergent serialization.
  4. Encode the canonical string as UTF-8. These are the signable bytes.
  5. Verify both Ed25519 signatures (64-byte hex) over those bytes against
     the raw 32-byte hex public keys (PyNaCl VerifyKey).

Relation to the SDK: the TS builder signs canonicalize(body) where
canonicalize (src/core/canonical.ts) is sorted-key JSON that OMITS keys whose
value is null or undefined; strict RFC 8785 preserves nulls. The golden vector
therefore carries NO null-valued keys (asserted below), a domain on which the
two procedures coincide byte for byte. A vector with null members would need
that divergence resolved first; this script refuses such input.

Usage:
  python3 tools/verify-bilateral-independent.py [path/to/golden.json]
  (default: test/gateway/fixtures/bilateral-receipt.golden.json)

Exit 0: both signatures verified over independently rebuilt bytes.
Exit 1: any check failed.
"""

import hashlib
import json
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

SIGNATURE_FIELDS = ("requestingAgentSignature", "servingAgentSignature", "gatewaySignature")


def jcs_escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            shorthand = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
            out.append(shorthand.get(o, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def assert_no_nulls(value, path="$"):
    if value is None:
        raise SystemExit(f"REFUSED: null value at {path}; strict JCS and the SDK "
                         f"canonicalize diverge on nulls, the golden vector must not carry any")
    if isinstance(value, dict):
        for k, v in value.items():
            assert_no_nulls(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            assert_no_nulls(v, f"{path}[{i}]")


def jcs_canonicalize(value) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        raise SystemExit("REFUSED: null reached the serializer (assert_no_nulls should have caught it)")
    if isinstance(value, str):
        return jcs_escape_string(value)
    if isinstance(value, bool):  # unreachable; bool handled above (bool is int subclass)
        raise AssertionError
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise SystemExit("REFUSED: non-integer number in the vector; this verifier is "
                         "integers-only by design (the golden vector carries no numbers)")
    if isinstance(value, list):
        return "[" + ",".join(jcs_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        # UTF-16 code-unit key order; equals code-point order for BMP-only keys.
        for k in value.keys():
            if any(ord(c) > 0xFFFF for c in k):
                raise SystemExit(f"REFUSED: astral-plane character in key {k!r}; UTF-16 "
                                 f"code-unit ordering not implemented for this case")
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(f"{jcs_escape_string(k)}:{jcs_canonicalize(v)}" for k, v in items) + "}"
    raise SystemExit(f"REFUSED: unsupported type {type(value).__name__}")


def main() -> int:
    default = Path(__file__).resolve().parent.parent / "test" / "gateway" / "fixtures" / "bilateral-receipt.golden.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    golden = json.loads(path.read_text(encoding="utf-8"))
    receipt = golden["receipt"]

    for required in ("aud", "action_ref"):
        if required not in receipt:
            print(f"FAIL: golden receipt does not carry {required}; R3-0(b) requires both")
            return 1

    body = {k: v for k, v in receipt.items() if k not in SIGNATURE_FIELDS}
    assert_no_nulls(body)
    canonical = jcs_canonicalize(body)
    signable = canonical.encode("utf-8")
    digest = hashlib.sha256(signable).hexdigest()

    print(f"vector: {path}")
    print(f"rebuilt canonical bytes: {len(signable)} bytes, sha256 {digest}")
    if "canonical_sha256" in golden:
        match = digest == golden["canonical_sha256"]
        print(f"matches fixture canonical_sha256: {match}")
        if not match:
            print("FAIL: independently rebuilt bytes differ from the fixture's record")
            return 1

    ok = True
    for label, sig_field, key_field in (
        ("requesting", "requestingAgentSignature", "requestingPublicKey"),
        ("serving", "servingAgentSignature", "servingPublicKey"),
    ):
        sig_hex = receipt[sig_field]
        pub_hex = golden[key_field]
        if len(pub_hex) != 64 or len(sig_hex) != 128:
            print(f"FAIL: {label}: key/signature length invalid")
            ok = False
            continue
        try:
            VerifyKey(bytes.fromhex(pub_hex)).verify(signable, bytes.fromhex(sig_hex))
            print(f"{label} signature: VALID (Ed25519 over rebuilt bytes)")
        except BadSignatureError:
            print(f"{label} signature: INVALID")
            ok = False

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
