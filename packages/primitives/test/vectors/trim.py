#!/usr/bin/env python3
"""Trim the upstream test-vector files into the subsets this directory holds.

Usage: trim.py <wycheproof checkout> <ACVP-Server checkout> <out dir>

Every output file records the upstream repository, the commit it was taken
from, the upstream path and the SHA-256 of the upstream file, so the subset
can be re-derived and checked. The selection rules are in `select_*` below;
each keeps every flag, reason and result category the upstream file has,
and trims only the number of examples per category where the examples are
large (the ML-KEM and ML-DSA keys run to several kilobytes each).

The output is flat: one `tests` list per file, each test carrying the
group-level fields it needs (the Ed25519 public key, the ChaCha20 nonce
size, the ML-DSA context), so the Gleam loader needs no notion of a group.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def provenance(repo_url: str, repo: Path, rel: str) -> dict:
    return {
        "repository": repo_url,
        "commit": head(repo),
        "path": rel,
        "sha256": sha256(repo / rel),
    }


def wycheproof(repo: Path, name: str, inline: list[str]) -> dict:
    rel = f"testvectors_v1/{name}_test.json"
    data = json.loads((repo / rel).read_text())
    tests = []
    for group in data["testGroups"]:
        carried = {k: group[k] for k in inline if k in group}
        # The Ed25519 groups hold the key as an object; only its raw
        # encoding is needed, under the name the test reads.
        if "publicKey" in carried:
            carried = {"pk": carried["publicKey"]["pk"]}
        for test in group["tests"]:
            row = dict(carried)
            row.update(test)
            tests.append(row)
    return {
        "source": provenance("https://github.com/C2SP/wycheproof", repo, rel),
        "algorithm": data["algorithm"],
        "schema": data["schema"],
        "upstreamNumberOfTests": data["numberOfTests"],
        "notes": data.get("notes", {}),
        "tests": tests,
    }


def acvp_groups(repo: Path, rel: str, parameter_set: str) -> tuple[dict, list]:
    data = json.loads((repo / rel).read_text())
    groups = [g for g in data["testGroups"] if g["parameterSet"] == parameter_set]
    return data, groups


def take_per_category(tests: list, key, per: int) -> list:
    seen: dict = {}
    out = []
    for test in tests:
        k = key(test)
        if seen.get(k, 0) < per:
            seen[k] = seen.get(k, 0) + 1
            out.append(test)
    return out


def acvp_mlkem(repo: Path) -> dict:
    keygen_rel = "gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json"
    ed_rel = "gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json"
    _, keygen_groups = acvp_groups(repo, keygen_rel, "ML-KEM-1024")
    _, ed_groups = acvp_groups(repo, ed_rel, "ML-KEM-1024")

    tests = []
    for g in keygen_groups:
        for t in g["tests"][:3]:
            tests.append({"function": "keyGen", **t})
    for g in ed_groups:
        f = g["function"]
        rows = g["tests"]
        if f == "encapsulation":
            rows = rows[:3]
        elif f == "decapsulation":
            rows = rows  # every modified-ciphertext case matters
        else:
            rows = take_per_category(rows, lambda t: t["reason"], 2)
        for t in rows:
            tests.append({"function": f, **t})
    return {
        "source": [
            provenance("https://github.com/usnistgov/ACVP-Server", repo, keygen_rel),
            provenance("https://github.com/usnistgov/ACVP-Server", repo, ed_rel),
        ],
        "algorithm": "ML-KEM-1024",
        "revision": "FIPS203",
        "tests": tests,
    }


def acvp_mldsa(repo: Path) -> dict:
    keygen_rel = "gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json"
    siggen_rel = "gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json"
    sigver_rel = "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
    _, keygen_groups = acvp_groups(repo, keygen_rel, "ML-DSA-65")
    _, siggen_groups = acvp_groups(repo, siggen_rel, "ML-DSA-65")
    _, sigver_groups = acvp_groups(repo, sigver_rel, "ML-DSA-65")

    tests = []
    for g in keygen_groups:
        for t in g["tests"][:3]:
            tests.append({"function": "keyGen", **t})

    # The binding signs and verifies the pure (non-prehashed) external
    # interface with an empty context, so only those sigGen rows verify
    # through it. Rows with a non-empty context are kept too, as negative
    # vectors: the same signature must not verify with an empty context.
    def pure_external(g):
        return g["signatureInterface"] == "external" and g["preHash"] == "pure"

    for g in siggen_groups:
        if not pure_external(g):
            continue
        empty = [t for t in g["tests"] if t.get("context", "") == ""]
        nonempty = [t for t in g["tests"] if t.get("context", "") != ""][:2]
        for t in empty + nonempty:
            tests.append(
                {
                    "function": "sigGen",
                    "deterministic": g["deterministic"],
                    "signatureInterface": g["signatureInterface"],
                    "preHash": g["preHash"],
                    **t,
                }
            )
    for g in sigver_groups:
        if not pure_external(g):
            continue
        for t in g["tests"]:
            if t.get("context", "") != "":
                continue
            tests.append(
                {
                    "function": "sigVer",
                    "signatureInterface": g["signatureInterface"],
                    "preHash": g["preHash"],
                    **t,
                }
            )
    return {
        "source": [
            provenance("https://github.com/usnistgov/ACVP-Server", repo, keygen_rel),
            provenance("https://github.com/usnistgov/ACVP-Server", repo, siggen_rel),
            provenance("https://github.com/usnistgov/ACVP-Server", repo, sigver_rel),
        ],
        "algorithm": "ML-DSA-65",
        "revision": "FIPS204",
        "tests": tests,
    }


def main() -> None:
    wyche, acvp, out = (Path(a) for a in sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "wycheproof_x25519.json": wycheproof(wyche, "x25519", ["curve"]),
        "wycheproof_ed25519.json": wycheproof(wyche, "ed25519", ["publicKey"]),
        "wycheproof_chacha20_poly1305.json": wycheproof(
            wyche, "chacha20_poly1305", ["keySize", "ivSize", "tagSize"]
        ),
        "wycheproof_hmac_sha256.json": wycheproof(
            wyche, "hmac_sha256", ["keySize", "tagSize"]
        ),
        "wycheproof_hkdf_sha256.json": wycheproof(wyche, "hkdf_sha256", ["keySize"]),
        "acvp_mlkem1024.json": acvp_mlkem(acvp),
        "acvp_mldsa65.json": acvp_mldsa(acvp),
    }
    for name, content in files.items():
        path = out / name
        path.write_text(json.dumps(content, indent=None, separators=(",", ":")) + "\n")
        print(f"{name}: {len(content['tests'])} tests, {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
