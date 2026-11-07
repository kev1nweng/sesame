#!/usr/bin/env python3
"""Check whether WeChat derives each database key from one shared secret.

Reads the hook log, pairs CCKeyDerivationPBKDF entry records (password/salt/rounds)
with their exit records (derived key), then tests:
  1. is the password the same across databases?
  2. does the recorded derived key equal a known database key?
  3. does pbkdf2(password, salt, rounds) reproduce the derived key?
"""
import hashlib
import json
import pathlib
import sys
from collections import Counter

LOG = pathlib.Path.home() / (
    "Library/Containers/com.tencent.xinWeChat/Data/sesame-keys.jsonl"
)
KEYS = pathlib.Path("/tmp/pbkdf2_test2.json")


def load_log():
    ins, outs = [], []
    if not LOG.exists():
        return ins, outs
    for line in LOG.open(errors="ignore"):
        try:
            v = json.loads(line)
        except Exception:
            continue
        if v.get("kind") == "pbkdf2":
            ins.append(v)
        elif v.get("kind") == "pbkdf2_out":
            outs.append(v)
    return ins, outs


def known_keys():
    try:
        data = json.loads(KEYS.read_text())
    except Exception:
        return {}
    return {rel: v["key"] for rel, v in data.get("databases", {}).items()}


def main():
    ins, outs = load_log()
    print(f"entry records: {len(ins)}   exit records: {len(outs)}")
    if not ins and not outs:
        print("no PBKDF2 calls captured")
        return

    recs = outs or ins
    print("distinct passwords:", len({r["password"] for r in recs}))
    print("rounds values:", dict(Counter(r.get("rounds") for r in recs)))
    print("distinct salts:", len({r["salt"] for r in recs}))

    keys = known_keys()
    by_key = {v: k for k, v in keys.items()}
    print(f"known databases in key file: {len(keys)}")

    hits = []
    for r in recs:
        d = r.get("derived", "")
        if d.strip("0"):
            hits.append((r, by_key.get(d)))
    print(f"exit records with a non-zero derived key: {len(hits)}")
    for r, db in hits[:5]:
        print(f"  derived {r['derived'][:16]}... -> {db or 'unknown database'}")

    # Does the KDF reproduce the derived key from password+salt+rounds?
    ok = 0
    tried = 0
    for r, db in hits[:20]:
        pw = bytes.fromhex(r["password"])
        salt = bytes.fromhex(r["salt"])
        want = bytes.fromhex(r["derived"])
        for algo in ("sha512", "sha256", "sha1"):
            for rounds in {r.get("rounds") or 0, 2, 1, 1000, 256000, 64000}:
                if rounds <= 0:
                    continue
                tried += 1
                got = hashlib.pbkdf2_hmac(algo, pw, salt, rounds, 32)
                if got == want:
                    print(f"  MATCH {db}: pbkdf2-{algo} rounds={rounds}")
                    ok += 1
                    break
    print(f"kdf reproductions: {ok} (tried {tried})")


if __name__ == "__main__":
    main()
