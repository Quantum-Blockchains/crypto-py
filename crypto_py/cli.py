from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .algorithms import BY_ID, resolve_algorithm
from .keyformat import (
    PRIVATE_PEM_LABEL,
    PUBLIC_PEM_LABEL,
    PrivateKeyContainer,
    PublicKeyContainer,
    decode_pem,
    decode_private_der,
    decode_public_der,
    encode_pem,
    encode_private_der,
    encode_public_der,
)


def _read_file(path: str) -> bytes:
    return Path(path).read_bytes()


def _write_file(path: str | None, data: bytes) -> None:
    if path:
        Path(path).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)


def _read_private(path: str, inform: str) -> PrivateKeyContainer:
    raw = _read_file(path)
    if inform == "PEM":
        raw = decode_pem(raw, PRIVATE_PEM_LABEL)
    return decode_private_der(raw)


def _read_public(path: str, inform: str) -> PublicKeyContainer:
    raw = _read_file(path)
    if inform == "PEM":
        raw = decode_pem(raw, PUBLIC_PEM_LABEL)
    return decode_public_der(raw)


def cmd_generate(args: argparse.Namespace) -> int:
    algo = resolve_algorithm(args.algorithm)
    pk, sk = algo.impl.keygen()

    container = PrivateKeyContainer(algo_id=algo.algo_id, sk=sk, pk=pk)
    der = encode_private_der(container)
    if args.outform == "PEM":
        out = encode_pem(PRIVATE_PEM_LABEL, der)
    else:
        out = der
    _write_file(args.out, out)
    return 0


def cmd_public(args: argparse.Namespace) -> int:
    priv = _read_private(args.input, args.inform)
    if priv.algo_id not in BY_ID:
        raise ValueError(f"Unknown algorithm id: {priv.algo_id}")
    pub = PublicKeyContainer(algo_id=priv.algo_id, pk=priv.pk)
    der = encode_public_der(pub)
    if args.outform == "PEM":
        out = encode_pem(PUBLIC_PEM_LABEL, der)
    else:
        out = der
    _write_file(args.out, out)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    priv = _read_private(args.sec, args.inform)
    algo = BY_ID[priv.algo_id].impl
    message = _read_file(args.file)
    sig = algo.sign(priv.sk, message)
    _write_file(args.out, sig)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    pub = _read_public(args.pub, args.inform)
    algo = BY_ID[pub.algo_id].impl
    message = _read_file(args.file)
    sig = _read_file(args.sig)
    ok = algo.verify(pub.pk, message, sig)
    print(f"Verification: {ok}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="crypto-py")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate key pair")
    g.add_argument("--algorithm", "-a", required=True)
    g.add_argument("--out", required=False)
    g.add_argument("--outform", default="PEM", choices=["PEM", "DER"])
    g.set_defaults(func=cmd_generate)

    pub = sub.add_parser("public", help="Extract public key")
    pub.add_argument("--in", dest="input", required=True)
    pub.add_argument("--inform", default="PEM", choices=["PEM", "DER"])
    pub.add_argument("--out", required=False)
    pub.add_argument("--outform", default="PEM", choices=["PEM", "DER"])
    pub.set_defaults(func=cmd_public)

    s = sub.add_parser("sign", help="Sign a file")
    s.add_argument("--sec", required=True)
    s.add_argument("--inform", default="PEM", choices=["PEM", "DER"])
    s.add_argument("--out", required=False)
    s.add_argument("--file", required=True)
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Verify a signature")
    v.add_argument("--pub", required=True)
    v.add_argument("--inform", default="PEM", choices=["PEM", "DER"])
    v.add_argument("--sig", required=True)
    v.add_argument("--file", required=True)
    v.set_defaults(func=cmd_verify)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
