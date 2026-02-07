from __future__ import annotations

import base64
import textwrap
from dataclasses import dataclass
from typing import Tuple

from .algorithms import BY_ID


PRIVATE_MAGIC = b"CRPY"
PUBLIC_MAGIC = b"CRPP"
VERSION = 1

PRIVATE_PEM_LABEL = "CRYPTO-PY PRIVATE KEY"
PUBLIC_PEM_LABEL = "CRYPTO-PY PUBLIC KEY"


@dataclass(frozen=True)
class PrivateKeyContainer:
    algo_id: int
    sk: bytes
    pk: bytes


@dataclass(frozen=True)
class PublicKeyContainer:
    algo_id: int
    pk: bytes


def _u32_be(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _read_u32_be(b: bytes, offset: int) -> Tuple[int, int]:
    if offset + 4 > len(b):
        raise ValueError("Invalid container: truncated length")
    return int.from_bytes(b[offset:offset + 4], "big"), offset + 4


def encode_private_der(c: PrivateKeyContainer) -> bytes:
    return b"".join([
        PRIVATE_MAGIC,
        bytes([VERSION]),
        bytes([c.algo_id]),
        _u32_be(len(c.sk)),
        c.sk,
        _u32_be(len(c.pk)),
        c.pk,
    ])


def decode_private_der(data: bytes) -> PrivateKeyContainer:
    if len(data) < 6 or data[:4] != PRIVATE_MAGIC:
        raise ValueError("Invalid private key container magic")
    version = data[4]
    if version != VERSION:
        raise ValueError(f"Unsupported private key container version: {version}")
    algo_id = data[5]
    if algo_id not in BY_ID:
        raise ValueError(f"Unknown algorithm id: {algo_id}")
    offset = 6
    sk_len, offset = _read_u32_be(data, offset)
    if offset + sk_len > len(data):
        raise ValueError("Invalid container: truncated secret key")
    sk = data[offset:offset + sk_len]
    offset += sk_len
    pk_len, offset = _read_u32_be(data, offset)
    if offset + pk_len > len(data):
        raise ValueError("Invalid container: truncated public key")
    pk = data[offset:offset + pk_len]
    return PrivateKeyContainer(algo_id=algo_id, sk=sk, pk=pk)


def encode_public_der(c: PublicKeyContainer) -> bytes:
    return b"".join([
        PUBLIC_MAGIC,
        bytes([VERSION]),
        bytes([c.algo_id]),
        _u32_be(len(c.pk)),
        c.pk,
    ])


def decode_public_der(data: bytes) -> PublicKeyContainer:
    if len(data) < 6 or data[:4] != PUBLIC_MAGIC:
        raise ValueError("Invalid public key container magic")
    version = data[4]
    if version != VERSION:
        raise ValueError(f"Unsupported public key container version: {version}")
    algo_id = data[5]
    if algo_id not in BY_ID:
        raise ValueError(f"Unknown algorithm id: {algo_id}")
    offset = 6
    pk_len, offset = _read_u32_be(data, offset)
    if offset + pk_len > len(data):
        raise ValueError("Invalid container: truncated public key")
    pk = data[offset:offset + pk_len]
    return PublicKeyContainer(algo_id=algo_id, pk=pk)


def encode_pem(label: str, der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(textwrap.wrap(b64, 64))
    return (
        f"-----BEGIN {label}-----\n"
        f"{body}\n"
        f"-----END {label}-----\n"
    ).encode("ascii")


def decode_pem(data: bytes, label: str) -> bytes:
    text = data.decode("ascii", errors="strict")
    header = f"-----BEGIN {label}-----"
    footer = f"-----END {label}-----"
    if header not in text or footer not in text:
        raise ValueError(f"Invalid PEM: missing {label} header/footer")
    start = text.index(header) + len(header)
    end = text.index(footer)
    b64 = "".join(text[start:end].strip().split())
    return base64.b64decode(b64)
