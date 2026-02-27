# crypto-py

Lightweight Python CLI for key generation, signing, and verification using
`dilithium-py` (Dilithium + ML-DSA variants).

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Generate private key (private container stores both `sk` and `pk`):

```bash
python3 -m crypto_py.cli generate --algorithm dil2 --out key.pem
```

Extract public key:

```bash
python3 -m crypto_py.cli public --in key.pem --out pub.pem
```

Sign file:

```bash
python3 -m crypto_py.cli sign --sec key.pem --file ./test.txt --out signature.bin
```

Verify signature:

```bash
python3 -m crypto_py.cli verify --pub pub.pem --sig signature.bin --file ./test.txt
```

## Supported Algorithms

- `dil2`
- `dil3`
- `dil5`
- `mldsa44`
- `mldsa65`
- `mldsa87`

## Formats

- Key I/O supports `PEM` and `DER`.
- Default format is `PEM` for both input and output.
- `--outform DER` writes binary DER instead of PEM.

Examples:

```bash
python3 -m crypto_py.cli generate --algorithm mldsa44 --out key.der --outform DER
python3 -m crypto_py.cli public --in key.der --inform DER --out pub.der --outform DER
```

## Command Reference

`generate`
- Required: `--algorithm`
- Optional: `--out`, `--outform {PEM,DER}`

`public`
- Required: `--in`
- Optional: `--inform {PEM,DER}`, `--out`, `--outform {PEM,DER}`

`sign`
- Required: `--sec`, `--file`
- Optional: `--inform {PEM,DER}`, `--out`

`verify`
- Required: `--pub`, `--sig`, `--file`
- Optional: `--inform {PEM,DER}`

## Output and Exit Codes

- If `--out` is omitted (`generate`, `public`, `sign`), output is written to `stdout`.
- `verify` prints `Verification: True` or `Verification: False`.
- Process exit code:
  - `0` on success
  - `1` on verification failure or runtime error

## Notes

- The project uses custom key containers with PEM labels:
  - `CRYPTO-PY PRIVATE KEY`
  - `CRYPTO-PY PUBLIC KEY`
