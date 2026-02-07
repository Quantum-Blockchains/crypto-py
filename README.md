# crypto-py

Python version of the CLI using `dilithium-py`.

## Install

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Generate a private key (container includes both sk+pk):

```
python -m crypto_py.cli generate --algorithm dil2 --out key.pem
python -m crypto_py.cli generate --algorithm mldsa44 --out key.der --outform DER
```

Extract public key:

```
python -m crypto_py.cli public --in key.pem --out pub.pem
python -m crypto_py.cli public --in key.der --inform DER --out pub.der --outform DER
```

Sign a file:

```
python -m crypto_py.cli sign --sec key.pem --file ./test.txt --out signature
```

Verify a signature:

```
python -m crypto_py.cli verify --pub pub.pem --sig signature --file ./test.txt
```

## Algorithms

- `dil2`
- `dil3`
- `dil5`
- `mldsa44`
- `mldsa65`
- `mldsa87`

## Key Format

This Python CLI uses a simple custom container format:

- Private key (DER):
  - magic `CRPY`
  - version (1 byte)
  - algorithm id (1 byte)
  - secret length (u32 big-endian)
  - secret key bytes
  - public length (u32 big-endian)
  - public key bytes

- Public key (DER):
  - magic `CRPP`
  - version (1 byte)
  - algorithm id (1 byte)
  - public length (u32 big-endian)
  - public key bytes

For PEM, the DER bytes are Base64-wrapped with labels:

- `CRYPTO-PY PRIVATE KEY`
- `CRYPTO-PY PUBLIC KEY`
