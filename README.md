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
