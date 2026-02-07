from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


@dataclass(frozen=True)
class Algo:
    name: str
    algo_id: int
    impl: object


_ALGOS = [
    Algo("dil2", 1, Dilithium2),
    Algo("dil3", 2, Dilithium3),
    Algo("dil5", 3, Dilithium5),
    Algo("mldsa44", 4, ML_DSA_44),
    Algo("mldsa65", 5, ML_DSA_65),
    Algo("mldsa87", 6, ML_DSA_87),
]

BY_NAME: Dict[str, Algo] = {a.name: a for a in _ALGOS}
BY_ID: Dict[int, Algo] = {a.algo_id: a for a in _ALGOS}


def resolve_algorithm(name: str) -> Algo:
    key = name.lower()
    if key not in BY_NAME:
        raise ValueError(f"Unsupported algorithm: {name}")
    return BY_NAME[key]
