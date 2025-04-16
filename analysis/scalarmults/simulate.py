#!/usr/bin/env python
# coding: utf-8

# # Simulating EPA-RE using points of low-order


import pickle
import itertools
import glob
import random
import sys
import time
import os

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

from collections import Counter

from pathlib import Path
from random import randint, randbytes, shuffle
from typing import Type, Any, Tuple

from tqdm.auto import tqdm, trange

from pyecsca.ec.params import DomainParameters, get_params
from pyecsca.ec.mult import *
from pyecsca.sca.re.rpa import multiples_computed
from pyecsca.misc.utils import TaskExecutor

from common import *


def get_general_multiples(bits: int, samples: int = 1000) -> MultResults:
    from random import randint
    results = []
    for _ in range(samples):
        big_scalar = randint(1, 2**bits)
        results.append({big_scalar})
    return MultResults(results, samples)


def get_general_n_multiples(bits: int, n: int, samples: int = 1000) -> MultResults:
    from random import randint
    results = []
    for _ in range(samples):
        smult = set()
        for i in range(n):
            b = randint(1,256)
            smult.add(randint(2**b,2**(b+1)))
        results.append(smult)
    return MultResults(results, samples)


def get_small_scalar_multiples(mult: MultIdent,
                               params: DomainParameters,
                               bits: int,
                               samples: int = 1000,
                               use_init: bool = True,
                               use_multiply: bool = True,
                               seed: bytes | None = None,
                               kind: str = "precomp+necessary") -> Tuple[MultResults, float]:

    duration = -time.perf_counter()
    results = []
    if seed is not None:
        random.seed(seed)

    # If no countermeasure is used, we have fully random scalars.
    # Otherwise, fix one per chunk.
    if mult.countermeasure is None:
        scalars = [random.randint(1, 2**bits) for _ in range(samples)]
    else:
        one = random.randint(1, 2**bits)
        scalars = [one for _ in range(samples)]

    for scalar in scalars:
        # Use a list for less memory usage.
        results.append(list(multiples_computed(scalar, params, mult.klass, mult.partial, use_init, use_multiply, kind=kind)))
    duration += time.perf_counter()
    return MultResults(results, samples, duration=duration, kind=kind)


if __name__ == "__main__":
    category = "secg"
    curve = "secp256r1"
    params = get_params(category, curve, "projective")
    num_workers = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    bits = params.order.bit_length()
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    kind = sys.argv[3] if len(sys.argv) > 3 else "precomp+necessary"
    use_init = (sys.argv[4].lower() == "true") if len(sys.argv) > 4 else True
    use_multiply = (sys.argv[5].lower() == "true") if len(sys.argv) > 5 else True
    selected_mults = all_mults
    shuffle(selected_mults)

    if (scratch := os.getenv("SCRATCHDIR")) is not None:
        outdir = Path(scratch)
    else:
        outdir = Path.cwd()

    print(f"Running on {num_workers} cores, doing {samples} samples.")

    chunk_id = randbytes(6).hex()
    with TaskExecutor(max_workers=num_workers) as pool:
        for mult in selected_mults:
            for countermeasure in (None, "gsr", "additive", "multiplicative", "euclidean", "bt"):
                mwc = mult.with_countermeasure(countermeasure)
                pool.submit_task(mwc,
                                 get_small_scalar_multiples,
                                 mwc, params, bits, samples, use_init=use_init, use_multiply=use_multiply, seed=chunk_id, kind=kind)
        for mult, future in tqdm(pool.as_completed(), desc="Computing small scalar distributions.", total=len(pool.tasks), smoothing=0):
            if error := future.exception():
                print("Error", mult, error)
                raise error
            res = future.result()
            print(f"Got {mult} in {res.duration}.")
            with (outdir / f"multiples_{bits}_{kind}_{'init' if use_init else 'noinit'}_{'mult' if use_multiply else 'nomult'}_chunk{chunk_id}.pickle").open("ab") as f:
                pickle.dump((mult, res), f)
