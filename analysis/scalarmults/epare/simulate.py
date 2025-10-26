import hashlib
import random
import pickle
import sys

from functools import partial

from .config import Config
from .mult_results import MultResults
from .prob_map import ProbMap, hash_divisors

from pyecsca.ec.params import DomainParameters
from pyecsca.ec.mod import mod
from pyecsca.sca.re.rpa import multiple_graph
from pyecsca.sca.re.epa import graph_to_check_inputs, evaluate_checks


if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


def simulate_multiples(
    mult: Config,
    params: DomainParameters,
    bits: int,
    samples: int = 100,
    seed: bytes | None = None,
) -> MultResults:
    """
    Takes a Config, which specifies a scalar multiplier (with optional countermeasures)
    and simulates `samples` scalar multiplications, while tracking which multiples of the
    symbolic input point get computed.
    """
    results = []
    if seed is not None:
        random.seed(seed)
    rng = lambda n: mod(random.randrange(n), n)

    # If no countermeasure is used, we have fully random scalars.
    # Otherwise, fix one per chunk.
    if not mult.has_countermeasure:
        scalars = [random.randint(1, 2**bits) for _ in range(samples)]
    else:
        one = random.randint(1, 2**bits)
        scalars = [one for _ in range(samples)]

    for scalar in scalars:
        results.append(
            multiple_graph(
                scalar, params, mult.mult.klass, partial(mult.partial, rng=rng)
            )
        )
    return MultResults(results, samples)


def simulate_multiples_direct(
    mult: Config,
    params: DomainParameters,
    bits: int,
    fname: str,
    samples: int = 100,
    seed: bytes | None = None,
) -> str:
    """
    Like the `simulate_multiples` function above, but stores the pickled output directly
    into a file named `fname`.
    """
    result = simulate_multiples(mult, params, bits, samples, seed)
    with open(fname, "wb") as f:
        pickle.dump((mult, result), f)
    return fname


def evaluate_multiples(
    mult: Config,
    res: MultResults,
    divisors: set[int],
    use_init: bool = True,
    use_multiply: bool = True,
):
    """
    Takes a Config and MultResults and a set of divisors (base point orders `q`) and
    evaluates them using the error model from the Config. Note that the Config
    must have an error model in this case. Returns the ProbMap.
    """
    if not mult.has_error_model:
        raise ValueError("Invalid config")
    errors = {divisor: 0 for divisor in divisors}
    check_funcs = {q: mult.error_model.make_check_funcs(q) for q in divisors}
    for precomp_ctx, full_ctx, out in res:
        check_inputs = graph_to_check_inputs(
            precomp_ctx,
            full_ctx,
            out,
            check_condition=mult.error_model.check_condition,
            precomp_to_affine=mult.error_model.precomp_to_affine,
            use_init=use_init,
            use_multiply=use_multiply,
        )
        for q in divisors:
            error = evaluate_checks(
                check_funcs=check_funcs[q],
                check_inputs=check_inputs,
            )
            errors[q] += error
    # Make probmaps smaller. Do not store zero probabilities.
    probs = {}
    for q, error in errors.items():
        if error != 0:
            probs[q] = error / samples
    samples = len(res)
    dhash = hash_divisors(divisors)
    return ProbMap(probs, dhash, samples)


def evaluate_multiples_direct(
    mult: Config,
    fname: str,
    offset: int,
    divisors: set[int],
    use_init: bool = True,
    use_multiply: bool = True,
):
    """
    Like `evaluate_multiples`, but instead reads the MultResults from a file named `fname`
    at an `offset`. Still returns the ProbMap, which is significantly smaller and easier
    to pickle than the MultResults.
    """
    with open(fname, "rb") as f:
        f.seek(offset)
        _, res = pickle.load(f)
    return evaluate_multiples(mult, res, divisors, use_init, use_multiply)


def evaluate_multiples_compressed(
    mult: Config,
    fname: str,
    offset: int,
    divisors: set[int],
    use_init: bool = True,
    use_multiply: bool = True,
):
    """
    Like `evaluate_multiples`, but instead reads the MultResults from a file named `fname`
    at an `offset` that is a zstd compressed file.
    Still returns the ProbMap, which is significantly smaller and easier
    to pickle than the MultResults.
    """
    with zstd.open(fname, "rb") as f:
        f.seek(offset)
        _, res = pickle.load(f)
    return evaluate_multiples(mult, res, divisors, use_init, use_multiply)

