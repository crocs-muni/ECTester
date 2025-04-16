import sys
import pickle
import itertools
import glob

from pyecsca.misc.utils import TaskExecutor
from tqdm.auto import tqdm

from common import *


def divides_any(l: int, small_scalars: set[int]) -> bool:
    for s in small_scalars:
        if s%l==0:
            return True
    return False


def process_small_scalars(scalar_results: MultResults, divisors: set[int]) -> ProbMap:
    result = {}
    for divisor in divisors:
        count = 0
        for smult in scalar_results.multiplications:
            if divides_any(divisor, smult):
                count += 1
        result[divisor] = count / scalar_results.samples
    return ProbMap(result, scalar_results.samples, scalar_results.kind)


def load_chunk(fname: str, divisors: set[int], kind: str) -> dict[MultIdent, ProbMap]:
    with open(fname, "rb") as f:
        multiples = {}
        while True:
            try:
                mult, distr = pickle.load(f)
                multiples[mult] = distr
            except EOFError:
                break
        res = {}
        for mult, results in multiples.items():
            results.kind = kind
            res[mult] = process_small_scalars(results, divisors)
    return res


if __name__ == "__main__":
    distributions_mults = {}
    bits = 256
    num_workers = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    divisor_name = sys.argv[2] if len(sys.argv) > 2 else "all"
    kind = sys.argv[3] if len(sys.argv) > 3 else "precomp+necessary"
    use_init = (sys.argv[4].lower() == "true") if len(sys.argv) > 4 else True
    use_multiply = (sys.argv[5].lower() == "true") if len(sys.argv) > 5 else True
    files = sorted(glob.glob(f"multiples_{bits}_{kind}_{'init' if use_init else 'noinit'}_{'mult' if use_multiply else 'nomult'}_chunk*.pickle"))

    selected_divisors = divisor_map[divisor_name]
    
    with TaskExecutor(max_workers=num_workers) as pool:
        for fname in files:
            pool.submit_task(fname,
                             load_chunk,
                             fname, selected_divisors, kind)
        for fname, future in tqdm(pool.as_completed(), total=len(pool.tasks), smoothing=0):
            if error := future.exception():
                print(f"Error {fname}, {error}")
                continue
            new_distrs = future.result()
            for mult, prob_map in new_distrs.items():
                if mult in distributions_mults:
                    distributions_mults[mult].merge(prob_map)
                else:
                    distributions_mults[mult] = prob_map
    for mult, prob_map in distributions_mults.items():
        print(f"Got {prob_map.samples} for {mult}.")

    # Save
    with open(f"{divisor_name}_{kind}_distrs.pickle", "wb") as f:
        pickle.dump(distributions_mults, f)
