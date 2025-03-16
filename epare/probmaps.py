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
    return ProbMap(result, scalar_results.samplesm, scalar_results.kind)

def load_chunk(fname: str, divisors: set[int], kind: str) -> dict[MultIdent, ProbMap]:
    with open(fname, "rb") as f:
        multiples = pickle.load(f)
        res = {}
        for mult, results in multiples.items():
            results.kind = kind
            res[mult] = process_small_scalars(results, divisors)
    return res

def powers_of(k, max_power=20):
    return [k**i for i in range(1, max_power)]

def prod_combine(one, other):
    return [a * b for a, b in itertools.product(one, other)]


if __name__ == "__main__":
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199]
    medium_primes = [211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397]
    large_primes = [401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    all_integers = list(range(1, 400))
    all_even = list(range(2, 400, 2))
    all_odd = list(range(1, 400, 2))
    all_primes = small_primes + medium_primes + large_primes
    
    divisor_map = {
        "small_primes": small_primes,
        "medium_primes": medium_primes,
        "large_primes": large_primes,
        "all_primes": all_primes,
        "all_integers": all_integers,
        "all_even": all_even,
        "all_odd": all_odd,
        "powers_of_2": powers_of(2),
        "powers_of_2_large": powers_of(2, 256),
        "powers_of_2_large_3": [i * 3 for i in powers_of(2, 256)],
        "powers_of_2_large_p1": [i + 1 for i in powers_of(2, 256)],
        "powers_of_2_large_m1": [i - 1 for i in powers_of(2, 256)],
        "powers_of_2_large_pmautobus": sorted(set([i + j for i in powers_of(2, 256) for j in range(-5,5) if i+j > 0])),
        "powers_of_3": powers_of(3),
    }
    divisor_map["all"] = list(sorted(set().union(*[v for v in divisor_map.values()])))

    distributions_mults = {}
    bits = 256
    num_workers = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    divisor_name = sys.argv[2] if len(sys.argv) > 2 else "all"
    kind = sys.argv[3] if len(sys.argv) > 3 else "precomp+necessary"
    files = sorted(glob.glob(f"multiples_{bits}_{kind}_chunk*.pickle"))
    
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
            # Save intermediate.
            with open(f"{divisor_name}_intermediate_{kind}_distrs.pickle", "wb") as f:
                pickle.dump(distributions_mults, f)
    for mult, prob_map in distributions_mults.items():
        print(f"Got {prob_map.samples} for {mult}.")
    # Save
    with open(f"{divisor_name}_{kind}_distrs.pickle", "wb") as f:
        pickle.dump(distributions_mults, f)