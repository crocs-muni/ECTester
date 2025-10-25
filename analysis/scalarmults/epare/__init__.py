import itertools
from statsmodels.stats.proportion import proportion_confint

from pyecsca.ec.mult import (
    LTRMultiplier,
    RTLMultiplier,
    BinaryNAFMultiplier,
    WindowNAFMultiplier,
    SimpleLadderMultiplier,
    CoronMultiplier,
    FixedWindowLTRMultiplier,
    FullPrecompMultiplier,
    ProcessingDirection,
    SlidingWindowMultiplier,
    BGMWMultiplier,
    CombMultiplier,
    WindowBoothMultiplier,
    ScalarMultiplier
)
from pyecsca.ec.countermeasures import (
    GroupScalarRandomization,
    AdditiveSplitting,
    MultiplicativeSplitting,
    EuclideanSplitting,
    BrumleyTuveri,
    PointBlinding,
    ScalarMultiplierCountermeasure
)

from .config import MultIdent, CountermeasureIdent, Config
from .error_model import ErrorModel, checks_add
from .mult_results import MultResults
from .prob_map import ProbMap



def powerset(iterable):
    """Take an iterable and create a powerset of its elements."""
    s = list(iterable)
    return map(set, itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1)))


def powers_of(k, max_power=20):
    """Take all powers of `k` up to `max_power`."""
    return [k**i for i in range(1, max_power)]


def prod_combine(one, other):
    """Multiply all pairs of elements from `one` and `other`."""
    return [a * b for a, b in itertools.product(one, other)]


# All dbl-and-add multipliers from https://github.com/J08nY/pyecsca/blob/master/pyecsca/ec/mult
window_mults = [
    MultIdent(SlidingWindowMultiplier, width=2, recoding_direction=ProcessingDirection.LTR),
    MultIdent(SlidingWindowMultiplier, width=3, recoding_direction=ProcessingDirection.LTR),
    MultIdent(SlidingWindowMultiplier, width=4, recoding_direction=ProcessingDirection.LTR),
    MultIdent(SlidingWindowMultiplier, width=5, recoding_direction=ProcessingDirection.LTR),
    MultIdent(SlidingWindowMultiplier, width=6, recoding_direction=ProcessingDirection.LTR),
    MultIdent(SlidingWindowMultiplier, width=2, recoding_direction=ProcessingDirection.RTL),
    MultIdent(SlidingWindowMultiplier, width=3, recoding_direction=ProcessingDirection.RTL),
    MultIdent(SlidingWindowMultiplier, width=4, recoding_direction=ProcessingDirection.RTL),
    MultIdent(SlidingWindowMultiplier, width=5, recoding_direction=ProcessingDirection.RTL),
    MultIdent(SlidingWindowMultiplier, width=6, recoding_direction=ProcessingDirection.RTL),
    MultIdent(FixedWindowLTRMultiplier, m=2**1),
    MultIdent(FixedWindowLTRMultiplier, m=2**2),
    MultIdent(FixedWindowLTRMultiplier, m=2**3),
    MultIdent(FixedWindowLTRMultiplier, m=2**4),
    MultIdent(FixedWindowLTRMultiplier, m=2**5),
    MultIdent(FixedWindowLTRMultiplier, m=2**6),
    MultIdent(WindowBoothMultiplier, width=2),
    MultIdent(WindowBoothMultiplier, width=3),
    MultIdent(WindowBoothMultiplier, width=4),
    MultIdent(WindowBoothMultiplier, width=5),
    MultIdent(WindowBoothMultiplier, width=6)
]
naf_mults = [
    MultIdent(WindowNAFMultiplier, width=2),
    MultIdent(WindowNAFMultiplier, width=3),
    MultIdent(WindowNAFMultiplier, width=4),
    MultIdent(WindowNAFMultiplier, width=5),
    MultIdent(WindowNAFMultiplier, width=6),
    MultIdent(BinaryNAFMultiplier, always=False, direction=ProcessingDirection.LTR),
    MultIdent(BinaryNAFMultiplier, always=False, direction=ProcessingDirection.RTL),
    MultIdent(BinaryNAFMultiplier, always=True, direction=ProcessingDirection.LTR),
    MultIdent(BinaryNAFMultiplier, always=True, direction=ProcessingDirection.RTL)
]
comb_mults = [
    MultIdent(CombMultiplier, width=2, always=True),
    MultIdent(CombMultiplier, width=3, always=True),
    MultIdent(CombMultiplier, width=4, always=True),
    MultIdent(CombMultiplier, width=5, always=True),
    MultIdent(CombMultiplier, width=6, always=True),
    MultIdent(CombMultiplier, width=2, always=False),
    MultIdent(CombMultiplier, width=3, always=False),
    MultIdent(CombMultiplier, width=4, always=False),
    MultIdent(CombMultiplier, width=5, always=False),
    MultIdent(CombMultiplier, width=6, always=False),
    MultIdent(BGMWMultiplier, width=2, direction=ProcessingDirection.LTR),
    MultIdent(BGMWMultiplier, width=3, direction=ProcessingDirection.LTR),
    MultIdent(BGMWMultiplier, width=4, direction=ProcessingDirection.LTR),
    MultIdent(BGMWMultiplier, width=5, direction=ProcessingDirection.LTR),
    MultIdent(BGMWMultiplier, width=6, direction=ProcessingDirection.LTR),
    MultIdent(BGMWMultiplier, width=2, direction=ProcessingDirection.RTL),
    MultIdent(BGMWMultiplier, width=3, direction=ProcessingDirection.RTL),
    MultIdent(BGMWMultiplier, width=4, direction=ProcessingDirection.RTL),
    MultIdent(BGMWMultiplier, width=5, direction=ProcessingDirection.RTL),
    MultIdent(BGMWMultiplier, width=6, direction=ProcessingDirection.RTL)
]
binary_mults = [
    MultIdent(LTRMultiplier, always=False, complete=True),
    MultIdent(LTRMultiplier, always=True,  complete=True),
    MultIdent(LTRMultiplier, always=False, complete=False),
    MultIdent(LTRMultiplier, always=True,  complete=False),
    MultIdent(RTLMultiplier, always=False, complete=True),
    MultIdent(RTLMultiplier, always=True,  complete=True),
    MultIdent(RTLMultiplier, always=False, complete=False),
    MultIdent(RTLMultiplier, always=True,  complete=False),
    MultIdent(CoronMultiplier)
]
other_mults = [
    MultIdent(FullPrecompMultiplier, always=False, complete=True),
    MultIdent(FullPrecompMultiplier, always=True,  complete=True),
    MultIdent(FullPrecompMultiplier, always=False, complete=False),
    MultIdent(FullPrecompMultiplier, always=True,  complete=False),
    MultIdent(SimpleLadderMultiplier, complete=True),
    MultIdent(SimpleLadderMultiplier, complete=False)
]

# All error models are a simple cartesian product of the individual options.
def _all_error_models():
    result = []
    for checks in powerset(checks_add):
        for precomp_to_affine in (True, False):
            for check_condition in ("all", "necessary"):
                error_model = ErrorModel(checks, check_condition=check_condition, precomp_to_affine=precomp_to_affine)
                result.append(error_model)
    return result
all_error_models = _all_error_models()


# We can enumerate all mults and countermeasures here.
all_mults = window_mults + naf_mults + binary_mults + other_mults + comb_mults
def _all_mults_with_ctr():
    result = []
    for mult in all_mults:
        for one_ctr_class, other_ctr_class in itertools.product((GroupScalarRandomization, AdditiveSplitting, MultiplicativeSplitting, EuclideanSplitting, BrumleyTuveri, None), repeat=2):
            if one_ctr_class is None and other_ctr_class is None:
                result.append(mult)
                continue
            if other_ctr_class is None:
                continue
            if one_ctr_class is None:
                mults = [mult] * other_ctr_class.nmults
                other_ctr = CountermeasureIdent(other_ctr_class, *mults)
                result.append(other_ctr)
                continue

            mults = [mult] * other_ctr_class.nmults
            other_ctr = CountermeasureIdent(other_ctr_class, *mults)
            for i in range(1, 2**one_ctr_class.nmults):
                bits = format(i, f"0{one_ctr_class.nmults}b")
                args = [other_ctr if bit == "1" else mult for bit in bits]
                ctr = CountermeasureIdent(one_ctr_class, *args)
                result.append(ctr)
    return result
all_mults_with_ctr = _all_mults_with_ctr()
all_configs = [Config(mult, None) for mult in all_mults_with_ctr]


# We have several sets of divisors, inspired by various "interesting" multiples the multipliers may compute.
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


def conf_interval(p: float, samples: int, alpha: float = 0.05) -> tuple[float, float]:
    """Compute a confidence interval for a Binomial distribution."""
    return proportion_confint(round(p*samples), samples, alpha, method="wilson")
