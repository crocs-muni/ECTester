import itertools
import hashlib
from datetime import timedelta
from enum import Enum
from operator import itemgetter

from dataclasses import dataclass
from functools import partial, cached_property, total_ordering
from typing import Any, Optional, Type, Union, Literal

from statsmodels.stats.proportion import proportion_confint

from pyecsca.sca.re.rpa import MultipleContext
from pyecsca.ec.mult import *
from pyecsca.ec.point import Point
from pyecsca.ec.countermeasures import GroupScalarRandomization, AdditiveSplitting, MultiplicativeSplitting, EuclideanSplitting, BrumleyTuveri


def check_equal_multiples(k, l, q):
    """Checks whether the two multiples input into the formula are equal modulo q (the order of the base)."""
    return (k % q) == (l % q)


def check_divides(k, l, q):
    """Checks whether q (the order of the base) divides any of the multiples input into the formula."""
    return (k != 0) and (l != 0) and (k % q == 0) or (l % q == 0)


def check_half_add(k, l, q):
    return (q % 2 == 0) and ((k-l) % (q//2)) == 0


def check_affine(k, q):
    """Checks whether q (the order of the base) divides the multiple that is to be converted to affine."""
    return k % q == 0


def check_any(*checks, q=None):
    """Merge multiple checks together. The returned check function no longer takes the `q` parameter."""
    def check_func(k, l):
        for check in checks:
            if check(k, l, q):
                return True
        return False
    return check_func


# These checks can be applied to add formulas. See the formulas notebook for background on them.
checks_add = {
    "equal_multiples": check_equal_multiples,
    "divides": check_divides,
    "half_add": check_half_add
}

# This check can be applied to conversion to affine.
checks_affine = {
    "affine": check_affine
}

def powerset(iterable):
    """Take an iterable and create a powerset of its elements."""
    s = list(iterable)
    return map(set, itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1)))


@dataclass(frozen=True)
@total_ordering
class ErrorModel:
    """
    An ErrorModel describes the behavior of an implementation with regards to errors on exceptional
    inputs to its addition formulas, to-affine conversion or general scalar multiplication.

    :param checks: A set of names of checks (from checks_add and checks_affine) that the implementation performs.
    Note that these may not be checks that the implementation explicitly performs, only that it behaves w.r.t.
    errors as if it were doing these checks, due to the formulas it chose and any actual checks it has.
    :param check_condition: Either "all" or "necessary". Specifies whether the checks are applied to all points
    that the implementation computes during a scalar multiplication or only those that end up being used -- thus
    affect -- the final result. If an implementation does not perform any dummy operations, these two are the same.
    :param precomp_to_affine: Specifies whether the implementation converts all results of the precomputation step
    to affine form. If it does, it means that additional checks on all outputs of the precomputation are done as
    they have to be "convertible" to affine form.
    """
    checks: set[str]
    check_condition: Union[Literal["all"], Literal["necessary"]]
    precomp_to_affine: bool

    def __init__(self, checks: set[str], check_condition: Union[Literal["all"], Literal["necessary"]], precomp_to_affine: bool):
        for check in checks:
            if check not in checks_add:
                raise ValueError(f"Unknown check: {check}")
        checks = set(checks)
        checks.add("affine") # always done in our model
        object.__setattr__(self, "checks", checks)
        if check_condition not in ("all", "necessary"):
            raise ValueError("Wrong check_condition")
        object.__setattr__(self, "check_condition", check_condition)
        object.__setattr__(self, "precomp_to_affine", precomp_to_affine)

    def check_add(self, q):
        """Get the add formula check function for the given q."""
        if self.checks == {"affine"}:
            return lambda k, l: False
        return check_any(*map(lambda name: checks_add[name], filter(lambda check: check in checks_add, self.checks)), q=q)

    def check_affine(self, q):
        """Get the to-affine check function for the given q."""
        return partial(check_affine, q=q)

    def __lt__(self, other):
        if not isinstance(other, ErrorModel):
            return NotImplemented
        return str(self) < str(other)

    def __str__(self):
        cs = []
        if "equal_multiples" in self.checks:
            cs.append("em")
        if "divides" in self.checks:
            cs.append("d")
        if "half_add" in self.checks:
            cs.append("ha")
        if "affine" in self.checks:
            cs.append("a")
        precomp = "+pre" if self.precomp_to_affine else ""
        return f"({','.join(cs)}+{self.check_condition}{precomp})"

    def __hash__(self):
        return hash((tuple(sorted(self.checks)), self.check_condition, self.precomp_to_affine))


# All error models are a simple cartesian product of the individual options.
all_error_models = []
for checks in powerset(checks_add):
    for precomp_to_affine in (True, False):
        for check_condition in ("all", "necessary"):
            error_model = ErrorModel(checks, check_condition=check_condition, precomp_to_affine=precomp_to_affine)
            all_error_models.append(error_model)


@dataclass(frozen=True)
@total_ordering
class MultIdent:
    """
    A MultIdent is a description of a scalar multiplication implementation, consisting of a scalar multiplier,
    (optionally) a countermeasure, and (optionally) an error model.

    The scalar multiplier is defined by the `klass` attribute, along with the `args` and `kwargs` attributes.
    One can reconstruct the raw multiplier (without the countermeasure) by doing:
      
      klass(*args, **kwargs)

    The countermeasure is simply in the `countermeasure` attribute and may be `None`.

    The error model is simply in the `error_model` attribute and may be `None`. If it is `None`, the MultIdent
    is not suitable for error simulation and merely represents the description of a scalar multiplication
    implementation we care about when reverse-engineering: the multiplier and the countermeasure, we do not
    really care about the error model, yet need it when simulating.
    """
    klass: Type[ScalarMultiplier]
    args: list[Any]
    kwargs: dict[str, Any]
    countermeasure: Optional[str] = None
    error_model: Optional[ErrorModel] = None

    def __init__(self, klass: Type[ScalarMultiplier], *args, **kwargs):
        object.__setattr__(self, "klass", klass)
        object.__setattr__(self, "args", args if args is not None else [])
        if kwargs is not None and "countermeasure" in kwargs:
            object.__setattr__(self, "countermeasure", kwargs["countermeasure"])
            del kwargs["countermeasure"]
        if kwargs is not None and "error_model" in kwargs:
            object.__setattr__(self, "error_model", kwargs["error_model"])
            del kwargs["error_model"]
        object.__setattr__(self, "kwargs", kwargs if kwargs is not None else {})
    
    @cached_property
    def partial(self):
        """Get the callable that constructs the scalar multiplier (with countermeasure if any)."""
        func = partial(self.klass, *self.args, **self.kwargs)
        if self.countermeasure is None:
            return func
        if self.countermeasure == "gsr":
            return lambda *args, **kwargs: GroupScalarRandomization(func(*args, **kwargs))
        elif self.countermeasure == "additive":
            return lambda *args, **kwargs: AdditiveSplitting(func(*args, **kwargs))
        elif self.countermeasure == "multiplicative":
            return lambda *args, **kwargs: MultiplicativeSplitting(func(*args, **kwargs))
        elif self.countermeasure == "euclidean":
            return lambda *args, **kwargs: EuclideanSplitting(func(*args, **kwargs))
        elif self.countermeasure == "bt":
            return lambda *args, **kwargs: BrumleyTuveri(func(*args, **kwargs))

    def with_countermeasure(self, countermeasure: str | None):
        """Return a new MultIdent with a given countermeasure."""
        if countermeasure not in (None, "gsr", "additive", "multiplicative", "euclidean", "bt"):
            raise ValueError(f"Unknown countermeasure: {countermeasure}")
        return MultIdent(self.klass, *self.args, **self.kwargs, countermeasure=countermeasure)

    def with_error_model(self, error_model: ErrorModel | None):
        """Return a new MultIdent with a given error model."""
        if not (isinstance(error_model, ErrorModel) or error_model is None):
            raise ValueError("Unknown error model.")
        return MultIdent(self.klass, *self.args, **self.kwargs, countermeasure=self.countermeasure, error_model=error_model)

    def __str__(self):
        name = self.klass.__name__.replace("Multiplier", "")
        args = ("_" + ",".join(list(map(str, self.args)))) if self.args else ""
        kwmap = {"recoding_direction": "recode",
                 "direction": "dir",
                 "width": "w"}
        kwargs = ("_" + ",".join(f"{kwmap.get(k, k)}:{v.name if isinstance(v, Enum) else str(v)}" for k,v in self.kwargs.items())) if self.kwargs else ""
        countermeasure = f"+{self.countermeasure}" if self.countermeasure is not None else ""
        error_model = f"+{self.error_model}" if self.error_model is not None else ""
        return f"{name}{args}{kwargs}{countermeasure}{error_model}"

    def __getstate__(self):
        state = self.__dict__.copy()
        # Remove cached properties
        state.pop("partial", None)
        return state

    def __lt__(self, other):
        if not isinstance(other, MultIdent):
            return NotImplemented
        return str(self) < str(other)

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash((self.klass, self.countermeasure, self.error_model, tuple(self.args), tuple(self.kwargs.keys()), tuple(self.kwargs.values())))


@dataclass
class MultResults:
    """
    A MultResults instance represents many simulated scalar multiplciation computations, which were tracked
    using a `MultipleContext` (i.e. the outputs of the :func:`pyecsca.sca.re.rpa.multiple_graph` function).
    Generally, these would be for one MultIdent only, but that should be handled separately, for example
    in a dict[MultIdent, MultResults]. The `samples` describe how many computations
    are contained and must correspond to the length of the `multiplications` list.
    """
    multiplications: list[tuple[MultipleContext, MultipleContext, Point]]
    samples: int
    duration: Optional[float] = None

    def merge(self, other: "MultResults"):
        self.multiplications.extend(other.multiplications)
        self.samples += other.samples

    def __len__(self):
        return self.samples

    def __iter__(self):
        yield from self.multiplications

    def __getitem__(self, i):
        return self.multiplications[i]

    def __str__(self):
        duration = timedelta(seconds=int(self.duration)) if self.duration is not None else ""
        return f"MultResults({self.samples},{duration})"

    def __repr__(self):
        return str(self)


@dataclass
class ProbMap:
    """
    A ProbMap is a mapping from integers (base point order q) to floats (error probability for some scalar
    multiplication implementation, i.e. MultIdent). The probability map is constructed for a given set of
    `divisors` (the base point orders q). Probability maps can be narrowed or merged. A narrowing restricts
    the probability map to a smaller set of `divisors`. A merging takes another probability map using the
    same divisor set and updates the probabilities to a weighted average of the two probability maps
    (the weight is the number of samples).
    """
    probs: dict[int, float]
    divisors_hash: bytes
    samples: int

    def __len__(self):
        return len(self.probs)

    def __iter__(self):
        yield from self.probs

    def __getitem__(self, i):
        return self.probs[i] if i in self.probs else 0.0

    def __contains__(self, item):
        return item in self.probs

    def keys(self):
        return self.probs.keys()

    def values(self):
        return self.probs.values()

    def items(self):
        return self.probs.items()

    def narrow(self, divisors: set[int]):
        """Narrow the probability map to the new set of divisors (must be a subset of the current set)."""
        divisors_hash = hashlib.blake2b(str(sorted(divisors)).encode(), digest_size=8).digest()
        if self.divisors_hash == divisors_hash:
            # Already narrow.
            return
        for kdel in set(self.probs.keys()).difference(divisors):
            del self.probs[kdel]
        self.divisors_hash = divisors_hash

    def merge(self, other: "ProbMap") -> None:
        """Merge the `other` probability map into this one (must share the divisor set)."""
        if self.divisors_hash != other.divisors_hash:
            raise ValueError("Merging can only work on probmaps created for same divisors.")
        new_keys = set(self.keys()).union(other.keys())
        result = {}
        for key in new_keys:
            sk = self[key]
            ok = other[key]
            result[key] = (sk * self.samples + ok * other.samples) / (self.samples + other.samples)
        self.probs = result
        self.samples += other.samples


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

# We can enumerate all mults and countermeasures here.
all_mults = window_mults + naf_mults + binary_mults + other_mults + comb_mults
all_mults_with_ctr = [mult.with_countermeasure(ctr) for mult in all_mults for ctr in (None, "gsr", "additive", "multiplicative", "euclidean", "bt")]


def powers_of(k, max_power=20):
    """Take all powers of `k` up to `max_power`."""
    return [k**i for i in range(1, max_power)]

def prod_combine(one, other):
    """Multiply all pairs of elements from `one` and `other`."""
    return [a * b for a, b in itertools.product(one, other)]


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
