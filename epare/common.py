import multiprocessing
import inspect
import tempfile
import sys
import os
from datetime import timedelta

from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial, cached_property
from importlib import import_module, invalidate_caches
from pathlib import Path
from typing import Type, Any, Optional
from enum import Enum

from pyecsca.ec.params import DomainParameters, get_params
from pyecsca.ec.mult import *
from pyecsca.ec.countermeasures import GroupScalarRandomization, AdditiveSplitting, MultiplicativeSplitting, EuclideanSplitting, BrumleyTuveri


spawn_context = multiprocessing.get_context("spawn")

# Allow to use "spawn" multiprocessing method for function defined in a Jupyter notebook.
# https://neuromancer.sk/article/35
@contextmanager
def enable_spawn(func):
    invalidate_caches()
    source = inspect.getsource(func)
    current_file_path = os.path.abspath(__file__)
    with open(current_file_path, 'r') as self, tempfile.NamedTemporaryFile(suffix=".py", mode="w") as f:
        f.write(self.read())
        f.write(source)
        f.flush()
        path = Path(f.name)
        directory = str(path.parent)
        sys.path.append(directory)
        module = import_module(str(path.stem))
        yield getattr(module, func.__name__)
        sys.path.remove(directory)


@dataclass(frozen=True)
class MultIdent:
    klass: Type[ScalarMultiplier]
    args: list[Any]
    kwargs: dict[str, Any]
    countermeasure: Optional[str] = None

    def __init__(self, klass: Type[ScalarMultiplier], *args, **kwargs):
        object.__setattr__(self, "klass", klass)
        object.__setattr__(self, "args", args if args is not None else [])
        if kwargs is not None and "countermeasure" in kwargs:
            object.__setattr__(self, "countermeasure", kwargs["countermeasure"])
            del kwargs["countermeasure"]
        object.__setattr__(self, "kwargs", kwargs if kwargs is not None else {})
    
    @cached_property
    def partial(self):
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
        if countermeasure not in (None, "gsr", "additive", "multiplicative", "euclidean", "bt"):
            raise ValueError(f"Unknown countermeasure: {countermeasure}")
        return MultIdent(self.klass, *self.args, **self.kwargs, countermeasure=countermeasure)

    def __str__(self):
        name = self.klass.__name__.replace("Multiplier", "")
        args = ("_" + ",".join(list(map(str, self.args)))) if self.args else ""
        kwmap = {"recoding_direction": "recode",
                 "direction": "dir",
                 "width": "w"}
        kwargs = ("_" + ",".join(f"{kwmap.get(k, k)}:{v.name if isinstance(v, Enum) else str(v)}" for k,v in self.kwargs.items())) if self.kwargs else ""
        countermeasure = f"+{self.countermeasure}" if self.countermeasure is not None else ""
        return f"{name}{args}{kwargs}{countermeasure}"

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash((self.klass, self.countermeasure, tuple(self.args), tuple(self.kwargs.keys()), tuple(self.kwargs.values())))


@dataclass
class MultResults:
    multiplications: list[set[int]]
    samples: int
    duration: Optional[float] = None
    kind: Optional[str] = None

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
        kind = self.kind if self.kind is not None else ""
        return f"MultResults({self.samples},{duration},{kind})"

    def __repr__(self):
        return str(self)


@dataclass
class ProbMap:
    probs: dict[int, float]
    samples: int
    kind: Optional[str] = None

    def __len__(self):
        return len(self.probs)

    def __iter__(self):
        yield from self.probs

    def __getitem__(self, i):
        return self.probs[i]

    def keys(self):
        return self.probs.keys()

    def values(self):
        return self.probs.values()

    def items(self):
        return self.probs.items()

    def narrow(self, divisors: set[int]):
        self.probs = {k:v for k, v in self.probs.items() if k in divisors}

    def merge(self, other: "ProbMap") -> None:
        if self.kind != other.kind:
            raise ValueError("Merging ProbMaps of different kinds leads to unexpected results.")
        new_keys = set(self.keys()).union(other.keys())
        result = {}
        for key in new_keys:
            if key in self and key in other:
                result[key] = (self[key] * self.samples + other[key] * other.samples) / (self.samples + other.samples)
            elif key in self:
                result[key] = self[key]
            elif key in other:
                result[key] = other[key]
        self.probs = result
        self.samples += other.samples

    def enrich(self, other: "ProbMap") -> None:
        if self.samples != other.samples:
            raise ValueError("Enriching can only work on equal amount of samples (same run, different divisors)")
        if self.kind != other.kind:
            raise ValueError("Enriching ProbMaps of different kinds leads to unexpected results.")
        self.probs.update(other.probs)


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
    MultIdent(BinaryNAFMultiplier, direction=ProcessingDirection.LTR),
    MultIdent(BinaryNAFMultiplier, direction=ProcessingDirection.RTL)
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

all_mults = window_mults + naf_mults + binary_mults + other_mults + comb_mults
all_mults_with_ctr = [mult.with_countermeasure(ctr) for mult in all_mults for ctr in (None, "gsr", "additive", "multiplicative", "euclidean", "bt")]
