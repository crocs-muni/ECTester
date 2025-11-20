import itertools
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from typing import Any, Optional, Type
from anytree import Node

from pyecsca.ec.countermeasures import (
    GroupScalarRandomization,
    AdditiveSplitting,
    MultiplicativeSplitting,
    EuclideanSplitting,
    BrumleyTuveri,
    PointBlinding,
    MultPointBlinding,
    ScalarMultiplierCountermeasure,
)
from pyecsca.ec.mult import (
    ScalarMultiplier,
    SlidingWindowMultiplier,
    ProcessingDirection,
    FixedWindowLTRMultiplier,
    WindowBoothMultiplier,
    WindowNAFMultiplier,
    BinaryNAFMultiplier,
    CombMultiplier,
    BGMWMultiplier,
    LTRMultiplier,
    RTLMultiplier,
    CoronMultiplier,
    FullPrecompMultiplier,
    SimpleLadderMultiplier,
)
from .error_model import ErrorModel


class Composable:
    klass: Type
    args: list[Any]
    kwargs: dict[str, Any]

    @property
    def mult(self):
        """
        Extract the MultIdent out of the Composable.

        We assume there is only one somewhere in the tree
        (in all the leafs). We also assume the Composable only has up to 3 layers:
          Countermeasure(Countermeasure(Mult)), or
          Countermeasure(Mult), or
          Mult
        """
        if isinstance(self, MultIdent):
            return self
        for arg in self.args:
            if isinstance(arg, Composable):
                return arg.mult
        for kwarg in self.kwargs.values():
            if isinstance(kwarg, Composable):
                return kwarg.mult

    def walk(self, callback):
        """
        Recursively walk the Composable, applying the callback.
        """
        callback(self)
        for arg in self.args:
            if isinstance(arg, Composable):
                arg.walk(callback)
        for kwarg in self.kwargs.values():
            if isinstance(kwarg, Composable):
                kwarg.walk(callback)

    def tree(self) -> Node:
        me = Node(self)
        children = []
        for arg in self.args:
            if isinstance(arg, Composable):
                children.append(arg.tree())
        for kwarg in self.kwargs.values():
            if isinstance(kwarg, Composable):
                children.append(kwarg.tree())
        me.children = children
        return me

    def construct(self, *mult_args, **mult_kwargs):
        """Recursively construct this composable."""
        args, kwargs = self._build_args_kwargs(mult_args, mult_kwargs)
        return self._instantiate(args, kwargs, mult_args, mult_kwargs)

    def _build_args_kwargs(self, mult_args, mult_kwargs):
        args = []
        for arg in self.args:
            if isinstance(arg, Composable):
                args.append(arg.construct(*mult_args, **mult_kwargs))
            else:
                args.append(arg)
        kwargs = {}
        for key, value in self.kwargs.items():
            if isinstance(value, Composable):
                kwargs[key] = value.construct(*mult_args, **mult_kwargs)
            else:
                kwargs[key] = value
        return args, kwargs

    def _instantiate(self, c_args, c_kwargs, mult_args, mult_kwargs):
        return self.klass(*c_args, **c_kwargs)

    def __lt__(self, other):
        if not isinstance(other, Composable):
            return NotImplemented
        return str(self) < str(other)


@dataclass(frozen=True)
@total_ordering
class CountermeasureIdent(Composable):
    klass: Type[ScalarMultiplierCountermeasure]
    args: list[Any]
    kwargs: dict[str, Any]

    def __init__(self, klass: Type[ScalarMultiplier], *args, **kwargs):
        object.__setattr__(self, "klass", klass)
        object.__setattr__(self, "args", args if args is not None else [])
        object.__setattr__(self, "kwargs", kwargs if kwargs is not None else {})

    def construct(self, *mult_args, **mult_kwargs):
        args, kwargs = self._build_args_kwargs(mult_args, mult_kwargs)
        # Capture any formula required to instantiate this countermeasure from the mult args
        for arg in mult_args:
            if any(map(lambda req: isinstance(arg, req), self.klass.requires)):
                kwargs[arg.shortname] = arg
        # Capture the rng as well.
        if "rng" in mult_kwargs:
            kwargs["rng"] = mult_kwargs["rng"]
        return self._instantiate(args, kwargs, mult_args, mult_kwargs)

    def __str__(self):
        if issubclass(self.klass, GroupScalarRandomization):
            name = "gsr"
        elif issubclass(self.klass, AdditiveSplitting):
            name = "asplit"
        elif issubclass(self.klass, MultiplicativeSplitting):
            name = "msplit"
        elif issubclass(self.klass, EuclideanSplitting):
            name = "esplit"
        elif issubclass(self.klass, BrumleyTuveri):
            name = "bt"
        elif issubclass(self.klass, PointBlinding):
            name = "blind"
        elif issubclass(self.klass, MultPointBlinding):
            name = "mblind"
        else:
            name = "?"
        # Only print other Composables as Countermeasures do not have interesting arguments
        args = (
            (
                ",".join(
                    list(
                        map(
                            str,
                            filter(lambda arg: isinstance(arg, Composable), self.args),
                        )
                    )
                )
            )
            if self.args
            else ""
        )
        # Same for kwargs
        kwargs = (
            (",".join(f"{k}={v}" for k, v in self.kwargs if isinstance(v, Composable)))
            if self.kwargs
            else ""
        )
        return f"{name}({args}{',' if args and kwargs else ''}{kwargs})"

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(
            (
                self.klass,
                tuple(self.args),
                tuple(self.kwargs.keys()),
                tuple(self.kwargs.values()),
            )
        )


@dataclass(frozen=True)
@total_ordering
class MultIdent(Composable):
    klass: Type[ScalarMultiplier]
    args: list[Any]
    kwargs: dict[str, Any]

    def __init__(self, klass: Type[ScalarMultiplier], *args, **kwargs):
        object.__setattr__(self, "klass", klass)
        object.__setattr__(self, "args", args if args is not None else [])
        object.__setattr__(self, "kwargs", kwargs if kwargs is not None else {})

    def _instantiate(self, c_args, c_kwargs, mult_args, mult_kwargs):
        args = [*c_args, *mult_args]
        kwargs = {**c_kwargs, **mult_kwargs}
        if "rng" in kwargs:
            del kwargs["rng"]
        return self.klass(*args, **kwargs)

    def __str__(self):
        name = self.klass.__name__.replace("Multiplier", "")
        args = (",".join(list(map(str, self.args)))) if self.args else ""
        kwmap = {"recoding_direction": "recode", "direction": "dir", "width": "w"}
        kwargs = (
            (
                ",".join(
                    f"{kwmap.get(k, k)}:{v.name if isinstance(v, Enum) else str(v)}"
                    for k, v in self.kwargs.items()
                )
            )
            if self.kwargs
            else ""
        )
        return f"{name}({args}{',' if args and kwargs else ''}{kwargs})"

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(
            (
                self.klass,
                tuple(self.args),
                tuple(self.kwargs.keys()),
                tuple(self.kwargs.values()),
            )
        )


@dataclass(frozen=True)
@total_ordering
class Config:
    """
    A Config is a description of a scalar multiplication implementation, consisting of a scalar multiplier,
    (optionally) a countermeasure, and (optionally) an error model.

    The scalar multiplier and countermeasure combination is specified as an instance of `Composable` stored
    in the `composition` attribute.

    The error model is simply in the `error_model` attribute and may be `None`. If it is `None`, the Config
    is not suitable for error simulation and merely represents the description of a scalar multiplication
    implementation we care about when reverse-engineering: the multiplier and the countermeasure, we do not
    really care about the error model, yet need it when simulating.
    """

    composition: Composable
    error_model: Optional[ErrorModel] = None

    @property
    def partial(self):
        """Get the callable that constructs the scalar multiplier (with countermeasure if any)."""
        return self.composition.construct

    @property
    def mult(self):
        """Get the MultIdent"""
        return self.composition.mult

    @property
    def has_countermeasure(self):
        return isinstance(self.composition, CountermeasureIdent)

    @property
    def countermeasures(self) -> set[CountermeasureIdent]:
        r = set()
        if not self.has_countermeasure:
            return r
        self.composition.walk(lambda c: r.add(c) if isinstance(c, CountermeasureIdent) else None)

    @property
    def has_error_model(self):
        return self.error_model is not None

    def with_error_model(self, error_model: ErrorModel | None):
        """Return a new Config with a given error model."""
        if not (isinstance(error_model, ErrorModel) or error_model is None):
            raise ValueError("Unknown error model.")
        return Config(self.composition, error_model=error_model)

    def __str__(self):
        error_model = str(self.error_model) if self.error_model else ""
        return f"<{self.composition}{error_model}>"

    def __repr__(self):
        return str(self)

    def __lt__(self, other):
        if not isinstance(other, Config):
            return NotImplemented
        me = (self.mult, self.composition)
        them = (other.mult, other.composition)
        return me < them

    def __hash__(self):
        return hash((self.composition, self.error_model))


# We can enumerate all mults and countermeasures here.
def _all_mults_with_ctr():
    result = []
    for mult in all_mults:
        for one_ctr_class, other_ctr_class in itertools.product(
            (
                GroupScalarRandomization,
                AdditiveSplitting,
                MultiplicativeSplitting,
                EuclideanSplitting,
                BrumleyTuveri,
                None,
            ),
            repeat=2,
        ):
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


# fmt: off
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
all_mults = window_mults + naf_mults + binary_mults + other_mults + comb_mults
all_mults_with_ctr = _all_mults_with_ctr()
all_configs = [Config(mult, None) for mult in all_mults_with_ctr]
# fmt: on
