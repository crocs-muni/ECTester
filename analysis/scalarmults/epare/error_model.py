from dataclasses import dataclass
from functools import partial, total_ordering
from typing import Any, Optional, Type, Union, Literal


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