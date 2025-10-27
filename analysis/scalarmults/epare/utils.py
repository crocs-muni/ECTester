import itertools

from statsmodels.stats.proportion import proportion_confint


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


def conf_interval(p: float, samples: int, alpha: float = 0.05) -> tuple[float, float]:
    """Compute a confidence interval for a Binomial distribution."""
    return proportion_confint(round(p*samples), samples, alpha, method="wilson")
