import numpy as np
from matplotlib import ticker
from math import sqrt, log


def hw(i):
    res = 0
    while i:
        res += 1
        i &= i - 1
    return res


def moving_average(a, n) :
    ret = np.cumsum(a, dtype=float)
    ret[n:] = ret[n:] - ret[:-n]
    return ret[n - 1:] / n


def time_scale(data, orig_unit, target_unit, scaling_factor):
    units = {
        "milli": ("ms", 1000000),
        "micro": (r"$\mu s$", 1000),
        "nano":  ("ns", 1)
    }
    upper = units[orig_unit][1]
    lower = units[target_unit][1] * scaling_factor
    if upper > lower:
        data *= upper // lower
    elif lower > upper:
        np.floor_divide(data, lower // upper, data)
    return (r"$\frac{1}{" + str(scaling_factor) + "}$" if scaling_factor != 1 else "") + units[target_unit][0]


def hist_size_func(choice):
    if choice == "sqrt":
        return lambda n, xmin, xmax, var, xlower, xupper: int(sqrt(n)) + 1
    elif choice == "sturges":
        return lambda n, xmin, xmax, var, xlower, xupper: int(log(n, 2)) + 1
    elif choice == "rice":
        return lambda n, xmin, xmax, var, xlower, xupper: int(2 * n**(1/3))
    elif choice == "scott":
        return lambda n, xmin, xmax, var, xlower, xupper: (xmax - xmin) // int((3.5 * sqrt(var)) / (n**(1/3)))
    elif choice == "fd":
        return lambda n, xmin, xmax, var, xlower, xupper: (xmax - xmin) // int(2 * (xupper - xlower) / (n**(1/3)))
    else:
        return lambda n, xmin, xmax, var, xlower, xupper: hist_size


def plot_hist(axes, data, xlabel=None, log=False, avg=True, median=True, bins=None, **kwargs):
    time_max = max(data)
    time_min = min(data)
    time_avg = np.average(data)
    time_median = np.median(data)
    if bins is None:
        bins = time_max - time_min + 1
    hist = axes.hist(data, bins=bins, log=log, **kwargs)
    if avg:
        axes.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="blue", label="avg = {}".format(time_avg))
    if median:
        axes.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
    axes.set_ylabel("count" + ("\n(log)" if log else ""))
    axes.set_xlabel("time" if xlabel is None else xlabel)
    axes.xaxis.set_major_locator(ticker.MaxNLocator())
    if avg or median:
        axes.legend(loc="best")
    return hist


def miller_correction(entropy, samples, bins):
    return entropy + (bins - 1)/(2*samples)


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p
