import hashlib
import numpy as np
from matplotlib import ticker
from math import sqrt, log
import ec
from asn1crypto.core import Sequence

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
    if orig_unit == "instr":
        return orig_unit
    units = {
        "milli": ("ms", 1000000),
        "micro": (r"$\mu s$", 1000),
        "nano":  ("ns", 1)
    }
    upper = units[orig_unit][1] * scaling_factor
    lower = units[target_unit][1]
    if upper > lower:
        data *= upper // lower
    elif lower > upper:
        np.floor_divide(data, lower // upper, data)
    return (r"$\frac{1}{" + str(scaling_factor) + "}$" if scaling_factor != 1 else "") + units[target_unit][0]

def recompute_nonces(data, curve_name, hash_algo):
    try:
        curve = ec.get_curve(curve_name)
    except:
        curve = ec.load_curve(curve_name)
    verified = False
    for elem in data:
        if elem["nonce"] is not None:
            continue
        if elem["index"] % (len(data)//10) == 0:
            print(".", end="")
        if hash_algo is None:
            hm = int.from_bytes(elem["data"], byteorder="big") % curve.group.n
        else:
            h = hashlib.new(hash_algo, elem["data"])
            hm = int(h.hexdigest(), 16)
            if h.digest_size * 8 > curve.group.n.bit_length():
                hm >> h.digest_size * 8 - curve.group.n.bit_length()
            hm = hm % curve.group.n
        r, s = Sequence.load(elem["signature"]).native.values()
        r = ec.Mod(r, curve.group.n)
        s = ec.Mod(s, curve.group.n)
        rx = r * elem["priv"]
        hmrx = hm + rx
        nonce = s.inverse() * hmrx
        if not verified:
            res = int(nonce) * curve.g
            if int(res.x) % curve.group.n != int(r):
                print("Nonce recomputation couldnt verify!")
                raise ValueError
            else:
                print("Nonce recomputation works")
                verified = True
        elem["nonce"] = int(nonce)

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


