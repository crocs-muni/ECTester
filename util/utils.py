import numpy as np
from matplotlib import ticker


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
