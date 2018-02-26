#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Script for plotting ECTester ECDH results.
#
# Example usage:
#
#     > java -jar ECTesterReader.jar -dh 10000 -b 192 -fp -o dh.csv
#     ...
#     > ./plot_dh.py dh.csv
#     ...
#

import numpy as np
import matplotlib.pyplot as plt
from matplotlib import ticker, colors
import argparse
from copy import deepcopy
from operator import itemgetter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot ECTester ECDH timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--skip-first", dest="skip_first", action="store_true", help="Skip first entry, as it's usually a large outlier.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    with open(opts.file, "r") as f:
        header = f.readline()
    header_names = header.split(";")

    hx = lambda x: int(x, 16)
    data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx, 4: hx}, dtype=np.dtype([("index","u4"), ("time","u4"), ("pub", "O"), ("priv", "O"), ("secret","O")]))
    if opts.skip_first:
        data = data[1:]

    if "nano" in header_names[1]:
        unit = r"$\mu s$"
        time_data = map(lambda x: x[1]/1000, data)
    else:
        unit = r"ms"
        time_data = map(itemgetter(1), data)
    priv_data = map(itemgetter(2), data)
    pub_data = map(itemgetter(3), data)
    secret_data = map(itemgetter(4), data)

    plt.style.use("ggplot")
    fig = plt.figure(tight_layout=True)
    fig.suptitle(opts.file)

    axe_hist = fig.add_subplot(2,1,1)
    time_max = max(time_data)
    time_avg = np.average(time_data)
    time_median = np.median(time_data)
    axe_hist.hist(time_data, bins=time_max/3, log=True)
    axe_hist.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="red", label="avg = {}".format(time_avg))
    axe_hist.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
    axe_hist.set_ylabel("count\n(log)")
    axe_hist.set_xlabel("time ({})".format(unit))
    axe_hist.xaxis.set_major_locator(ticker.MaxNLocator())
    axe_hist.legend(loc="best")

    priv_bit_bins = {}
    for i in range(len(data)):
        skey = priv_data[i]
        time = time_data[i]
        skey_hw = 0
        while skey:
            skey_hw += 1
            skey &= skey - 1
        if skey_hw in priv_bit_bins:
            priv_bit_bins[skey_hw].append(time)
        else:
            priv_bit_bins[skey_hw] = [time]
    priv_bit_x = []
    priv_bit_y = []
    for k,v in priv_bit_bins.items():
        priv_bit_x.extend([k] * len(v))
        priv_bit_y.extend(v)

    axe_priv_hist = fig.add_subplot(2,1,2)
    h, xe, ye = np.histogram2d(priv_bit_x, priv_bit_y, bins=[max(priv_bit_bins) - min(priv_bit_bins), (time_max - min(time_data))/5])
    cmap = deepcopy(plt.cm.plasma)
    cmap.set_bad("black")
    im = axe_priv_hist.imshow(h.T, origin="low", cmap=cmap, aspect="auto", extent=[xe[0], xe[-1], ye[0], ye[-1]], norm=colors.LogNorm())
    axe_priv_hist.set_xlabel("private key Hamming weight")
    axe_priv_hist.set_ylabel("time ({})".format(unit))
    fig.colorbar(im, ax=axe_priv_hist)

    fig.text(0.01, 0.02, "Data size: {}".format(len(time_data)), size="small")

    if opts.output is None:
        plt.show()
    else:
        fig.set_size_inches(12, 10)
        plt.savefig(opts.output, dpi=400)
