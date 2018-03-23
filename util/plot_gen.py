#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Script for plotting ECTester key generation results.
#
# Example usage:
#
#     > java -jar ECTesterReader.jar -g 10000 -b 192 -fp -o gen.csv
#     ...
#     > ./plot_gen.py gen.csv
#     ...
#

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.colors as colors
from operator import itemgetter
from copy import deepcopy
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot results of ECTester key generation timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--pub", dest="pub", action="store_true", help="Show public key scatter plot.")
    parser.add_argument("--priv", dest="priv", action="store_true", help="Show private key scatter plot.")
    parser.add_argument("--hist", dest="hist", action="store_true", help="Show histogram.")
    parser.add_argument("--hw-hist", dest="hw_hist", action="store_true", help="Show Hamming weight 2D histogram (private key Hamming weight and generation time).")
    parser.add_argument("--skip-first", dest="skip_first", action="store_true", help="Skip first entry, as it's usually a large outlier.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    with open(opts.file, "r") as f:
        header = f.readline()
    header_names = header.split(";")

    plots = [opts.priv, opts.pub, opts.hist, opts.hw_hist]
    n_plots = sum(plots)
    if n_plots == 0:
        n_plots = 4
        plots = [True, True, True, True]

    hx = lambda x: int(x, 16)
    data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx}, dtype=np.dtype([("index","u4"), ("time","u4"), ("pub", "O"), ("priv", "O")]))
    if opts.skip_first:
        data = data[1:]

    if "nano" in header_names[1]:
        unit = r"$\mu s$"
        time_data = map(lambda x: x[1]//1000, data)
    else:
        unit = r"ms"
        time_data = map(itemgetter(1), data)
    time_data = list(time_data)
    priv_data = list(map(itemgetter(2), data))
    pub_data = list(map(itemgetter(3), data))

    plt.style.use("ggplot")
    fig = plt.figure()
    fig.tight_layout(rect=[0, 0.02, 1, 0.98])
    fig.suptitle(opts.file)

    plot_i = 1
    if plots[0]:
        axe_private = fig.add_subplot(n_plots, 1, plot_i)
        axe_private.scatter(time_data, priv_data, marker="x", s=10)
        axe_private.set_ylabel("private key value\n(big endian)")
        axe_private.set_xlabel("time ({})".format(unit))
        plot_i += 1

    if plots[1]:
        axe_public = fig.add_subplot(n_plots, 1, plot_i)
        axe_public.scatter(time_data, pub_data, marker="x", s=10)
        axe_public.set_ylabel("public key value\n(big endian)")
        axe_public.set_xlabel("time ({})".format(unit))
        plot_i += 1

    if plots[2]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        time_max = max(time_data)
        time_avg = np.average(time_data)
        time_median = np.median(time_data)
        axe_hist.hist(time_data, bins=time_max//3, log=True)
        axe_hist.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="red", label="avg = {}".format(time_avg))
        axe_hist.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
        axe_hist.set_ylabel("count\n(log)")
        axe_hist.set_xlabel("time ({})".format(unit))
        axe_hist.xaxis.set_major_locator(ticker.MaxNLocator())
        axe_hist.legend(loc="best")
        plot_i += 1

    if plots[3]:
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
        axe_priv_hist = fig.add_subplot(n_plots, 1, plot_i)
        h, xe, ye = np.histogram2d(priv_bit_x, priv_bit_y, bins=[max(priv_bit_bins) - min(priv_bit_bins), (max(time_data) - min(time_data))//5])
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
        ext = opts.output.name.split(".")[-1]
        plt.savefig(opts.output, format=ext, dpi=400)
