#!/usr/bin/env python
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
from operator import itemgetter
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot results of ECTester key generation timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--pub", dest="pub", action="store_true", help="Show public key scatter plot.")
    parser.add_argument("--priv", dest="priv", action="store_true", help="Show private key scatter plot.")
    parser.add_argument("--hist", dest="hist", action="store_true", help="Show histogram.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    plots = [opts.priv, opts.pub, opts.hist]
    n_plots = sum(plots)
    if n_plots == 0:
        n_plots = 3
        plots = [True, True, True]

    hx = lambda x: int(x, 16)
    data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx}, dtype=np.dtype([("index","u4"), ("time","u4"), ("pub", "O"), ("priv", "O")]))

    time_data = map(itemgetter(1), data)
    priv_data = map(itemgetter(2), data)
    pub_data = map(itemgetter(3), data)

    fig = plt.figure(tight_layout=True)
    fig.suptitle(opts.file)

    plot_i = 1
    if plots[0]:
        axe_private = fig.add_subplot(n_plots, 1, plot_i)
        axe_private.scatter(time_data, priv_data, marker="x", s=10)
        axe_private.set_ylabel("private key value\n(big endian)")
        axe_private.set_xlabel("time (ms)")
        plot_i += 1

    if plots[1]:
        axe_public = fig.add_subplot(n_plots, 1, plot_i)
        axe_public.scatter(time_data, pub_data, marker="x", s=10)
        axe_public.set_ylabel("public key value\n(big endian)")
        axe_public.set_xlabel("time (ms)")
        plot_i += 1

    if plots[2]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        axe_hist.hist(time_data, bins=400, log=True)
        axe_hist.set_ylabel("count\n(log)")
        axe_hist.set_xlabel("time (ms)")

    if opts.output is None:
        plt.show()
    else:
        plt.savefig(opts.output, dpi=400)
