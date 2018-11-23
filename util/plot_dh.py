#!/usr/bin/env python3
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

from utils import hw, moving_average, plot_hist

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot ECTester ECDH timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--priv", dest="priv", action="store_true", help="Show private key MSB heatmap plot.")
    parser.add_argument("--hist", dest="hist", action="store_true", help="Show time histogram.")
    parser.add_argument("--hw-hist", dest="hw_hist", action="store_true", help="Show Hamming weight heatmap (private key Hamming weight and time).")
    parser.add_argument("--avg", dest="avg", action="store_true", help="Show moving average of time.")
    parser.add_argument("--log", dest="log", action="store_true", help="Use logarithmic scale.")
    parser.add_argument("--skip-first", dest="skip_first", nargs="?", const=1, type=int, help="Skip first entry, as it's usually a large outlier.")
    parser.add_argument("-t", "--title", dest="title", nargs="?", default="", type=str, help="What title to give the figure.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    with open(opts.file, "r") as f:
        header = f.readline()
    header_names = header.split(";")

    hx = lambda x: int(x, 16)
    data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx, 4: hx}, dtype=np.dtype([("index","u4"), ("time","u4"), ("pub", "O"), ("priv", "O"), ("secret","O")]))
    if opts.skip_first:
        data = data[opts.skip_first:]

    time_data = data["time"]
    if "nano" in header_names[1]:
        unit = r"$\mu s$"
        time_data = np.array(list(map(lambda x: x//1000, time_data)))
    else:
        unit = r"ms"
    priv_data = data["priv"]
    pub_data = data["pub"]
    secret_data = data["secret"]

    plt.style.use("ggplot")
    fig = plt.figure()
    layout_kwargs = {}
    if opts.title is None:
        fig.suptitle(opts.file)
        layout_kwargs["rect"] = [0, 0.02, 1, 0.98]
    elif opts.title:
        fig.suptitle(opts.title)
        layout_kwargs["rect"] = [0, 0.02, 1, 0.98]
    fig.tight_layout(**layout_kwargs)

    time_max = max(time_data)
    time_min = min(time_data)
    bit_size = len(bin(max(priv_data))) - 2

    cmap = deepcopy(plt.cm.plasma)
    cmap.set_bad("black")

    norm = colors.Normalize()
    if opts.log:
        norm = colors.LogNorm()

    axe_private = fig.add_subplot(3,1,1)
    priv_msb = np.array(list(map(lambda x: x >> (bit_size - 8), priv_data)), dtype=np.dtype("u1"))
    heatmap, xedges, yedges = np.histogram2d(priv_msb, time_data, bins=[128, time_max - time_min])
    extent = [xedges[0], xedges[-1], yedges[0], yedges[-1]]
    axe_private.imshow(heatmap.T, extent=extent, aspect="auto", cmap=cmap, origin="low", interpolation="nearest", norm=norm)
    axe_private.set_xlabel("private key MSB value")
    axe_private.set_ylabel("ECDH time ({})".format(unit))

    axe_hist = fig.add_subplot(3,1,2)
    plot_hist(axe_hist, time_data, "ECDH time ({})".format(unit), opts.log)
    axe_hist.legend(loc="best")

    axe_priv_hist = fig.add_subplot(3,1,3)
    priv_hw = np.array(list(map(hw, priv_data)), dtype=np.dtype("u2"))
    h, xe, ye = np.histogram2d(priv_hw, time_data, bins=[max(priv_hw) - min(priv_hw), time_max - time_min])
    im = axe_priv_hist.imshow(h.T, origin="low", cmap=cmap, aspect="auto", extent=[xe[0], xe[-1], ye[0], ye[-1]], norm=colors.LogNorm())
    axe_priv_hist.axvline(x=bit_size//2, alpha=0.7, linestyle="dotted", color="white", label=str(bit_size//2) + " bits")    
    axe_priv_hist.set_xlabel("private key Hamming weight")
    axe_priv_hist.set_ylabel("time ({})".format(unit))
    axe_priv_hist.legend(loc="best")
    fig.colorbar(im, ax=axe_priv_hist)

    fig.text(0.01, 0.02, "Data size: {}".format(len(time_data)), size="small")

    if opts.output is None:
        plt.show()
    else:
        fig.set_size_inches(12, 10)
        ext = opts.output.name.split(".")[-1]
        plt.savefig(opts.output, format=ext, dpi=400, bbox_inches='tight')
