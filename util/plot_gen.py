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
from scipy.stats import entropy
import matplotlib.pyplot as plt
from matplotlib import ticker, colors
from copy import deepcopy
import argparse

from utils import hw, moving_average, plot_hist

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot results of ECTester key generation timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--priv", dest="priv", action="store_true", help="Show private key MSB heatmap plot.")
    parser.add_argument("--hist", dest="hist", action="store_true", help="Show keygen time histogram.")
    parser.add_argument("--export-hist", dest="export_hist", action="store_true", help="Show export time histogram.")
    parser.add_argument("--avg", dest="avg", action="store_true", help="Show moving average of keygen time.")
    parser.add_argument("--hw-hist", dest="hw_hist", action="store_true", help="Show Hamming weight heatmap (private key Hamming weight and keygen time).")
    parser.add_argument("--log", dest="log", action="store_true", help="Use logarithmic scale.")
    parser.add_argument("--skip-first", dest="skip_first", nargs="?", const=1, type=int, help="Skip first entry, as it's usually a large outlier.")
    parser.add_argument("-t", "--title", dest="title", type=str, nargs="?", default="", help="What title to give the figure.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    with open(opts.file, "r") as f:
        header = f.readline()
    header_names = header.split(";")
    if len(header_names) not in (4, 5):
        print("Bad data?")
        exit(1)

    plots = [opts.priv, opts.hist, opts.export_hist, opts.avg, opts.hw_hist]
    n_plots = sum(plots)
    if n_plots == 0:
        plots = [True for _ in range(5)]
        if len(header_names) == 4:
            n_plots = 4
            plots[2] = False
        else:
            n_plots = 5


    if plots[2] and len(header_names) != 5:
        n_plots = n_plots - 1
        if n_plots == 0:
            print("Nothing to plot.")
            exit(1)
        plots[2] = False

    hx = lambda x: int(x, 16)
    if len(header_names) == 4:
        data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx}, dtype=np.dtype([("index", "u4"), ("gen_time", "u4"), ("pub", "O"), ("priv", "O")]))
    else:
        data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={3: hx, 4: hx}, dtype=np.dtype([("index", "u4"), ("gen_time", "u4"), ("export_time", "u4"), ("pub", "O"), ("priv", "O")]))

    if opts.skip_first:
        data = data[opts.skip_first:]


    gen_time_data = data["gen_time"]
    export_time_data = None
    if "export_time" in data.dtype.names:
        export_time_data = data["export_time"]
    pub_data = data["pub"]
    priv_data = data["priv"]

    gen_unit = "ms"
    if header_names[1].endswith("[nano]"):
        gen_unit = r"$\mu s$"
        np.floor_divide(gen_time_data, 1000, out=gen_time_data)
    export_unit = "ms"
    if len(header_names) == 5 and header_names[2].endswith("[nano]"):
        export_unit = r"$\mu s$"
        np.floor_divide(export_time_data, 1000, out=export_time_data)

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

    max_gen_time = max(gen_time_data)
    min_gen_time = min(gen_time_data)
    bit_size = len(bin(max(priv_data))) - 2

    sorted_data = np.sort(data, order="gen_time")

    i = 0
    entropies = {}
    while i < len(data):
        time_val = sorted_data["gen_time"][i]
        j = i
        msbs = [0 for _ in range(256)]
        while j < len(data) and sorted_data["gen_time"][j] == time_val:
            msbs[(sorted_data["priv"][j] >> (bit_size - 8)) & 0xff] += 1
            j += 1
        if j - 100 > i:
            entropies[time_val] = entropy(msbs, base=2)
        i = j

    entropy = sum(entropies.values())/len(entropies)

    cmap = deepcopy(plt.cm.plasma)
    cmap.set_bad("black")

    norm = colors.Normalize()
    if opts.log:
        norm = colors.LogNorm()

    plot_i = 1
    if plots[0]:
        axe_private = fig.add_subplot(n_plots, 1, plot_i)
        priv_msb = np.array(list(map(lambda x: x >> (bit_size - 8), priv_data)), dtype=np.dtype("u1"))
        max_msb = max(priv_msb)
        min_msb = min(priv_msb)
        heatmap, xedges, yedges = np.histogram2d(priv_msb, gen_time_data, bins=[max_msb - min_msb, max_gen_time - min_gen_time])
        extent = [min_msb, max_msb, yedges[0], yedges[-1]]
        axe_private.imshow(heatmap.T, extent=extent, aspect="auto", cmap=cmap, origin="low", interpolation="nearest", norm=norm)
        axe_private.set_xlabel("private key MSB value")
        axe_private.set_ylabel("keygen time ({})".format(gen_unit))
        plot_i += 1

    if plots[1]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        plot_hist(axe_hist, gen_time_data, "keygen time ({})".format(gen_unit), opts.log)
        plot_i += 1

    if plots[2]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        plot_hist(axe_hist, export_time_data, "export time ({})".format(export_unit), opts.log)
        plot_i += 1

    if plots[3]:
        axe_avg = fig.add_subplot(n_plots, 1, plot_i)
        #if len(header_names) == 5:
        #   axe_other = axe_avg.twinx()
        #   axe_other.plot(moving_average(export_time_data, 100), color="green", alpha=0.6, label="export, window = 100")
        #   axe_other.plot(moving_average(export_time_data, 1000), color="yellow", alpha=0.6, label="export, window = 1000")
        #   axe_other.legend(loc="lower right")
        axe_avg.plot(moving_average(gen_time_data, 100), label="window = 100")
        axe_avg.plot(moving_average(gen_time_data, 1000), label="window = 1000")
        axe_avg.set_ylabel("keygen time ({})".format(gen_unit))
        axe_avg.set_xlabel("index")
        axe_avg.legend(loc="best")
        plot_i += 1

    if plots[4]:
        axe_priv_hist = fig.add_subplot(n_plots, 1, plot_i)
        priv_hw = np.array(list(map(hw, priv_data)), dtype=np.dtype("u2"))
        h, xe, ye = np.histogram2d(priv_hw, gen_time_data, bins=[max(priv_hw) - min(priv_hw), max_gen_time - min_gen_time])
        im = axe_priv_hist.imshow(h.T, origin="low", cmap=cmap, aspect="auto", extent=[xe[0], xe[-1], ye[0], ye[-1]], norm=norm)
        axe_priv_hist.axvline(x=bit_size//2, alpha=0.7, linestyle="dotted", color="white", label=str(bit_size//2) + " bits")
        axe_priv_hist.set_xlabel("private key Hamming weight")
        axe_priv_hist.set_ylabel("keygen time ({})".format(gen_unit))
        axe_priv_hist.legend(loc="best")
        fig.colorbar(im, ax=axe_priv_hist)

    fig.text(0.01, 0.02, "Data size: {}".format(len(gen_time_data)), size="small")
    fig.text(0.01, 0.04, "Entropy of privkey MSB(estimated): {:.2f} b".format(entropy), size="small")

    if opts.output is None:
        plt.show()
    else:
        fig.set_size_inches(12, 10)
        ext = opts.output.name.split(".")[-1]
        plt.savefig(opts.output, format=ext, dpi=400, bbox_inches='tight')
