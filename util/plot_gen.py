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
from matplotlib import ticker, colors
from copy import deepcopy
import argparse

def hw(i):
    res = 0
    while i:
        res += 1
        i &= i - 1
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot results of ECTester key generation timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("--priv", dest="priv", action="store_true", help="Show private key MSB heatmap plot.")
    parser.add_argument("--hist", dest="hist", action="store_true", help="Show keygen time histogram.")
    parser.add_argument("--export-hist", dest="export_hist", action="store_true", help="Show export time histogram.")
    parser.add_argument("--hw-hist", dest="hw_hist", action="store_true", help="Show Hamming weight heatmap (private key Hamming weight and keygen time).")
    parser.add_argument("--skip-first", dest="skip_first", action="store_true", help="Skip first entry, as it's usually a large outlier.")
    parser.add_argument("-t", "--title", dest="title", type=str, nargs="?", default="", help="What title to give the figure.")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    with open(opts.file, "r") as f:
        header = f.readline()
    header_names = header.split(";")
    if len(header_names) not in (4, 5):
        print("Bad data?")
        exit(1)

    plots = [opts.priv, opts.hist, opts.export_hist, opts.hw_hist]
    n_plots = sum(plots)
    if n_plots == 0:
        if len(header_names) == 4:
            n_plots = 3
        else:
            n_plots = 4
        plots = [True for _ in range(n_plots)]

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
        data = data[1:]

    gen_time_data = data["gen_time"]
    export_time_data = None
    if "export_time" in data.dtype.names:
        export_time_data = data["export_time"]
    pub_data = data["pub"]
    priv_data = data["priv"]


    gen_unit = "ms"
    if header_names[1].endswith("[nano]"):
        gen_unit = r"$\mu s$"
        gen_time_data = list(map(lambda x: x[1]//1000, gen_time_data))
    export_unit = "ms"
    if len(header_names) == 5 and header_names[2].endswith("[nano]"):
        export_unit = r"$\mu s$"
        export_time_data = list(map(lambda x: x[1]//1000, export_time_data))

    plt.style.use("ggplot")
    fig = plt.figure()
    layout_kwargs = {}
    if opts.title is None:
        fig.suptitle(opts.file)
        #layout_kwargs["rect"] = [0, 0.02, 1, 0.98]
    elif opts.title:
        fig.suptitle(opts.title)
        #layout_kwargs["rect"] = [0, 0.02, 1, 0.98]
    fig.tight_layout(**layout_kwargs)

    max_gen_time = max(gen_time_data)
    min_gen_time = min(gen_time_data)
    bit_size = len(bin(max(priv_data))) - 2

    cmap = deepcopy(plt.cm.plasma)
    cmap.set_bad("black")

    plot_i = 1
    if plots[0]:
        axe_private = fig.add_subplot(n_plots, 1, plot_i)
        priv_msb = np.array(list(map(lambda x: x >> (bit_size - 8), priv_data)), dtype=np.dtype("u1"))
        heatmap, xedges, yedges = np.histogram2d(priv_msb, gen_time_data, bins=[128, max_gen_time - min_gen_time])
        extent = [xedges[0], xedges[-1], yedges[0], yedges[-1]]
        axe_private.imshow(heatmap.T, extent=extent, aspect="auto", cmap=cmap, origin="low", interpolation="nearest", norm=colors.LogNorm())
        axe_private.set_xlabel("private key MSB value\n(big endian)")
        axe_private.set_ylabel("time ({})".format(gen_unit))
        plot_i += 1

    if plots[1]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        time_max = max(gen_time_data)
        time_min = min(gen_time_data)
        time_avg = np.average(gen_time_data)
        time_median = np.median(gen_time_data)
        axe_hist.hist(gen_time_data, bins=int((time_max - time_min)/1.2), log=True)
        axe_hist.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="blue", label="avg = {}".format(time_avg))
        axe_hist.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
        axe_hist.set_ylabel("count\n(log)")
        axe_hist.set_xlabel("keygen time ({})".format(gen_unit))
        axe_hist.xaxis.set_major_locator(ticker.MultipleLocator())
        axe_hist.legend(loc="best")
        plot_i += 1

    if plots[2]:
        axe_hist = fig.add_subplot(n_plots, 1, plot_i)
        time_max = max(export_time_data)
        time_min = min(export_time_data)
        time_avg = np.average(export_time_data)
        time_median = np.median(export_time_data)
        axe_hist.hist(export_time_data, bins=int((time_max - time_min)/1.2), log=True)
        axe_hist.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="blue", label="avg = {}".format(time_avg))
        axe_hist.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
        axe_hist.set_ylabel("count\n(log)")
        axe_hist.set_xlabel("export time ({})".format(export_unit))
        axe_hist.xaxis.set_major_locator(ticker.MultipleLocator())
        axe_hist.legend(loc="best")
        plot_i += 1

    if plots[3]:
        axe_priv_hist = fig.add_subplot(n_plots, 1, plot_i)
        priv_hw = np.array(list(map(hw, priv_data)), dtype=np.dtype("u2"))
        h, xe, ye = np.histogram2d(priv_hw, gen_time_data, bins=[max(priv_hw) - min(priv_hw), max_gen_time - min_gen_time])
        im = axe_priv_hist.imshow(h.T, origin="low", cmap=cmap, aspect="auto", extent=[xe[0], xe[-1], ye[0], ye[-1]], norm=colors.LogNorm())
        axe_priv_hist.axvline(x=bit_size//2, alpha=0.7, linestyle="dotted", color="white", label=str(bit_size//2) + " bits")
        axe_priv_hist.set_xlabel("private key Hamming weight")
        axe_priv_hist.set_ylabel("time ({})".format(gen_unit))
        axe_priv_hist.legend(loc="best")
        fig.colorbar(im, ax=axe_priv_hist)

    if plot_i > 2:
        fig.text(0.01, 0.02, "Data size: {}".format(len(gen_time_data)), size="small")

    if opts.output is None:
        plt.tight_layout()
        plt.show()
    else:
        fig.set_size_inches(12, 10)
        ext = opts.output.name.split(".")[-1]
        plt.savefig(opts.output, format=ext, dpi=400, bbox_inches='tight')
