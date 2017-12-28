#!/usr/bin/env python
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
import matplotlib.ticker as ticker
import argparse
from operator import itemgetter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot ECTester ECDH timing.")
    parser.add_argument("-o", "--output", dest="output", type=argparse.FileType("wb"), help="Write image to [file], do not display.", metavar="file")
    parser.add_argument("file", type=str, help="The file to plot(csv).")

    opts = parser.parse_args()

    hx = lambda x: int(x, 16)
    data = np.genfromtxt(opts.file, delimiter=";", skip_header=1, converters={2: hx, 3: hx, 4: hx}, dtype=np.dtype([("index","u4"), ("time","u4"), ("pub", "O"), ("priv", "O"), ("secret","O")]))

    time_data = map(itemgetter(1), data)
    priv_data = map(itemgetter(2), data)
    pub_data = map(itemgetter(3), data)
    secret_data = map(itemgetter(4), data)

    fig = plt.figure(tight_layout=True)
    fig.suptitle(opts.file)

    axe_hist = fig.add_subplot(1,1,1)
    time_max = max(time_data)
    time_avg = np.average(time_data)
    time_median = np.median(time_data)
    axe_hist.hist(time_data, bins=time_max/3, log=True)
    axe_hist.axvline(x=time_avg, alpha=0.7, linestyle="dotted", color="red", label="avg = {}".format(time_avg))
    axe_hist.axvline(x=time_median, alpha=0.7, linestyle="dotted", color="green", label="median = {}".format(time_median))
    axe_hist.set_ylabel("count\n(log)")
    axe_hist.set_xlabel("time (ms)")
    axe_hist.xaxis.set_major_locator(ticker.MaxNLocator())
    axe_hist.legend(loc="best")

    if opts.output is None:
        plt.show()
    else:
        plt.savefig(opts.output, dpi=400)
