"""
Merge all probs files into one.
"""

import pickle
import sys

import click

from pathlib import Path

from tqdm import tqdm

from .. import ProbMap


if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


@click.command()
def main():
    maps = {}
    for file in tqdm(Path().glob("probs_*.zpickle"), desc="Merging probmaps.", smoothing=0):
        with zstd.open(file, "rb") as h:
            while True:
                try:
                    full, prob_map = pickle.load(h)
                    if full not in maps:
                        maps[full] = prob_map
                    else:
                        maps[full].merge(prob_map)
                except EOFError:
                    break
                except pickle.UnpicklingError:
                    print(f"Bad unpickling, the probs file {file} is likely truncated.")
                    break
    with open("merged.pickle", "wb") as f:
        pickle.dump(maps, f)


if __name__ == "__main__":
    main()