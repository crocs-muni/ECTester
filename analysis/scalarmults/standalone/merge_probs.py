"""
Merge all probs files into one.
"""

import pickle

import click

from pathlib import Path

from epare import ProbMap


@click.command()
def main():
    maps = {}
    for file in Path().glob("probs_*.pickle"):
        with file.open("rb") as h:
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