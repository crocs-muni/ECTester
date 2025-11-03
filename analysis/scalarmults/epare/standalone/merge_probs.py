"""
Merge all probs files into one.
"""

import pickle
import sys

import click

from pathlib import Path

from tqdm import tqdm

from ..error_model import all_error_models
from ..config import all_configs

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


@click.command()
@click.option(
    "-z", "--compressed", is_flag=True, help="Whether to load the probmaps compressed."
)
def main(compressed):
    maps = {}
    if compressed:
        glob = "probs_*.zpickle"
        out = "merged.zpickle"
        opener = zstd.open
    else:
        glob = "probs_*.pickle"
        out = "merged.pickle"
        opener = open

    found = list(Path().glob(glob))
    click.echo(f"Found {len(found)} probmap files.")
    if not found:
        return

    for file in tqdm(found, desc="Merging probmaps.", smoothing=0):
        with opener(file, "rb") as h, tqdm(
            total=len(all_configs) * len(all_error_models),
            desc=f"Loading probmap {file}.",
            smoothing=0,
            leave=False,
        ) as bar:
            i = 0
            while True:
                try:
                    full, prob_map = pickle.load(h)
                    bar.update(1)
                    i += 1
                    if full not in maps:
                        maps[full] = prob_map
                    else:
                        maps[full].merge(prob_map)
                except EOFError:
                    break
                except (pickle.UnpicklingError, zstd.ZstdError):
                    click.echo(
                        f"Bad unpickling/decompression, the probs file {file} is likely truncated."
                    )
                    break
            click.echo(f"Loaded {i} probmaps from {file}.")
    with opener(out, "wb") as f:
        pickle.dump(maps, f)


if __name__ == "__main__":
    main()
