"""
Make a multiples file for all configs (without error models).

The file is rather large as it stores the full multiple graphs
as pickles for a number of samples for each config. For now this is
around 300 GB for samples = 1000.
"""

import atexit
import sys
import time

from pathlib import Path
from tempfile import TemporaryDirectory

import click

from tqdm import tqdm

from pyecsca.ec.params import get_params
from pyecsca.misc.utils import TaskExecutor
from ..simulate import simulate_multiples_direct
from ..config import all_configs

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


@click.command()
@click.option(
    "temp",
    "--temp",
    envvar="SCRATCHDIR",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
)
@click.option("workers", "--workers", type=int, required=True)
@click.option("seed", "--seed", required=True)
@click.option("samples", "--samples", type=int, default=100)
def main(temp, workers, seed, samples):
    category = "secg"
    curve = "secp256r1"
    params = get_params(category, curve, "projective")
    bits = params.order.bit_length()

    if temp is None:
        tmp = TemporaryDirectory()
        temp = Path(tmp.name)
        atexit.register(tmp.cleanup)

    output = Path(f"multiples_{seed}.zpickle")

    with TaskExecutor(max_workers=workers) as pool, zstd.open(output, "wb") as h:
        for i, mult in enumerate(all_configs):
            pool.submit_task(
                mult,
                simulate_multiples_direct,
                mult,
                params,
                bits,
                temp / f"m{seed}_{i}.pickle",
                samples,
                seed=seed,
            )

        i = 0
        for mult, future in tqdm(
            pool.as_completed(),
            desc="Computing multiple graphs.",
            total=len(pool.tasks),
        ):
            i += 1
            if error := future.exception():
                click.echo(f"Error! {mult} {error}")
                continue
            fpath = future.result()
            with fpath.open("rb") as f:
                h.write(f.read())
            fpath.unlink()
            if (i % 100) == 0:
                time.sleep(1)


if __name__ == "__main__":
    main()
