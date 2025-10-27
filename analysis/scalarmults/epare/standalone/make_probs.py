"""
Make the probs file from a given multiples file.
"""

import atexit
import gc
import pickle
import sys

from pathlib import Path
from tempfile import TemporaryDirectory

import click

from tqdm import tqdm

from pyecsca.misc.utils import TaskExecutor
from ..simulate import evaluate_multiples_all
from ..divisors import divisor_map
from ..error_model import all_error_models
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
def main(temp, workers, seed):
    if temp is None:
        tmp = TemporaryDirectory()
        temp = Path(tmp.name)
        atexit.register(tmp.cleanup)

    use_init = True
    use_multiply = True

    in_path = Path(f"multiples_{seed}.zpickle")
    out_path = Path(f"probs_{seed}.zpickle")

    with (
        zstd.open(in_path, "rb") as f,
        zstd.open(out_path, "wb") as h,
        TaskExecutor(max_workers=workers) as pool,
        tqdm(
            total=len(all_configs) * len(all_error_models),
            desc=f"Generating probability maps.",
            smoothing=0,
        ) as bar,
    ):
        file_map = {}
        while True:
            try:
                mult, vals = pickle.load(f)
                # Store the mult and vals into a temporary compressed file.
                file = temp / f"v{hash(mult)}.zpickle"
                file_map[mult] = file
                with zstd.open(file, "wb") as mult_f:
                    pickle.dump((mult, vals), mult_f)

                # Pass the file name and offset to speed up computation start.
                pool.submit_task(
                    mult,
                    evaluate_multiples_all,
                    mult,
                    file,
                    0,
                    divisor_map["all"],
                    use_init,
                    use_multiply,
                )
                gc.collect()
                for mult, future in pool.as_completed(wait=False):
                    bar.update(1)
                    file_map[mult].unlink()
                    if error := future.exception():
                        click.echo(f"Error! {mult} {error}")
                        continue
                    res = future.result()
                    for full, probmap in res.items():
                        pickle.dump((full, probmap), h)
            except EOFError:
                break
            except pickle.UnpicklingError:
                click.echo("Bad unpickling, the multiples file is likely truncated.")
                break
        for full, future in pool.as_completed():
            bar.update(1)
            file_map[mult].unlink()
            if error := future.exception():
                click.echo(f"Error! {mult} {error}")
                continue
            res = future.result()
            for full, probmap in res.items():
                pickle.dump((full, probmap), h)


if __name__ == "__main__":
    main()
