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

from pyecsca.ec.params import get_params
from pyecsca.misc.utils import TaskExecutor
from .. import all_configs, all_error_models, evaluate_multiples_compressed, divisor_map


if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


@click.command()
@click.option("temp", "--temp", envvar="SCRATCHDIR", type=click.Path(file_okay=False, dir_okay=True, path_type=Path), default=None)
@click.option("workers", "--workers", type=int, required=True)
@click.option("seed", "--seed", required=True)
def main(temp, workers, seed):
    category = "secg"
    curve = "secp256r1"
    params = get_params(category, curve, "projective")
    bits = params.order.bit_length()

    if temp is None:
        tmp = TemporaryDirectory()
        temp = Path(tmp.name)
        atexit.register(tmp.cleanup)

    use_init = True
    use_multiply = True

    in_path = Path(f"multiples_{seed}.zpickle")
    out_path = Path(f"probs_{seed}.zpickle")

    with zstd.open(in_path, "rb") as f, zstd.open(out_path, "wb") as h, TaskExecutor(max_workers=workers) as pool, tqdm(total=len(all_configs), desc=f"Generating probability maps.", smoothing=0) as bar:
        while True:
            try:
                start = f.tell()
                bar.update(1)
                mult, _ = pickle.load(f)
                for error_model in all_error_models:
                    full = mult.with_error_model(error_model)
                    # Pass the file name and offset to speed up computation start.
                    pool.submit_task(full,
                                     evaluate_multiples_compressed,
                                     full, in_path, start, divisor_map["all"], use_init, use_multiply)
                gc.collect()
                for full, future in pool.as_completed(wait=False):
                    if error := future.exception():
                        print("Error!", full, error)
                        continue
                    res = future.result()
                    pickle.dump((full, res), h)
            except EOFError:
                break
            except pickle.UnpicklingError:
                print("Bad unpickling, the multiples file is likely truncated.")
                break
        for full, future in pool.as_completed():
            if error := future.exception():
                print("Error!", full, error)
                continue
            res = future.result()
            pickle.dump((full, res), h)


if __name__ == "__main__":
    main()