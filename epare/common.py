import multiprocessing
import inspect
import tempfile
import sys
import os


from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial, cached_property
from importlib import import_module, invalidate_caches
from pathlib import Path
from typing import Type, Any

from pyecsca.ec.params import DomainParameters, get_params
from pyecsca.ec.mult import *


spawn_context = multiprocessing.get_context("spawn")

# Allow to use "spawn" multiprocessing method for function defined in a Jupyter notebook.
# https://neuromancer.sk/article/35
@contextmanager
def enable_spawn(func):
    invalidate_caches()
    source = inspect.getsource(func)
    current_file_path = os.path.abspath(__file__)
    with open(current_file_path, 'r') as self, tempfile.NamedTemporaryFile(suffix=".py", mode="w") as f:
        f.write(self.read())
        f.write(source)
        f.flush()
        path = Path(f.name)
        directory = str(path.parent)
        sys.path.append(directory)
        module = import_module(str(path.stem))
        yield getattr(module, func.__name__)
        sys.path.remove(directory)


@dataclass(frozen=True)
class MultIdent:
    klass: Type[ScalarMultiplier]
    args: list[Any]
    kwargs: dict[str, Any]

    def __init__(self, klass: Type[ScalarMultiplier], *args, **kwargs):
        object.__setattr__(self, "klass", klass)
        object.__setattr__(self, "args", args if args is not None else [])
        object.__setattr__(self, "kwargs", kwargs if kwargs is not None else {})

    @cached_property
    def partial(self):
        return partial(self.klass, *self.args, **self.kwargs)

    def __str__(self):
        return f"{self.klass.__name__}_{self.args}_{self.kwargs}"

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash((self.klass, tuple(self.args), tuple(self.kwargs.keys()), tuple(self.kwargs.values())))


@dataclass
class MultResults:
    multiplications: list[set[int]]
    samples: int

    def merge(self, other: "MultResults"):
        self.multiplications.extend(other.multiplications)
        self.samples += other.samples

    def __len__(self):
        return self.samples

    def __iter__(self):
        yield from self.multiplications

    def __getitem__(self, i):
        return self.multiplications[i]

    def __str__(self):
        return f"MultResults({self.samples})"

    def __repr__(self):
        return str(self)
