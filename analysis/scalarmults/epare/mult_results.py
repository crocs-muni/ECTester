from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from pyecsca.sca.re.rpa import MultipleContext
from pyecsca.ec.point import Point


@dataclass
class MultResults:
    """
    A MultResults instance represents many simulated scalar multiplciation computations, which were tracked
    using a `MultipleContext` (i.e. the outputs of the :func:`pyecsca.sca.re.rpa.multiple_graph` function).
    Generally, these would be for one Config only, but that should be handled separately, for example
    in a dict[Config, MultResults]. The `samples` describe how many computations
    are contained and must correspond to the length of the `multiplications` list.
    """

    multiplications: list[tuple[MultipleContext, MultipleContext, Point]]
    samples: int
    duration: Optional[float] = None

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
        duration = (
            timedelta(seconds=int(self.duration)) if self.duration is not None else ""
        )
        return f"MultResults({self.samples},{duration})"

    def __repr__(self):
        return str(self)
